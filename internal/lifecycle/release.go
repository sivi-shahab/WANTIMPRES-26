package lifecycle

import (
	"context"
	"io/fs"
	"log/slog"
	"sync/atomic"
	"time"

	"wantimpres26/internal/policysvc"
)

// Releaser keeps this replica's bundle server on the latest release. Every replica runs one: a release cut on any
// replica reaches all of them through Postgres NOTIFY within moments, with a poll as the fallback, so whichever
// replica a sidecar long-polls has it (spec §13: publish/rollback to every PEP ≤ 60 s p99).
type Releaser struct {
	Store  *Store
	Server *policysvc.Server
	FS     fs.FS
	Signer policysvc.Signer
	Log    *slog.Logger
	Poll   time.Duration // fallback when a notification is missed

	current atomic.Int64
}

// Current is the release this replica serves (exported as a metric to spot replicas that fall behind).
func (r *Releaser) Current() int64 { return r.current.Load() }

// Sync builds and publishes the latest release if it is newer than what is served.
func (r *Releaser) Sync(ctx context.Context) error {
	rel, err := r.Store.Latest(ctx)
	if err != nil {
		return err
	}
	if rel.Number <= r.current.Load() {
		return nil
	}
	tarball, rev, err := policysvc.Build(ctx, r.FS, r.Signer, rel.Overrides())
	if err != nil {
		return err
	}
	r.Server.Publish(tarball, rev)
	r.current.Store(rel.Number)
	r.Log.Info("policy release published", "release", rel.Number, "revision", rev)
	return nil
}

// Run listens for new releases until ctx ends. Call Sync once before serving traffic.
func (r *Releaser) Run(ctx context.Context) {
	for ctx.Err() == nil {
		if err := r.listen(ctx); err != nil && ctx.Err() == nil {
			r.Log.Error("release listener", "err", err)
			select {
			case <-ctx.Done():
			case <-time.After(5 * time.Second):
			}
		}
	}
}

func (r *Releaser) listen(ctx context.Context) error {
	conn, err := r.Store.db.Acquire(ctx)
	if err != nil {
		return err
	}
	defer conn.Release()
	if _, err := conn.Exec(ctx, "LISTEN policy_release"); err != nil {
		return err
	}
	for ctx.Err() == nil {
		if err := r.Sync(ctx); err != nil { // after (re)subscribing, so nothing slips between check and LISTEN
			r.Log.Error("policy release sync", "err", err)
		}
		wait, cancel := context.WithTimeout(ctx, r.Poll)
		_, err := conn.Conn().WaitForNotification(wait)
		cancel()
		if err != nil && wait.Err() == nil && ctx.Err() == nil {
			return err // connection problem, not the poll timeout
		}
	}
	return nil
}
