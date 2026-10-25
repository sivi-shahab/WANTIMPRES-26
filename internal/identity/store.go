// Package identity holds users and groups provisioned over SCIM 2.0 and the role bindings that give them
// permissions (spec §10.1, ADR-0002). Every change that can alter someone's permissions is audited.
package identity

import (
	"context"
	_ "embed"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"wantimpres26/internal/audit"
	"wantimpres26/internal/authz"
)

//go:embed schema.sql
var schemaSQL string

var (
	ErrNotFound = errors.New("not found")
	ErrConflict = errors.New("conflict")
	ErrInvalid  = errors.New("invalid")
)

// Store is the Postgres-backed identity module. Tenant is the audit log tenant (single deployment, ADR-0001).
type Store struct {
	db     *pgxpool.Pool
	tenant string
}

func Open(ctx context.Context, db *pgxpool.Pool, tenant string) (*Store, error) {
	if _, err := db.Exec(ctx, schemaSQL); err != nil {
		return nil, fmt.Errorf("apply identity schema: %w", err)
	}
	return &Store{db: db, tenant: tenant}, nil
}

// inTx runs f in a transaction and appends one audit entry with it, so the change and its record commit together.
func (s *Store) inTx(ctx context.Context, actor, action string, f func(pgx.Tx) (map[string]any, error)) error {
	return pgx.BeginFunc(ctx, s.db, func(tx pgx.Tx) error {
		target, err := f(tx)
		if err != nil || target == nil {
			return err
		}
		_, err = audit.AppendTx(ctx, tx, s.tenant, actor, action, target)
		return err
	})
}

// Bindings returns the unexpired role bindings of an active user, direct and through groups. Unknown or
// deactivated users get none: deny by default.
func (s *Store) Bindings(ctx context.Context, username string) ([]authz.Binding, error) {
	rows, err := s.db.Query(ctx, `SELECT b.role, b.attrs, b.expires_at FROM identity.role_bindings b
		JOIN identity.users u ON u.active AND lower(u.user_name) = lower($1)
		WHERE (b.user_id = u.id OR b.group_id IN (SELECT group_id FROM identity.group_members WHERE user_id = u.id))
		  AND (b.expires_at IS NULL OR b.expires_at > now())`, username)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, func(r pgx.CollectableRow) (authz.Binding, error) {
		var b authz.Binding
		var exp *time.Time
		err := r.Scan(&b.Role, &b.Attrs, &exp)
		if exp != nil {
			b.Expires = *exp
		}
		return b, err
	})
}

// RoleBinding is the API view of a binding.
type RoleBinding struct {
	ID        string      `json:"id"`
	User      string      `json:"user,omitempty"`  // userName
	Group     string      `json:"group,omitempty"` // displayName
	Role      string      `json:"role"`
	Attrs     authz.Attrs `json:"attrs"`
	ExpiresAt *time.Time  `json:"expires_at,omitempty"`
	CreatedBy string      `json:"created_by"`
	CreatedAt time.Time   `json:"created_at"`
}

func (s *Store) ListBindings(ctx context.Context) ([]RoleBinding, error) {
	rows, err := s.db.Query(ctx, `SELECT b.id, coalesce(u.user_name, ''), coalesce(g.display_name, ''), b.role, b.attrs,
		b.expires_at, b.created_by, b.created_at FROM identity.role_bindings b
		LEFT JOIN identity.users u ON u.id = b.user_id LEFT JOIN identity.groups g ON g.id = b.group_id ORDER BY b.created_at`)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, pgx.RowToStructByPos[RoleBinding])
}

// Bind gives a user (by userName) or group (by displayName) a role. Audited as identity.role.bind.
func (s *Store) Bind(ctx context.Context, actor string, b RoleBinding) (RoleBinding, error) {
	if !authz.ValidRole(b.Role) || (b.User == "") == (b.Group == "") {
		return RoleBinding{}, fmt.Errorf("%w: need a known role and exactly one of user or group", ErrInvalid)
	}
	if b.Role == "break_glass" {
		return RoleBinding{}, fmt.Errorf("%w: break_glass is not bindable; it belongs to the configured accounts", ErrInvalid)
	}
	err := s.inTx(ctx, actor, "identity.role.bind", func(tx pgx.Tx) (map[string]any, error) {
		var userID, groupID *string
		var id string
		if b.User != "" {
			if err := tx.QueryRow(ctx, "SELECT id FROM identity.users WHERE lower(user_name) = lower($1)", b.User).Scan(&id); err != nil {
				return nil, notFound(err)
			}
			userID = &id
		} else {
			if err := tx.QueryRow(ctx, "SELECT id FROM identity.groups WHERE display_name = $1", b.Group).Scan(&id); err != nil {
				return nil, notFound(err)
			}
			groupID = &id
		}
		err := tx.QueryRow(ctx, `INSERT INTO identity.role_bindings (user_id, group_id, role, attrs, expires_at, created_by)
			VALUES ($1, $2, $3, $4, $5, $6) RETURNING id, created_at`, userID, groupID, b.Role, b.Attrs, b.ExpiresAt, actor).Scan(&b.ID, &b.CreatedAt)
		b.CreatedBy = actor
		return map[string]any{"binding": b.ID, "user": b.User, "group": b.Group, "role": b.Role, "attrs": b.Attrs, "expires_at": b.ExpiresAt}, err
	})
	return b, err
}

// Unbind removes a binding. Audited as identity.role.unbind.
func (s *Store) Unbind(ctx context.Context, actor, id string) error {
	return s.inTx(ctx, actor, "identity.role.unbind", func(tx pgx.Tx) (map[string]any, error) {
		var role string
		if err := tx.QueryRow(ctx, "DELETE FROM identity.role_bindings WHERE id = $1 RETURNING role", id).Scan(&role); err != nil {
			return nil, notFound(err)
		}
		return map[string]any{"binding": id, "role": role}, nil
	})
}

func notFound(err error) error {
	if errors.Is(err, pgx.ErrNoRows) {
		return ErrNotFound
	}
	return err
}

// UserActive reports whether userName is a provisioned, active user, inside the caller's transaction (agent
// owners, ticket 27). Unknown users are not active.
func UserActive(ctx context.Context, tx pgx.Tx, userName string) (bool, error) {
	var active bool
	err := tx.QueryRow(ctx, "SELECT active FROM identity.users WHERE lower(user_name) = lower($1)", userName).Scan(&active)
	if errors.Is(err, pgx.ErrNoRows) {
		return false, nil
	}
	return active, err
}

// UserExists reports whether userName is provisioned at all, active or not (agent identities must not be user
// accounts, ticket 27).
func UserExists(ctx context.Context, tx pgx.Tx, userName string) (bool, error) {
	var exists bool
	err := tx.QueryRow(ctx, "SELECT EXISTS (SELECT 1 FROM identity.users WHERE lower(user_name) = lower($1))", userName).Scan(&exists)
	return exists, err
}
