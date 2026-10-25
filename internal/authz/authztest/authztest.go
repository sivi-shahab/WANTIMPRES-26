// Package authztest is a fake IdP for tests: a bearer token is just a username, and each user carries the MFA,
// login time and bindings the test wants.
package authztest

import (
	"context"
	"errors"
	"sync"
	"time"

	"wantimpres26/internal/authz"
)

type User struct {
	Bindings   []authz.Binding
	NoMFA      bool
	LoginAge   time.Duration // how long ago the user logged in
	BreakGlass bool
}

type Record struct {
	Actor, Action string
	Target        map[string]any
}

// Audit collects what the authenticator audits.
type Audit struct {
	mu      sync.Mutex
	Records []Record
	Fail    bool // make every audit write fail
}

func (a *Audit) Actions() []string {
	a.mu.Lock()
	defer a.mu.Unlock()
	var out []string
	for _, r := range a.Records {
		out = append(out, r.Actor+":"+r.Action)
	}
	return out
}

// New returns an Authenticator over users, with step-up age 5 min, and the audit sink it writes to.
// audit may be nil to use a fresh in-memory sink.
func New(users map[string]User, now func() time.Time, audit func(ctx context.Context, actor, action string, target map[string]any) error) (*authz.Authenticator, *Audit) {
	sink := &Audit{}
	if audit == nil {
		audit = func(_ context.Context, actor, action string, target map[string]any) error {
			sink.mu.Lock()
			defer sink.mu.Unlock()
			if sink.Fail {
				return errors.New("audit unavailable")
			}
			sink.Records = append(sink.Records, Record{actor, action, target})
			return nil
		}
	}
	breakGlass := map[string]bool{}
	for name, u := range users {
		if u.BreakGlass {
			breakGlass["sub-"+name] = true
		}
	}
	return &authz.Authenticator{
		Verify: func(_ context.Context, raw string) (authz.Claims, error) {
			u, ok := users[raw]
			if !ok {
				return authz.Claims{}, errors.New("unknown token")
			}
			acr := "mfa"
			if u.NoMFA {
				acr = "pwd"
			}
			return authz.Claims{Subject: "sub-" + raw, Username: raw, ACR: acr, AuthTime: now().Add(-u.LoginAge)}, nil
		},
		MFAACR:     []string{"mfa"},
		BreakGlass: breakGlass,
		Bindings: func(_ context.Context, username string) ([]authz.Binding, error) {
			return users[username].Bindings, nil
		},
		Audit:     audit,
		StepUpAge: 5 * time.Minute,
		Now:       now,
	}, sink
}

// Role is a one-binding user with a fresh MFA login.
func Role(role string) User { return User{Bindings: []authz.Binding{{Role: role}}} }
