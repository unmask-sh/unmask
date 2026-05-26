// In-flight setup-wizard input.  The Cacti / Zabbix style "commit at the
// end" wizard collects each step's input here (= keyed by the setup-token
// cookie value) and applies everything atomically in the Install step.
//
// Storage is in-memory (single admin instance + short TTL = no Db round-trip).
// Lost on restart; the user simply restarts the wizard from the token step.
package handlers

import (
	"net/http"
	"sync"
	"time"

	"github.com/unmask-sh/unmask/admin/internal/settings"
)

// wizardStateTTL: how long collected input is held before being forgotten.
// Matches SetupTokenCookieName MaxAge so a stale cookie can't resurrect old input.
const wizardStateTTL = 1 * time.Hour

type wizardState struct {
	DBSet    bool
	DB       settings.DB
	UserSet  bool
	Username string
	Password string
	expires  time.Time
}

// step returns the next-step name based on what's been collected so far.
// Order: db -> user -> review.  Each step is "missing" until its Set flag
// flips true.  The bot-detection posture is configured later in the Operating mode
// tab so the wizard stays narrowly focused on "make admin reachable".
func (w *wizardState) step() string {
	if !w.DBSet {
		return "db"
	}
	if !w.UserSet {
		return "user"
	}
	return "review"
}

var (
	wizardStateMu sync.Mutex
	wizardStates  = map[string]*wizardState{}
)

// gcExpiredLocked drops entries whose TTL has passed.  Called from the
// public helpers (= lazy GC; we don't run a goroutine for this).  Caller
// holds wizardStateMu.
func gcExpiredLocked(now time.Time) {
	for k, s := range wizardStates {
		if now.After(s.expires) {
			delete(wizardStates, k)
		}
	}
}

// getWizardState returns the current state for the request, allocating
// an empty one if none exists yet.  Returns nil if the request has no
// valid setup token cookie (= caller must redirect to the token step).
func getWizardState(r *http.Request) *wizardState {
	c, err := r.Cookie(SetupTokenCookieName)
	if err != nil || c.Value == "" {
		return nil
	}
	now := time.Now()
	wizardStateMu.Lock()
	defer wizardStateMu.Unlock()
	gcExpiredLocked(now)
	s := wizardStates[c.Value]
	if s == nil {
		s = &wizardState{expires: now.Add(wizardStateTTL)}
		wizardStates[c.Value] = s
	}
	return s
}

// touchWizardState bumps the TTL on each meaningful write so the user has
// the full TTL window from their last interaction (= not the start of the
// wizard).  Called internally by the savers.
func touchWizardState(s *wizardState) {
	s.expires = time.Now().Add(wizardStateTTL)
}

// dropWizardState removes the in-flight state for a token (= called after
// a successful Install or when the token is regenerated).
func dropWizardState(tokenValue string) {
	wizardStateMu.Lock()
	defer wizardStateMu.Unlock()
	delete(wizardStates, tokenValue)
}
