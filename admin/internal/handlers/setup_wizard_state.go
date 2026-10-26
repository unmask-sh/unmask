// In-flight setup-wizard input.  The Cacti / Zabbix style "commit at the
// end" wizard collects each step's input here (= keyed by the setup-token
// cookie value) and applies everything atomically in the Install step.
//
// Storage is in-memory (single admin instance + short TTL = no Db round-trip).
// Lost on restart; the user simply restarts the wizard from the token step.
package handlers

import (
	"sync"
	"time"

	"github.com/unmask-sh/unmask/admin/internal/settings"
)

// wizardStateTTL: how long collected input is held before being forgotten.
// Matches SetupTokenCookieName MaxAge so a stale cookie can't resurrect old input.
const wizardStateTTL = 1 * time.Hour

type wizardState struct {
	DBSet        bool
	DB           settings.DB
	UserSet      bool
	UserSkipped  bool // reconfigure: keep the target DB's existing admin instead of creating one
	Username     string
	PasswordHash string // argon2id PHC; the plaintext is hashed at entry and never kept (AUTH-7)
	// OptionsSet: the options step was submitted.  A wizard driven by a
	// script (the container smoke test posts install right after the user
	// step) never visits it, and install then leaves every option as the
	// config has it -- the defaults, on a fresh install.
	OptionsSet bool
	Options    wizardOptions
	expires    time.Time
}

// wizardOptions: what the options step collects.  Every communication is a
// switch that is on by default; the step lists them so the operator can
// turn one off before the daemon makes the first contact, instead of
// finding the setting later.  The two other fields are the first-run
// choices the settings tabs would otherwise ask for: the hostname the admin
// UI answers on, and monitor mode.
type wizardOptions struct {
	// Feed: the shared BAN feed -- the hourly pull and the registration with
	// the hub (community_bans.subscribe_mode).
	Feed bool
	// Liveness: the pull carries this install's token so the hub can count
	// running installs (community_bans.publish_liveness).
	Liveness bool
	// Country: the reporter's country code on the feed
	// (community_bans.publish_country).
	Country bool
	// GeoIP: the DB-IP Lite download and its updates (ipgeo.auto_fetch,
	// auto_update, auto_update_asn).
	GeoIP bool
	// Sync: the daily download of the crawler IP ranges and the browser
	// versions (nginx.sync_disabled, inverted).
	Sync bool
	// VersionCheck: the update check (version_check_disabled, inverted).
	VersionCheck bool
	// AdminHost: the one entry for nginx.admin_allowed_hosts, with its
	// marker ("exact:admin.example.com"); "" = no restriction.
	AdminHost string
	// ObserveOnly: start in monitor mode (challenge.default.observe_only).
	ObserveOnly bool
}

// step returns the next-step name based on what's been collected so far.
// Order: db -> user -> options -> review.  Each step is "missing" until its
// Set flag flips true.  The options step is for the first run only: a
// superadmin reconfiguring the database (reconfigure) already has every
// option on the settings tabs, and the wizard must not rewrite them from a
// form that shows defaults.
func (w *wizardState) step(reconfigure bool) string {
	if !w.DBSet {
		return "db"
	}
	if !w.UserSet && !w.UserSkipped {
		return "user"
	}
	if !w.OptionsSet && !reconfigure {
		return "options"
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

// wizardStateForKey returns the in-flight state for key, allocating an empty
// one if none exists.  The caller derives key from the bootstrap token cookie
// or, when reconfiguring, the authenticated superadmin session (see
// Handler.wizardStateKey).  An empty key yields nil so the caller can redirect.
func wizardStateForKey(key string) *wizardState {
	if key == "" {
		return nil
	}
	now := time.Now()
	wizardStateMu.Lock()
	defer wizardStateMu.Unlock()
	gcExpiredLocked(now)
	s := wizardStates[key]
	if s == nil {
		s = &wizardState{expires: now.Add(wizardStateTTL)}
		wizardStates[key] = s
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
