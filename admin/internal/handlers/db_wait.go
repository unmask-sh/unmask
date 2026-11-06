package handlers

import (
	"log"
	"net/http"
	"os"
	"strings"

	"github.com/unmask-sh/unmask/admin/internal/i18n"
	"github.com/unmask-sh/unmask/admin/internal/settings"
)

// A daemon that started without its database.
//
// A start that cannot open the database used to mean one thing: an install
// nobody has set up, so every admin page went to the setup wizard.  On an
// install that HAS been set up it means the database was not there yet -- a
// host that boots unmask before MariaDB, a daemon restarted while the
// database is down for maintenance -- and the wizard is the wrong answer
// twice over: it sealed itself when it finished (the token is gone, see
// hasValidSetupToken), so the redirect led to a page nobody could use, and
// nothing brought the daemon back to its database short of a restart by
// hand.
//
// So the two are told apart at the start (SetupCompleted).  The install that
// was never set up behaves as it always did.  The one that was keeps serving
// what needs no database -- the challenge pages -- says so on its admin
// routes (503, serveDBWaiting) and on /readyz, and retries the database until
// it answers, at which point it starts over in place (cmd/unmask db_wait.go).
// The process never gains a database it did not start with: Handler.DB is
// read without a lock by every request, so the state below is fixed for the
// life of the process.

// SetupCompleted reports whether this install has been through the setup
// wizard, as far as can be told without its database -- the question a start
// that cannot open the database has to answer before it knows what the
// failure means.
//
// It has not while the wizard can still be entered: a setup token is on disk
// (the package's postinstall wrote it and the wizard removes it when it
// finishes), or UNMASK_OPEN_SETUP=1 opens the wizard without one.  And it has
// not while there is nothing a retry could reach: no config file, or a db
// section that names no database.  Anything else is an install whose wizard
// sealed itself, and whose database is merely away.
//
// configPath is the resolved config file ("" when the daemon runs on
// defaults); cfg is its db section.
func SetupCompleted(configPath string, cfg settings.DB) bool {
	if setupTokenOnDisk() || os.Getenv("UNMASK_OPEN_SETUP") == "1" {
		return false
	}
	if strings.TrimSpace(configPath) == "" {
		return false
	}
	return dbSectionNamesADatabase(cfg)
}

// setupTokenOnDisk reports whether a setup-token file exists, readable or
// not, empty or not: the wizard has not removed it, so it has not finished.
// (readSetupToken answers "" for a file it cannot read, which is the right
// answer for "is this cookie the token" and the wrong one here.)
func setupTokenOnDisk() bool {
	for _, p := range []string{SetupTokenPath, legacySetupTokenPath} {
		if p == "" {
			continue
		}
		if _, err := os.Lstat(p); err == nil {
			return true
		}
	}
	return false
}

// dbSectionNamesADatabase reports whether the db section says where the
// database is.  A driver the daemon does not know, a MariaDB with no host or
// no database name, a SQLite with no path: no retry reaches those, and they
// are the wizard's to ask for.
func dbSectionNamesADatabase(cfg settings.DB) bool {
	// The drivers as db.Open reads them (settings.Load has already turned
	// "mysql" into "mariadb").
	switch cfg.Driver {
	case "", "sqlite":
		return strings.TrimSpace(cfg.SQLitePath) != ""
	case "mariadb":
		m := cfg.MariaDB
		return strings.TrimSpace(m.Host) != "" && m.Port > 0 &&
			strings.TrimSpace(m.Database) != "" && strings.TrimSpace(m.User) != ""
	}
	return false
}

// ClearStaleSetupToken removes a setup token left beside an install that is
// set up -- one whose database holds an admin account, which is what the
// caller has just read.  SetupNeeded does the same on the first admin
// request; the daemon's start does it without waiting for one, because
// SetupCompleted reads the token's absence as "set up" and a postinstall
// that mints a token on every upgrade (apk does) would otherwise make the
// next start without a database look like a fresh install.
func ClearStaleSetupToken() {
	if !setupTokenOnDisk() {
		return
	}
	log.Printf("setup: an admin account exists, so the setup token on disk is stale; removing it")
	removeSetupToken()
}

// dbWaiting reports whether this daemon runs without the database of an
// install that is set up (Handler.DBWaiting).
func (h *Handler) dbWaiting() bool {
	return h != nil && h.DBWaiting && h.DB == nil
}

// dbWaitRetryAfter is the Retry-After of the 503 the admin routes answer
// meanwhile, and the page's own reload (db_wait.html says the same number):
// the daemon's retries settle at one every thirty seconds, and it is back a
// few seconds after the one that succeeds.
const dbWaitRetryAfter = "10"

// serveDBWaiting answers an admin request on a daemon that waits for its
// database: 503, with what is going on in the operator's language.  The
// JSON routes get it as JSON, so a page's fetch reads an error it can show
// and not a document it cannot parse.  Nothing the page says depends on who
// asks, except the way to the wizard, which a signed-in superadmin is shown
// because for them it opens (SetupGate).
func (h *Handler) serveDBWaiting(w http.ResponseWriter, r *http.Request) {
	base := h.cfg().Server.BasePath
	w.Header().Set("Cache-Control", "no-store, no-cache, must-revalidate")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Retry-After", dbWaitRetryAfter)
	if strings.HasPrefix(r.URL.Path, base+"/admin/api/") {
		writeJSON(w, http.StatusServiceUnavailable, map[string]any{"ok": 0, "error": "database unavailable"})
		return
	}
	tmpl, err := loadDashboardTemplate()
	if err != nil {
		http.Error(w, "database unavailable; the daemon is retrying", http.StatusServiceUnavailable)
		return
	}
	data := map[string]any{
		"Lang":     i18n.Resolve(r),
		"BasePath": base,
		// Asking again is the same request only for a read.
		"Reload":      r.Method == http.MethodGet || r.Method == http.MethodHead,
		"Reconfigure": h.setupSuperadmin(r) != nil,
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusServiceUnavailable)
	if err := tmpl.ExecuteTemplate(w, "db_wait.html", data); err != nil {
		log.Printf("db wait render: %v", err)
	}
}
