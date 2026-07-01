package handlers

import (
	"context"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"github.com/unmask-sh/unmask/admin/internal/db"
	"github.com/unmask-sh/unmask/admin/internal/settings"
	"github.com/unmask-sh/unmask/admin/internal/user"
)

// reconfHandler returns a fully-migrated handler.  When withAdmin is true it
// also seeds a superadmin and returns its id (= setupHasAdmin true).
func reconfHandler(t *testing.T, withAdmin bool) (*Handler, int64) {
	t.Helper()
	dir := t.TempDir()
	conn, err := db.Open(settings.DB{Driver: "sqlite", SQLitePath: filepath.Join(dir, "rc.sqlite")})
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	t.Cleanup(func() { conn.Close() })
	if err := db.Migrate(conn); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	repo := user.New(conn)
	var uid int64
	if withAdmin {
		hash, herr := user.HashPassword("correct-horse-battery")
		if herr != nil {
			t.Fatalf("hash: %v", herr)
		}
		u, cerr := repo.CreateWithHash(context.Background(), "admin", hash, user.RoleSuperadmin)
		if cerr != nil {
			t.Fatalf("create admin: %v", cerr)
		}
		uid = u.ID
	}
	h := &Handler{DB: conn, UserRepo: repo, ConfigPath: filepath.Join(dir, "config.yml")}
	h.SetSettings(settings.Settings{Secret: settings.Secret{BVSecret: "test-secret"}})
	// Point the token path at a non-existent temp file so the bootstrap path is
	// driven purely by the user count, not a stray /etc/unmask/.setup-token.
	oldTok := SetupTokenPath
	SetupTokenPath = filepath.Join(dir, ".setup-token")
	t.Cleanup(func() { SetupTokenPath = oldTok })
	return h, uid
}

func superadminCookie(uid int64) *http.Cookie {
	return issueSessionCookie("test-secret", uid, user.RoleSuperadmin, false, false)
}

// --- setupSuperadmin auth matrix ---

func TestSetupSuperadmin_RejectsNoSession(t *testing.T) {
	h, _ := reconfHandler(t, true)
	req := httptest.NewRequest("GET", "/admin/setup/", nil)
	if h.setupSuperadmin(req) != nil {
		t.Error("no session should not be treated as superadmin")
	}
}

func TestSetupSuperadmin_RejectsNonSuperadmin(t *testing.T) {
	h, _ := reconfHandler(t, true)
	// Seed a viewer and present its session.
	repo := user.New(h.DB)
	hash, _ := user.HashPassword("correct-horse-battery")
	v, err := repo.CreateWithHash(context.Background(), "viewer", hash, user.RoleViewer)
	if err != nil {
		t.Fatalf("create viewer: %v", err)
	}
	req := httptest.NewRequest("GET", "/admin/setup/", nil)
	req.AddCookie(issueSessionCookie("test-secret", v.ID, user.RoleViewer, false, false))
	if h.setupSuperadmin(req) != nil {
		t.Error("a viewer must not pass the superadmin gate")
	}
}

func TestSetupSuperadmin_AcceptsSuperadmin(t *testing.T) {
	h, uid := reconfHandler(t, true)
	req := httptest.NewRequest("GET", "/admin/setup/", nil)
	req.AddCookie(superadminCookie(uid))
	if h.setupSuperadmin(req) == nil {
		t.Error("a valid superadmin session should pass the gate")
	}
}

// TestWizardKey_SuperadminOnEmptyDB is the regression guard for the "setup
// session expired; reload and re-enter the token" loop: after switching to a
// fresh / empty DB the live table has no admin (setupHasAdmin()==false), but a
// superadmin holding a session from before the switch must keep driving the
// wizard.  Keying the state off setupHasAdmin() dropped them into the bootstrap
// token branch (no token on a configured install) -> empty key -> getWizardState
// nil -> "session expired".  Auth must win.
func TestWizardKey_SuperadminOnEmptyDB(t *testing.T) {
	h, _ := reconfHandler(t, false) // migrated, NO admin -> setupHasAdmin()==false
	if h.setupHasAdmin() {
		t.Fatal("precondition: the DB must have no admin")
	}
	req := httptest.NewRequest("GET", "/admin/setup/", nil)
	req.AddCookie(superadminCookie(1)) // a cookie that predates the DB switch
	// The user row is absent in the empty DB, so setupSuperadmin falls back to
	// the (HMAC-signed) cookie role and still recognizes the superadmin.
	if h.setupSuperadmin(req) == nil {
		t.Fatal("a valid superadmin session must pass even when the live DB is empty")
	}
	if k := h.wizardStateKey(req); k != "sess:1" {
		t.Errorf("want session-keyed wizard state on an empty DB, got %q (the bug returned \"\")", k)
	}
	if h.getWizardState(req) == nil {
		t.Error("getWizardState must not be nil for an authed superadmin (nil triggers 'session expired')")
	}
}

// TestReconfigureNoOp covers the "nothing to apply" detection that hides the
// review-step install button (and short-circuits a direct install POST): the
// selected DB is the one the daemon already runs AND no new admin is created.
func TestReconfigureNoOp(t *testing.T) {
	h, _ := reconfHandler(t, true) // admin exists; targetDBStats reuses h.DB
	live := h.cfg().DB

	if !h.reconfigureNoOp(&wizardState{DB: live, DBSet: true, UserSkipped: true}) {
		t.Error("same DB + existing admin + no new user should be a no-op")
	}
	if h.reconfigureNoOp(&wizardState{DB: live, DBSet: true, UserSet: true, Username: "extra"}) {
		t.Error("creating a new admin is a real change, not a no-op")
	}
	other := settings.DB{Driver: "sqlite", SQLitePath: filepath.Join(t.TempDir(), "other.sqlite")}
	if h.reconfigureNoOp(&wizardState{DB: other, DBSet: true, UserSkipped: true}) {
		t.Error("switching to a different DB is a change, not a no-op")
	}
	if h.reconfigureNoOp(nil) {
		t.Error("a nil wizard state must not be treated as a no-op")
	}
}

// --- SetupGate ---

func TestSetupGate_ConfiguredRejectsUnauthed(t *testing.T) {
	h, _ := reconfHandler(t, true)
	called := false
	gate := h.SetupGate(func(http.ResponseWriter, *http.Request) { called = true })
	req := httptest.NewRequest("GET", "/admin/setup/", nil) // no session
	rr := httptest.NewRecorder()
	gate(rr, req)
	if called {
		t.Error("/setup/ must not be served to an unauthenticated request on a configured install")
	}
	if rr.Code != http.StatusFound || rr.Header().Get("Location") != "/admin/" {
		t.Errorf("want 302 -> /admin/, got %d -> %q", rr.Code, rr.Header().Get("Location"))
	}
}

func TestSetupGate_ConfiguredAllowsSuperadmin(t *testing.T) {
	h, uid := reconfHandler(t, true)
	called := false
	gate := h.SetupGate(func(w http.ResponseWriter, _ *http.Request) { called = true; w.WriteHeader(200) })
	req := httptest.NewRequest("GET", "/admin/setup/", nil)
	req.AddCookie(superadminCookie(uid))
	rr := httptest.NewRecorder()
	gate(rr, req)
	if !called {
		t.Errorf("superadmin should reach /setup/ for reconfigure, got %d -> %q", rr.Code, rr.Header().Get("Location"))
	}
}

func TestSetupGate_BootstrapForcesSetup(t *testing.T) {
	h, _ := reconfHandler(t, false) // no admin yet
	called := false
	gate := h.SetupGate(func(http.ResponseWriter, *http.Request) { called = true })
	req := httptest.NewRequest("GET", "/admin/", nil) // non-setup path
	rr := httptest.NewRecorder()
	gate(rr, req)
	if called {
		t.Error("bootstrap must redirect non-setup paths to the wizard")
	}
	if rr.Code != http.StatusFound || rr.Header().Get("Location") != "/admin/setup/" {
		t.Errorf("want 302 -> /admin/setup/, got %d -> %q", rr.Code, rr.Header().Get("Location"))
	}
}

// --- wizardState.step() with UserSkipped ---

func TestWizardStep_UserSkippedAdvancesToReview(t *testing.T) {
	s := &wizardState{DBSet: true, UserSkipped: true}
	if got := s.step(); got != "review" {
		t.Errorf("skipped user step should advance to review, got %q", got)
	}
	s2 := &wizardState{DBSet: true}
	if got := s2.step(); got != "user" {
		t.Errorf("un-set, un-skipped user should stay on user step, got %q", got)
	}
}
