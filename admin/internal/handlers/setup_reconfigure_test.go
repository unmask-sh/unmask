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
