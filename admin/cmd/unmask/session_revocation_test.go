package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"testing"

	"github.com/unmask-sh/unmask/admin/internal/handlers"
	"github.com/unmask-sh/unmask/admin/internal/user"
)

// cookieValue returns the named cookie's value from a login's cookies.
func cookieValue(cookies []*http.Cookie, name string) string {
	for _, c := range cookies {
		if c.Name == name {
			return c.Value
		}
	}
	return ""
}

// A revoked session stays revoked when the client hangs up on its request.
// The account lookup ran on the request's context, so a client that closed
// its side right after sending made the lookup fail -- and a failed lookup
// kept the session, which let the cookie of a deleted, suspended, demoted or
// signed-out account save settings.
func TestRevokedSessionRefusedWhenClientHangsUp(t *testing.T) {
	cases := []struct {
		name   string
		revoke func(t *testing.T, h *handlers.Handler, id int64)
	}{
		{"signed out everywhere", func(t *testing.T, h *handlers.Handler, id int64) {
			if err := h.UserRepo.BumpSessionGen(context.Background(), id); err != nil {
				t.Fatal(err)
			}
		}},
		{"password changed", func(t *testing.T, h *handlers.Handler, id int64) {
			if err := h.UserRepo.SetPassword(context.Background(), id, "a-new-password-2026"); err != nil {
				t.Fatal(err)
			}
		}},
		{"demoted to viewer", func(t *testing.T, h *handlers.Handler, id int64) {
			if err := h.UserRepo.SetRole(context.Background(), id, user.RoleViewer); err != nil {
				t.Fatal(err)
			}
		}},
		{"suspended", func(t *testing.T, h *handlers.Handler, id int64) {
			if err := h.UserRepo.SetDisabled(context.Background(), id, true); err != nil {
				t.Fatal(err)
			}
		}},
		{"deleted", func(t *testing.T, h *handlers.Handler, id int64) {
			if err := h.UserRepo.Delete(context.Background(), id); err != nil {
				t.Fatal(err)
			}
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s, h, mux := routeFixture(t)
			base := s.Server.BasePath
			ctx := context.Background()
			for _, name := range []string{"boss", "boss2"} {
				if _, err := h.UserRepo.Create(ctx, name, name+"-pass-2026", user.RoleSuperadmin); err != nil {
					t.Fatal(err)
				}
			}
			cookies := loginAs(t, mux, base, "boss", "boss-pass-2026")
			boss, err := h.UserRepo.GetByUsername(ctx, "boss")
			if err != nil {
				t.Fatal(err)
			}
			tc.revoke(t, h, boss.ID)

			form := url.Values{"url": {"https://hooks.example/changed"}, "format": {"generic"}}
			req := httptest.NewRequest(http.MethodPost, base+"/admin/settings/save?section=notifications", strings.NewReader(form.Encode()))
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			req.Header.Set("X-CSRF-Token", cookieValue(cookies, "unmask_admin_csrf"))
			for _, c := range cookies {
				req.AddCookie(c)
			}
			hungUp, cancel := context.WithCancel(ctx)
			cancel()
			rec := httptest.NewRecorder()
			mux.ServeHTTP(rec, req.WithContext(hungUp))

			if got := h.SnapshotSettings().Notifications.URL; got != "" {
				t.Fatalf("the revoked session saved settings (webhook now %q); response %d %s", got, rec.Code, rec.Header().Get("Location"))
			}
			if rec.Code != http.StatusFound && rec.Code != http.StatusForbidden {
				t.Fatalf("response %d %s, want the sign-in redirect or 403", rec.Code, rec.Header().Get("Location"))
			}
		})
	}
}

// The reconfigure wizard makes the same account check as every other admin
// page: the cookie of a superadmin whose account was deleted opens nothing.
// It used to open the wizard, which could create a new superadmin.
func TestDeletedSuperadminCannotReconfigure(t *testing.T) {
	s, h, mux := routeFixture(t)
	base := s.Server.BasePath
	ctx := context.Background()
	// A fixed admin key: the fixture's host cannot keep the generated one, so
	// a save that reloads the settings would otherwise sign everyone out and
	// hide what this test is about.
	const fixed = "session-revocation-test-admin-secret-0123456789"
	f, err := os.OpenFile(h.ConfigPath, os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = f.WriteString("  admin_secret: " + fixed + "\nnginx:\n  output_dir: " + t.TempDir() + "\n")
	_ = f.Close()
	cur := h.SnapshotSettings()
	cur.Secret.AdminSecret = fixed
	h.SetSettings(cur)

	for _, name := range []string{"departed", "boss"} {
		if _, err := h.UserRepo.Create(ctx, name, name+"-pass-2026", user.RoleSuperadmin); err != nil {
			t.Fatal(err)
		}
	}
	cookies := loginAs(t, mux, base, "departed", "departed-pass-2026")
	dep, err := h.UserRepo.GetByUsername(ctx, "departed")
	if err != nil {
		t.Fatal(err)
	}
	if err := h.UserRepo.Delete(ctx, dep.ID); err != nil {
		t.Fatal(err)
	}
	do := func(method, path string, form url.Values) *httptest.ResponseRecorder {
		var req *http.Request
		if form != nil {
			req = httptest.NewRequest(method, base+path, strings.NewReader(form.Encode()))
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			req.Header.Set("X-CSRF-Token", cookieValue(cookies, "unmask_admin_csrf"))
		} else {
			req = httptest.NewRequest(method, base+path, nil)
		}
		for _, c := range cookies {
			req.AddCookie(c)
		}
		return serve(mux, req)
	}

	if rec := do(http.MethodGet, "/admin/setup/", nil); rec.Code == http.StatusOK && strings.Contains(rec.Body.String(), `name="driver"`) {
		t.Fatalf("the deleted account's cookie opened the reconfigure wizard")
	}
	do(http.MethodPost, "/admin/setup/db", url.Values{"driver": {"existing"}})
	do(http.MethodPost, "/admin/setup/user", url.Values{"username": {"backdoor"}, "password": {"backdoor-pass-2026"}, "password_confirm": {"backdoor-pass-2026"}})
	do(http.MethodPost, "/admin/setup/install", url.Values{})
	if u, err := h.UserRepo.GetByUsername(ctx, "backdoor"); err == nil {
		t.Fatalf("the deleted account's cookie created account %q (role %s) through the wizard", u.Username, u.Role)
	}
}

// When the database does not answer, a session is neither honoured nor
// signed out: the request gets 503 and the cookie stays, so the next request
// after the blip goes through.
func TestUncheckedSessionRefusedButKept(t *testing.T) {
	s, h, mux := routeFixture(t)
	base := s.Server.BasePath
	ctx := context.Background()
	if _, err := h.UserRepo.Create(ctx, "boss", "boss-pass-2026", user.RoleSuperadmin); err != nil {
		t.Fatal(err)
	}
	cookies := loginAs(t, mux, base, "boss", "boss-pass-2026")
	if err := h.DB.Close(); err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodGet, base+"/admin/api/now", nil)
	for _, c := range cookies {
		req.AddCookie(c)
	}
	rec := serve(mux, req)
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("session check without a database: %d, want 503", rec.Code)
	}
	for _, c := range rec.Result().Cookies() {
		if c.Name == "unmask_admin_session" {
			t.Fatalf("the session cookie was touched (%q, MaxAge %d); a database blip must not sign anyone out", c.Value, c.MaxAge)
		}
	}
}
