package handlers

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

// The token step is gated and validated by the same lookup.  When the token
// lives only at the legacy path (an install whose postinstall or entrypoint
// wrote /etc/unmask/.setup-token), the wizard used to skip the token step --
// it only stat'ed the new path -- while every POST still demanded the cookie
// the skipped step would have set: a silent dead-end on the user step.
func TestSetupNeededHonoursLegacyTokenPath(t *testing.T) {
	h := newTestHandler(t)
	dir := t.TempDir()
	oldNew, oldLegacy := SetupTokenPath, legacySetupTokenPath
	SetupTokenPath = filepath.Join(dir, "new", ".setup-token") // absent
	legacySetupTokenPath = filepath.Join(dir, ".setup-token")
	t.Cleanup(func() { SetupTokenPath, legacySetupTokenPath = oldNew, oldLegacy })
	const token = "tok-legacy-path-4242"
	if err := os.WriteFile(legacySetupTokenPath, []byte(token+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { dropWizardState(token) })

	r := httptest.NewRequest(http.MethodGet, "/unmask/admin/setup/", nil)
	if needed, step := h.SetupNeeded(r); !needed || step != "token" {
		t.Fatalf("no cookie: SetupNeeded = (%v, %q), want (true, \"token\") -- the step that mints the cookie every later POST checks", needed, step)
	}
	r.AddCookie(&http.Cookie{Name: SetupTokenCookieName, Value: token})
	if _, step := h.SetupNeeded(r); step == "token" {
		t.Fatal("a valid cookie for the legacy-path token still lands on the token step")
	}
}
