package handlers

import (
	"github.com/unmask-sh/unmask/admin/internal/i18n"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/unmask-sh/unmask/admin/internal/settings"
)

// TestApplyUAFilterFormUAEnabled pins the upstream_ua_enabled intake: only
// range-backed patterns are kept (UA rescue is the only path for the rest, so
// listing them would be dead weight), a pattern also posted as disabled stays
// disabled, and duplicates collapse.
func TestApplyUAFilterFormUAEnabled(t *testing.T) {
	form := url.Values{}
	form.Add("upstream_ua_enabled", `Googlebot\/`)
	form.Add("upstream_ua_enabled", `Googlebot\/`) // dup
	form.Add("upstream_ua_enabled", `ClaudeBot`)   // not range-backed -> dropped
	form.Add("upstream_ua_enabled", `GPTBot`)      // also disabled below -> dropped
	form.Add("upstream_ua_enabled", "  ")          // blank -> dropped
	form.Add("upstream_disabled", `GPTBot`)

	r := httptest.NewRequest("POST", "/unmask/admin/settings/", strings.NewReader(form.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if err := r.ParseForm(); err != nil {
		t.Fatal(err)
	}

	var n settings.Nginx
	if err := applyUAFilterForm(&n, r, i18n.LangEN); err != nil {
		t.Fatalf("applyUAFilterForm: %v", err)
	}

	if got := n.SearchBots.UpstreamUAEnabled; len(got) != 1 || got[0] != `Googlebot\/` {
		t.Errorf("UpstreamUAEnabled = %q, want [Googlebot\\/]", got)
	}
	if got := n.SearchBots.UpstreamDisabled; len(got) != 1 || got[0] != `GPTBot` {
		t.Errorf("UpstreamDisabled = %q, want [GPTBot]", got)
	}
}
