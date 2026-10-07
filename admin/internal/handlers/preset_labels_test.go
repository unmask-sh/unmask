package handlers

import (
	"strings"
	"testing"

	"github.com/unmask-sh/unmask/admin/internal/i18n"
	"github.com/unmask-sh/unmask/admin/internal/user"
)

// A preset says how its patterns are read, as a custom row does, and when it
// shipped and when a release last changed it.  The SQL-injection preset
// shipped opt-in in v0.1.0 and went on by default in v0.1.50 -- "since
// v0.1.50" said it was new then.
func TestPresetRowsSayModeAndVersions(t *testing.T) {
	h := vacuumHandler(t, 10)
	since := func(v string) string { return i18n.Tf(i18n.LangEN, "settings.ua.added_in", v) }
	updated := func(v string) string { return i18n.Tf(i18n.LangEN, "settings.ua.updated_in", v) }
	regexChip := `<span class="pat-lit lead" data-mode="regex">` + patModeName(i18n.LangEN, "regex") + `</span>`

	// The row of one preset: from its checkbox to the next row's.
	row := func(body, input string) string {
		t.Helper()
		i := strings.Index(body, input)
		if i < 0 {
			t.Fatalf("no preset row %s", input)
		}
		rest := body[i:]
		if j := strings.Index(rest[1:], `<div class="preset`); j >= 0 {
			rest = rest[:j+1]
		}
		return rest
	}

	hp := renderTab(t, h, "honeypot", user.RoleSuperadmin, "en")
	sqli := row(hp, `value="sql-injection"`)
	for _, w := range []string{since("v0.1.0"), updated("v0.1.50"), regexChip} {
		if !strings.Contains(sqli, w) {
			t.Errorf("the SQL-injection preset row lacks %q", w)
		}
	}
	if strings.Contains(sqli, since("v0.1.50")) || strings.Contains(sqli, `class="new-badge"`) {
		t.Error("the SQL-injection preset reads as added in v0.1.50")
	}
	if wp := row(hp, `value="wordpress"`); strings.Contains(wp, "updated ") || !strings.Contains(wp, regexChip) {
		t.Error("the WordPress preset: an updated label it has no release for, or no mode chip")
	}

	// The machine-access path presets went on by default in v0.1.2.
	bp := renderTab(t, h, "bypass-paths", user.RoleSuperadmin, "en")
	if r := row(bp, `value="static-assets"`); !strings.Contains(r, updated("v0.1.2")) || !strings.Contains(r, regexChip) {
		t.Error("the static-assets preset row lacks its updated label or its mode chip")
	}
	if r := row(renderTab(t, h, "protected", user.RoleSuperadmin, "en"), `value="unmask"`); !strings.Contains(r, updated("v0.1.28")) || !strings.Contains(r, regexChip) {
		t.Error("the unmask protected-path preset row lacks its updated label or its mode chip")
	}
	// A JA4 preset says it on every rule's line.
	ja4 := row(renderTab(t, h, "ja4-verdicts", user.RoleSuperadmin, "en"), `value="rotating_proxy"`)
	if n := strings.Count(ja4, `class="pat-lit lead" data-mode="regex"`); n != 4 {
		t.Errorf("the rotating_proxy preset has %d mode chips, want one on each of its 4 rules", n)
	}
	// The IP-range presets: PerplexityBot's source moved in v0.1.7.
	ips := renderTab(t, h, "bypass-ips", user.RoleSuperadmin, "ja")
	i := strings.Index(ips, `value="perplexitybot"`)
	if i < 0 {
		t.Fatal("no PerplexityBot range preset")
	}
	tr := ips[i:]
	if j := strings.Index(tr, "</tr>"); j >= 0 {
		tr = tr[:j]
	}
	if !strings.Contains(tr, i18n.Tf(i18n.LangJA, "settings.ua.updated_in", "v0.1.7")) {
		t.Error("the PerplexityBot range preset lacks its updated label")
	}
}
