package handlers

import (
	"bytes"
	"regexp"
	"strings"
	"testing"

	"github.com/unmask-sh/unmask/admin/internal/dashboard"
	"github.com/unmask-sh/unmask/admin/internal/i18n"
)

// renderReuseCard executes the real card template with the real funcmap, so a
// template error (a bad dict call, a missing i18n key, a field renamed out from
// under the markup) fails here rather than on the live dashboard.
func renderReuseCard(t *testing.T, data map[string]any) string {
	t.Helper()
	tmpl, err := loadDashboardTemplate()
	if err != nil {
		t.Fatalf("load dashboard templates: %v", err)
	}
	var buf bytes.Buffer
	if err := tmpl.ExecuteTemplate(&buf, "captcha_reuse_card", data); err != nil {
		t.Fatalf("execute captcha_reuse_card: %v", err)
	}
	return buf.String()
}

// sectionRows counts the <tr> rows rendered under each ranking table, keyed by
// the order the sections appear (CAPTCHA first, PoW second).
func sectionTables(body string) []string {
	return regexp.MustCompile(`(?s)<table[^>]*cp-rankable.*?</table>`).FindAllString(body, -1)
}

// TestCookieReuseCardRendersBothSections: the card gained a second ranking, and
// the two sections must stay distinguishable -- same markup, different rows,
// and the fingerprint-spread column only where it is meaningful.
func TestCookieReuseCardRendersBothSections(t *testing.T) {
	body := renderReuseCard(t, map[string]any{
		"Lang":     i18n.LangJA,
		"BasePath": "/unmask/admin",
		"CaptchaReuse": []dashboard.CookieReuseRow{
			{IP: "1.2.3.4", JA4: "t13d_a", Verdict: "bot_curl", IsBot: true,
				UAFull: "curl/8.0", JA4Count: 1, Requests: 500, LastSeenTS: 1750000000},
		},
		"PowReuse": []dashboard.CookieReuseRow{
			{IP: "10.0.0.2", JA4: "t13d_z", UAFull: "Mozilla/5.0",
				JA4Count: 1, Requests: 9000, LastSeenTS: 1750000000},
			{IP: "10.0.0.1", JA4: "t13d_b", UAFull: "Mozilla/5.0",
				JA4Count: 37, Requests: 8000, LastSeenTS: 1750000000},
		},
	})

	tables := sectionTables(body)
	if len(tables) != 2 {
		t.Fatalf("rendered %d ranking tables, want one per cookie kind", len(tables))
	}
	if !strings.Contains(tables[0], "1.2.3.4") || strings.Contains(tables[0], "10.0.0.") {
		t.Error("the first table must hold the CAPTCHA rows only")
	}
	if !strings.Contains(tables[1], "10.0.0.2") || strings.Contains(tables[1], "1.2.3.4") {
		t.Error("the second table must hold the PoW rows only")
	}

	// The JA4-spread column is what makes the PoW ranking readable (volume alone
	// cannot separate a scraper from carrier NAT), and it is noise on the
	// CAPTCHA side, where holding the cookie is already the signal.
	if strings.Contains(tables[0], "JA4 種類数") {
		t.Error("the CAPTCHA section must not carry the JA4-count column")
	}
	if !strings.Contains(tables[1], "JA4 種類数") {
		t.Error("the PoW section must carry the JA4-count column")
	}
	if !strings.Contains(tables[1], `>37<`) {
		t.Error("the shared-egress row must render its JA4 count")
	}
	// A single fingerprint at volume is the row an operator is hunting, so it
	// gets a class the stylesheet can pick out.
	if !strings.Contains(tables[1], "cr-ja4n-single") {
		t.Error("a JA4Count of 1 must be marked for emphasis")
	}
	// Both kinds keep the bot-row highlight wiring.
	if !strings.Contains(tables[0], "cp-bot-row") {
		t.Error("a bot verdict must still highlight its row")
	}
	// The caveat about who tops the PoW ranking has to travel with the card.
	if !strings.Contains(body, "NAT") {
		t.Error("the PoW note explaining shared egress is missing")
	}
}

// TestCookieReuseCardEmptySections: an empty ranking still renders its heading
// and its own empty message -- a section that vanished would read as "this kind
// is not being collected" when it just had no traffic.
func TestCookieReuseCardEmptySections(t *testing.T) {
	body := renderReuseCard(t, map[string]any{
		"Lang": i18n.LangJA, "BasePath": "/unmask/admin",
		"CaptchaReuse": []dashboard.CookieReuseRow{}, "PowReuse": []dashboard.CookieReuseRow{},
	})
	if n := len(sectionTables(body)); n != 0 {
		t.Fatalf("rendered %d tables for empty data, want 0", n)
	}
	for _, want := range []string{"CAPTCHA cookie", "PoW cookie"} {
		if !strings.Contains(body, want) {
			t.Errorf("the %q heading must render even with no rows", want)
		}
	}
	if strings.Count(body, "使い回し") < 2 {
		t.Error("each empty section needs its own message, not a single shared one")
	}
}

// TestCookieReuseCardEnglish: the card is fully translated, so rendering under
// en must not fall through to a raw key.
func TestCookieReuseCardEnglish(t *testing.T) {
	body := renderReuseCard(t, map[string]any{
		"Lang": i18n.LangEN, "BasePath": "/unmask/admin",
		"CaptchaReuse": []dashboard.CookieReuseRow{},
		"PowReuse": []dashboard.CookieReuseRow{
			{IP: "10.0.0.1", JA4Count: 3, Requests: 10, LastSeenTS: 1750000000},
		},
	})
	for _, key := range []string{"pow_reuse.rank_heading", "pow_reuse.empty", "pow_reuse.note", "th.ja4_count"} {
		if strings.Contains(body, key) {
			t.Errorf("untranslated key %q leaked into the page", key)
		}
	}
	if !strings.Contains(body, "JA4 count") {
		t.Error("the English JA4-count header is missing")
	}
}
