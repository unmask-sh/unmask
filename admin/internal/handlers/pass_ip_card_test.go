package handlers

import (
	"strings"
	"testing"
	"unicode"

	"github.com/unmask-sh/unmask/admin/internal/dashboard"
	"github.com/unmask-sh/unmask/admin/internal/i18n"
)

// The reuse card carries the passes behind the reuse: per address, the
// distinct cookies presented in a day and the busiest hour of one -- two
// sections of the same rows, the second only when there is anything to rank.
func TestPassIPSectionsRender(t *testing.T) {
	body := renderReuseCard(t, map[string]any{
		"Lang":     i18n.LangJA,
		"BasePath": "/unmask/admin",
		"PassCookies": []dashboard.CookieReuseRow{
			{IP: "10.0.0.9", JA4: "t13d_q", UAFull: "Mozilla/5.0", JA4Count: 12,
				Requests: 4000, Judged: 3000, Cookies: 37, Peak: 120, LastSeenTS: 1750000000},
		},
		"PassPeaks": []dashboard.CookieReuseRow{
			{IP: "10.0.0.8", JA4: "t13d_r", Verdict: "bot_curl", IsBot: true, UAFull: "curl/8.0",
				JA4Count: 1, Requests: 999, Judged: 950, Cookies: 1, Peak: 940, LastSeenTS: 1750000000},
		},
	})
	tables := sectionTables(body)
	if len(tables) != 2 {
		t.Fatalf("rendered %d ranking tables, want the two pass sections (no reuse rows were given)", len(tables))
	}
	for _, want := range []string{"10.0.0.9", ">37<", ">120<", ">3,000<", ">12<"} {
		if !strings.Contains(tables[0], want) {
			t.Errorf("the cookies section lacks %q", want)
		}
	}
	for _, want := range []string{"10.0.0.8", "cp-bot-row", ">940<", "bot_curl"} {
		if !strings.Contains(tables[1], want) {
			t.Errorf("the peak section lacks %q", want)
		}
	}
	if !strings.Contains(body, `data-help-key="help.pass_ip.peak"`) || !strings.Contains(body, `data-help-key="help.pass_ip.cookies"`) {
		t.Error("the columns lack their help keys")
	}

	// Nothing to rank: the empty text once, and no peak section.
	body = renderReuseCard(t, map[string]any{"Lang": i18n.LangEN, "BasePath": "/x"})
	if len(sectionTables(body)) != 0 {
		t.Error("an empty card rendered a ranking table")
	}
	if !strings.Contains(body, "No request carried a pass cookie") {
		t.Error("the empty cookies section lacks its text")
	}
	if strings.Contains(body, "Busiest hour") {
		t.Error("the peak section rendered with nothing to rank")
	}
	for _, r := range body {
		if unicode.Is(unicode.Han, r) || unicode.Is(unicode.Hiragana, r) || unicode.Is(unicode.Katakana, r) {
			t.Fatalf("the English card carries Japanese text: %q", string(r))
		}
	}
}
