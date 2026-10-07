package notifier

import (
	"strings"
	"testing"

	"github.com/unmask-sh/unmask/admin/internal/i18n"
)

var stuckReport = OverBlockReport{
	Tripped: true, Minutes: 10, Stuck: 5, Loaders: 6, StuckPct: 83,
	Rechallenged: 3, VerifyFailed: 2, Passed: 4, Serves: 120, ServeIPs: 40, Loads: 9,
	MinStuck: 3, MinPct: 50,
	Examples: []OverBlockExample{
		{IP: "203.0.113.5", Site: "shop.example", Path: "/cart", Rechallenged: 4},
		{IP: "2001:db8::7", Site: "shop.example", Path: "/", VerifyFailed: 2},
	},
	AdminURL: "https://admin.example/unmask",
}

// The trip mail says what is happening in plain words, the figures it was
// decided on, the addresses stuck, that protection is unchanged, and where to
// look -- in both parts, in the reader's language.  The one it replaces was a
// single line of "browser-grade challenge serves" and a ratio.
func TestRenderOverBlockTripped(t *testing.T) {
	for _, c := range []struct {
		lang i18n.Lang
		want []string
	}{
		{i18n.LangEN, []string{"Visitors may be stuck at the challenge", "5 of the 6 addresses that ran the challenge could not get through (83%)",
			"3 passed it and were shown it again", "2 had their answer fail verification", "203.0.113.5", "shop.example/cart", "shown again 4 times",
			"Protection is unchanged", "unmask doctor", "restart nginx", "3 addresses and 50%"}},
		{i18n.LangJA, []string{"challenge を通れない訪問者がいる可能性があります", "challenge を実行した 6 アドレスのうち 5 アドレス (83%) が通れていません",
			"3 アドレスは、通過したのに", "2 アドレスは、回答の検証に失敗しました", "2001:db8::7", "検証失敗 2 回", "保護は変わっていません",
			"unmask doctor", "3 アドレス以上かつ 50% 以上"}},
	} {
		subject, text, html := renderOverBlock(stuckReport, c.lang, "web1", stuckReport.AdminURL)
		if !strings.HasPrefix(subject, "[unmask:web1] ") || !strings.Contains(subject, i18n.T(c.lang, "mail.overblock.title_tripped")) {
			t.Errorf("%s subject = %q", c.lang, subject)
		}
		for _, w := range c.want {
			if !strings.Contains(text, w) {
				t.Errorf("%s text lacks %q:\n%s", c.lang, w, text)
			}
			if !strings.Contains(html, strings.ReplaceAll(w, "&", "&amp;")) {
				t.Errorf("%s html lacks %q", c.lang, w)
			}
		}
		if !strings.Contains(text, "https://admin.example/unmask/admin/hunt/?range=1h") || !strings.Contains(html, `href="https://admin.example/unmask/admin/hunt/?range=1h"`) {
			t.Errorf("%s: no link to the bot hunt", c.lang)
		}
		if strings.Contains(html, "<script") || strings.Contains(html, "<img") || strings.Contains(html, "http://") {
			t.Errorf("%s html fetches or runs something", c.lang)
		}
	}
	// Without the admin's address there is no link, and the mail says where to look.
	_, text, html := renderOverBlock(stuckReport, i18n.LangEN, "", "")
	if strings.Contains(text, "/admin/hunt/") || strings.Contains(html, "href=") || !strings.Contains(text, i18n.T(i18n.LangEN, "mail.overblock.check_hunt")) {
		t.Errorf("no admin URL: the mail should point at the bot hunt in words:\n%s", text)
	}
	// A visitor-supplied path is escaped in the HTML part.
	r := stuckReport
	r.Examples = []OverBlockExample{{IP: "203.0.113.9", Site: "s", Path: "/<script>alert(1)</script>", Rechallenged: 1}}
	if _, _, h := renderOverBlock(r, i18n.LangEN, "", ""); strings.Contains(h, "<script>alert") {
		t.Error("a path from the log reached the HTML unescaped")
	}
}

// The recovery mail: what it fell to, against where the alert fires.
func TestRenderOverBlockCleared(t *testing.T) {
	r := OverBlockReport{Minutes: 10, Stuck: 1, Loaders: 40, StuckPct: 2, MinStuck: 3, MinPct: 50}
	subject, text, _ := renderOverBlock(r, i18n.LangEN, "web1", "")
	if !strings.Contains(subject, "Visitors get past the challenge again") || !strings.Contains(text, "1 of the 40 addresses") || !strings.Contains(text, "below the alert's line of 3 addresses and 50%") {
		t.Errorf("cleared: %q\n%s", subject, text)
	}
	_, ja, _ := renderOverBlock(r, i18n.LangJA, "web1", "")
	if !strings.Contains(ja, "challenge を通れるようになりました") || !strings.Contains(ja, "下回りました") {
		t.Errorf("cleared (ja):\n%s", ja)
	}
}
