package handlers

import (
	"regexp"
	"strings"
	"testing"

	"github.com/unmask-sh/unmask/admin/internal/dashboard"
	"github.com/unmask-sh/unmask/admin/internal/i18n"
)

// Every ranking in the reuse card carries its own "?" beside the heading: what
// the table counts and how to read its rows, in the page's language, so an
// operator need not go back to the card's one explainer for each of the five.
func TestReuseSectionsCarryTheirHelp(t *testing.T) {
	rows := []dashboard.CookieReuseRow{{IP: "10.0.0.1", JA4: "t13d_q", UAFull: "Mozilla/5.0", JA4Count: 2,
		Requests: 40, Judged: 30, Cookies: 3, Peak: 9, LastSeenTS: 1750000000}}
	peaks := []dashboard.CookieReuseRow{{IP: "10.0.0.2", JA4: "t13d_r", UAFull: "Mozilla/5.0", JA4Count: 1,
		Requests: 20, Judged: 18, Cookies: 1, Peak: 18, LastSeenTS: 1750000000}}
	heading := regexp.MustCompile(`(?s)<h6 class="cp-h">(.*?)</h6>`)
	keys := []string{"captcha_reuse.help", "pow_reuse.help", "rebind_reuse.help", "pass_ip.cookies_help", "pass_ip.peak_help"}
	for _, lang := range []i18n.Lang{i18n.LangJA, i18n.LangEN} {
		body := renderReuseCard(t, map[string]any{"Lang": lang, "BasePath": "/x",
			"CaptchaReuse": rows, "PowReuse": rows, "RebindReuse": rows, "PassCookies": rows, "PassPeaks": peaks})
		heads := heading.FindAllStringSubmatch(body, -1)
		if len(heads) != len(keys) {
			t.Fatalf("%s: %d section headings, want %d", lang, len(heads), len(keys))
		}
		for i, key := range keys {
			h := heads[i][1]
			want := i18n.T(lang, key)
			if !strings.Contains(h, `class="info-tip"`) || !strings.Contains(h, `class="info-popup"`) {
				t.Errorf("%s: heading %d (%s) has no ? popover: %s", lang, i, key, h)
				continue
			}
			if !strings.Contains(h, want) {
				t.Errorf("%s: heading %d lacks the text of %s", lang, i, key)
			}
			if strings.Count(h, `class="info-tip"`) != 1 {
				t.Errorf("%s: heading %d carries %d ? badges, want one", lang, i, strings.Count(h, `class="info-tip"`))
			}
		}
	}
	// The card's own explainer stays where it was, beside the title.
	body := renderReuseCard(t, map[string]any{"Lang": i18n.LangEN, "BasePath": "/x", "PowReuse": rows})
	if !strings.Contains(body, i18n.T(i18n.LangEN, "dashboard.captcha_reuse.desc")) {
		t.Error("the card lost its title explainer")
	}
}
