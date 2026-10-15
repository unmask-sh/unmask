package handlers

import (
	"strings"
	"testing"

	"github.com/unmask-sh/unmask/admin/internal/i18n"
	"github.com/unmask-sh/unmask/admin/internal/settings"
)

// renderInheritTab executes one settings tab on a test handler whose settings
// mutate has shaped, and returns the handler and the page.
func renderInheritTab(t *testing.T, tab string, mutate func(*settings.Settings)) (*Handler, string) {
	t.Helper()
	h := newTestHandler(t)
	h.updateSettingsInMemory(mutate)
	return h, renderSettingsTab(t, h, tab)
}

// inheritOptionText: the text of the inherit option in the first select whose
// name starts with prefix.
func inheritOptionText(t *testing.T, body, prefix string) string {
	t.Helper()
	i := strings.Index(body, `name="`+prefix)
	if i < 0 {
		t.Fatalf("no select named %s... in the render", prefix)
	}
	sel := body[i:]
	sel = sel[:strings.Index(sel, "</select>")]
	j := strings.Index(sel, `<option value="inherit"`)
	if j < 0 {
		t.Fatalf("select %s... has no inherit option", prefix)
	}
	opt := sel[j:]
	opt = opt[strings.Index(opt, ">")+1:]
	return opt[:strings.Index(opt, "</option>")]
}

// TestSettingsUAFilterTabInheritOptionsNameTheDefault executes the UA-filter
// tab and pins two things about the crawler groups' "when stopped" picker:
// its inherit option names the chain it resolves to -- the tab's blocklist
// default, or the operating mode's own default while that is unset -- rather
// than a bare "inherit default" (in the form the custom rows below use), and
// the picker sits before the count in the row, so the count and the Detail
// button keep one place on every row whether or not the picker is shown.  The
// blocklist presets' picker inherits the same default and is checked the same
// way.
func TestSettingsUAFilterTabInheritOptionsNameTheDefault(t *testing.T) {
	render := func(t *testing.T, defaultAction string) (body, want string) {
		h, body := renderInheritTab(t, "ua-filter", func(s *settings.Settings) {
			s.Nginx.ChallengeTargets.DefaultAction = defaultAction
		})
		return body, i18n.Tf(i18n.LangJA, "settings.asn.rate_inherit_ph", h.resolvedUABlacklistAction())
	}

	for _, tc := range []struct{ name, action string }{
		{"blocklist default set", "captcha_only"},
		{"blocklist default unset", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			body, want := render(t, tc.action)
			if tc.action != "" && !strings.Contains(want, tc.action) {
				t.Fatalf("the label should name the default %q, got %q", tc.action, want)
			}
			if tc.action == "" && strings.Contains(want, "()") {
				t.Fatalf("an unset default should resolve to the operating mode's chain, label %q", want)
			}
			for _, prefix := range []string{"upstream_group_action__", "black_preset_action__"} {
				if got := inheritOptionText(t, body, prefix); got != want {
					t.Errorf("%s inherit option = %q, want %q", prefix, got, want)
				}
			}
		})
	}

	body, _ := render(t, "")
	grp := body[strings.Index(body, `<div class="upstream-group" data-cat="`):]
	grp = grp[:strings.Index(grp, `class="upstream-detail-btn"`)]
	picker, count := strings.Index(grp, `class="upstream-action-wrap"`), strings.Index(grp, `class="upstream-count"`)
	if picker < 0 || count < 0 || picker > count {
		t.Errorf("the chain picker should come before the count in the group row (picker at %d, count at %d)", picker, count)
	}
}

// TestSettingsJA4AndHoneypotTabsInheritOptionsNameTheDefault executes the
// ja4-verdicts and honeypot tabs and pins that the pickers on their presets
// and custom rows (the scaffold a new row is cloned from included) name the
// chain "inherit" resolves to: the tab's own default, or, while that is unset,
// the install's default chain -- the one the serve runs.  A bare "inherit
// default" hid a second hop: to the rate-limit tab for JA4, and for the
// honeypot the tab even claimed a pinned pow_then_captcha that the native
// serve does not run, so its unset option is pinned to the same chain.
func TestSettingsJA4AndHoneypotTabsInheritOptionsNameTheDefault(t *testing.T) {
	tabs := []struct {
		name     string
		prefixes []string
		set      func(s *settings.Settings, action string)
		chain    func(s settings.Settings) string
	}{
		{
			name:     "ja4-verdicts",
			prefixes: []string{"ja4_preset_action__", "ja4_extra_action_chain"},
			set: func(s *settings.Settings, action string) {
				s.Nginx.JA4Verdicts.DefaultAction = action
				// A custom row, so the row's own picker renders and not only the scaffold.
				s.Nginx.JA4Verdicts.Extra = []settings.JA4VerdictExtraRule{{ID: 100, Pattern: "^t13d_test", Verdict: "bot_test", Action: "bot"}}
			},
			chain: settings.Settings.JA4DefaultChain,
		},
		{
			name:     "honeypot",
			prefixes: []string{"honeypot_preset_action__", "honeypot_url_action"},
			set: func(s *settings.Settings, action string) {
				s.Nginx.Honeypot.DefaultAction = action
				s.Nginx.Honeypot.URLs = []settings.HoneypotURL{{Path: "/trap-test"}}
			},
			chain: settings.Settings.HoneypotDefaultChain,
		},
	}
	cases := []struct{ name, action, rateDefault, wantChain string }{
		// The tab's own default wins over the install's.
		{"default set", "captcha_only", "pow_only", "captcha_only"},
		// Unset, the install's default chain is the answer -- not a pinned pow_then_captcha.
		{"default unset", "", "captcha_only", "captcha_only"},
	}
	for _, tb := range tabs {
		for _, tc := range cases {
			t.Run(tb.name+"/"+tc.name, func(t *testing.T) {
				h, body := renderInheritTab(t, tb.name, func(s *settings.Settings) {
					tb.set(s, tc.action)
					s.RateLimit.Default.ChallengeMode = tc.rateDefault
				})
				if got := tb.chain(h.snapshotSettings()); got != tc.wantChain {
					t.Fatalf("resolved chain = %q, want %q", got, tc.wantChain)
				}
				want := i18n.Tf(i18n.LangJA, "settings.asn.rate_inherit_ph", tc.wantChain)
				for _, prefix := range tb.prefixes {
					if got := inheritOptionText(t, body, prefix); got != want {
						t.Errorf("%s inherit option = %q, want %q", prefix, got, want)
					}
				}
				if strings.Contains(body, "default を継承") {
					t.Errorf("the %s tab still renders a bare inherit label", tb.name)
				}
			})
		}
	}

	// The honeypot tab's own unset option names the install's chain too, in
	// place of the pow_then_captcha it used to claim.
	_, body := renderInheritTab(t, "honeypot", func(s *settings.Settings) {
		s.Nginx.Honeypot.DefaultAction = ""
		s.RateLimit.Default.ChallengeMode = "captcha_only"
	})
	i := strings.Index(body, `name="honeypot_default_action"`)
	if i < 0 {
		t.Fatal("no honeypot_default_action select in the render")
	}
	sel := body[i:]
	sel = sel[:strings.Index(sel, "</select>")]
	if want := i18n.Tf(i18n.LangJA, "settings.select.unset_as", "captcha_only"); !strings.Contains(sel, want) {
		t.Errorf("the unset option should read %q; select: %s", want, sel)
	}
}
