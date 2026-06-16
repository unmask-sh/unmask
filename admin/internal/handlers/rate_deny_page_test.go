package handlers

import (
	"strings"
	"testing"

	"github.com/unmask-sh/unmask/admin/internal/settings"
)

func TestDenyLangFromAccept(t *testing.T) {
	cases := []struct{ accept, want string }{
		{"", "en"},
		{"en-US,en;q=0.9", "en"},
		{"ja,en;q=0.8", "ja"},
		{"fr-FR,fr;q=0.9,en;q=0.8", "fr"},
		{"zh-Hant", "zh-Hant"},
		{"zh-TW,zh;q=0.9", "zh-Hant"},
		{"zh-CN,zh;q=0.9", "zh"},
		{"xx-YY,de;q=0.5", "de"}, // unknown primary skipped, de matched next
		{"klingon", "en"},        // unsupported -> en fallback
		{"  ko , en ", "ko"},     // whitespace tolerance
	}
	for _, c := range cases {
		if got := denyLangFromAccept(c.accept); got != c.want {
			t.Errorf("denyLangFromAccept(%q) = %q, want %q", c.accept, got, c.want)
		}
	}
}

func TestRenderRateDeny(t *testing.T) {
	// default English (preset defaults to friendly) + marker + branding fields.
	br := settings.BrandingValues{SiteName: "ACME", FooterText: "Operated by ACME", LogoPath: "/x/logo.png"}
	out := string(renderRateDeny(br, "friendly", "auto", "en-US,en;q=0.9", "/unmask"))
	for _, want := range []string{
		"<!-- unmask:rate-deny -->", `lang="en"`, "Thanks for your patience.",
		"ACME", "Operated by ACME", `src="/unmask/branding/logo"`,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("default render missing %q in:\n%s", want, out)
		}
	}

	// localized (ja) by Accept-Language (friendly default)
	ja := string(renderRateDeny(settings.BrandingValues{}, "friendly", "auto", "ja,en;q=0.8", "/unmask"))
	if !strings.Contains(ja, `lang="ja"`) || !strings.Contains(ja, "少々お待ちください") {
		t.Errorf("ja render not localized:\n%s", ja)
	}

	// Arabic renders right-to-left
	if ar := string(renderRateDeny(settings.BrandingValues{}, "friendly", "auto", "ar", "/unmask")); !strings.Contains(ar, `dir="rtl"`) {
		t.Errorf("ar render not rtl:\n%s", ar)
	}

	// no LogoPath -> no logo img
	if nolog := string(renderRateDeny(settings.BrandingValues{}, "friendly", "auto", "en", "/unmask")); strings.Contains(nolog, "branding/logo") {
		t.Errorf("logo img should be absent when LogoPath empty:\n%s", nolog)
	}

	// operator-controlled branding fields are HTML-escaped (no raw injection)
	if esc := string(renderRateDeny(settings.BrandingValues{SiteName: `<script>x</script>`}, "friendly", "auto", "en", "/unmask")); strings.Contains(esc, "<script>x</script>") {
		t.Errorf("SiteName not HTML-escaped:\n%s", esc)
	}

	// theme drives the <html data-theme> attribute; an unknown value clamps to auto
	for _, tc := range []struct{ in, want string }{
		{"auto", "auto"}, {"light", "light"}, {"dark", "dark"},
		{"", "auto"}, {"neon", "auto"},
	} {
		got := string(renderRateDeny(settings.BrandingValues{}, "friendly", tc.in, "en", "/unmask"))
		if !strings.Contains(got, `data-theme="`+tc.want+`"`) {
			t.Errorf("theme %q: want data-theme=%q in:\n%s", tc.in, tc.want, got)
		}
	}

	// the copy preset picks the tone; same language, different wording
	for _, tc := range []struct{ preset, wantBody string }{
		{settings.BrandingPresetFriendly, "Thanks for your patience."},
		{settings.BrandingPresetNeutral, "made too many requests in a short time."},
		{settings.BrandingPresetMinimal, "Please try again shortly."},
	} {
		got := string(renderRateDeny(settings.BrandingValues{}, tc.preset, "auto", "en", "/unmask"))
		if !strings.Contains(got, tc.wantBody) {
			t.Errorf("preset %q: want body %q in:\n%s", tc.preset, tc.wantBody, got)
		}
	}
	// an unknown preset falls back to friendly (denyMsgForPreset clamps)
	if fb := string(renderRateDeny(settings.BrandingValues{}, "bogus", "auto", "en", "/unmask")); !strings.Contains(fb, "Thanks for your patience.") {
		t.Errorf("unknown preset should fall back to friendly:\n%s", fb)
	}

	// every preset is complete: same language set as neutral, non-empty
	// title/body, and each (preset, lang) renders with the marker.
	neutral := denyMsgs[settings.BrandingPresetNeutral]
	for preset, table := range denyMsgs {
		if len(table) != len(neutral) {
			t.Errorf("preset %q has %d languages, want %d (parity with neutral)", preset, len(table), len(neutral))
		}
		for lang, m := range table {
			if _, ok := neutral[lang]; !ok {
				t.Errorf("preset %q language %q is absent from neutral", preset, lang)
			}
			if m.Title == "" || m.Body == "" {
				t.Errorf("preset %q lang %q has empty title/body: %+v", preset, lang, m)
			}
			body := string(renderRateDeny(settings.BrandingValues{}, preset, "auto", lang, "/unmask"))
			if !strings.Contains(body, "<!-- unmask:rate-deny -->") {
				t.Errorf("preset %q lang %q render missing marker", preset, lang)
			}
		}
	}
}

func TestResolvedDenyCopyPreset(t *testing.T) {
	cases := []struct{ deny, branding, want string }{
		{"", "friendly", "friendly"},       // unset -> inherit branding
		{"", "neutral", "neutral"},         // unset -> inherit branding
		{"minimal", "friendly", "minimal"}, // explicit override wins
		{"neutral", "minimal", "neutral"},  // explicit override wins
		{"bogus", "friendly", "friendly"},  // invalid -> inherit branding
	}
	for _, c := range cases {
		rl := settings.RateLimitConfig{DenyCopyPreset: c.deny}
		if got := rl.ResolvedDenyCopyPreset(c.branding); got != c.want {
			t.Errorf("ResolvedDenyCopyPreset(deny=%q, branding=%q) = %q, want %q", c.deny, c.branding, got, c.want)
		}
	}
}
