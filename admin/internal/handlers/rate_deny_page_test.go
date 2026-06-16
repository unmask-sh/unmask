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
	// default English + marker + branding fields all present
	br := settings.BrandingValues{SiteName: "ACME", FooterText: "Operated by ACME", LogoPath: "/x/logo.png"}
	out := string(renderRateDeny(br, "auto", "en-US,en;q=0.9", "/unmask"))
	for _, want := range []string{
		"<!-- unmask:rate-deny -->", `lang="en"`, "Too many requests",
		"ACME", "Operated by ACME", `src="/unmask/branding/logo"`,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("default render missing %q in:\n%s", want, out)
		}
	}

	// localized (ja) by Accept-Language
	ja := string(renderRateDeny(settings.BrandingValues{}, "auto", "ja,en;q=0.8", "/unmask"))
	if !strings.Contains(ja, `lang="ja"`) || !strings.Contains(ja, "リクエストが多すぎます") {
		t.Errorf("ja render not localized:\n%s", ja)
	}

	// Arabic renders right-to-left
	if ar := string(renderRateDeny(settings.BrandingValues{}, "auto", "ar", "/unmask")); !strings.Contains(ar, `dir="rtl"`) {
		t.Errorf("ar render not rtl:\n%s", ar)
	}

	// no LogoPath -> no logo img
	if nolog := string(renderRateDeny(settings.BrandingValues{}, "auto", "en", "/unmask")); strings.Contains(nolog, "branding/logo") {
		t.Errorf("logo img should be absent when LogoPath empty:\n%s", nolog)
	}

	// operator-controlled branding fields are HTML-escaped (no raw injection)
	if esc := string(renderRateDeny(settings.BrandingValues{SiteName: `<script>x</script>`}, "auto", "en", "/unmask")); strings.Contains(esc, "<script>x</script>") {
		t.Errorf("SiteName not HTML-escaped:\n%s", esc)
	}

	// theme drives the <html data-theme> attribute; an unknown value clamps to auto
	for _, tc := range []struct{ in, want string }{
		{"auto", "auto"}, {"light", "light"}, {"dark", "dark"},
		{"", "auto"}, {"neon", "auto"},
	} {
		got := string(renderRateDeny(settings.BrandingValues{}, tc.in, "en", "/unmask"))
		if !strings.Contains(got, `data-theme="`+tc.want+`"`) {
			t.Errorf("theme %q: want data-theme=%q in:\n%s", tc.in, tc.want, got)
		}
	}

	// every built-in language renders with the marker + a non-empty title/body
	for lang := range denyI18N {
		body := string(renderRateDeny(settings.BrandingValues{}, "auto", lang, "/unmask"))
		if !strings.Contains(body, "<!-- unmask:rate-deny -->") {
			t.Errorf("lang %q render missing marker", lang)
		}
		if m := denyI18N[lang]; m.Title == "" || m.Body == "" || (m.Dir != "ltr" && m.Dir != "rtl") {
			t.Errorf("lang %q has incomplete entry: %+v", lang, m)
		}
	}
}
