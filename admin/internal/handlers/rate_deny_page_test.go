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
	out := string(renderRateDeny(br, "", "", "en-US,en;q=0.9", "/unmask"))
	for _, want := range []string{
		"<!-- unmask:rate-deny -->", `lang="en"`, "Too many requests",
		"ACME", "Operated by ACME", `src="/unmask/branding/logo"`,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("default render missing %q in:\n%s", want, out)
		}
	}

	// localized (ja) by Accept-Language
	ja := string(renderRateDeny(settings.BrandingValues{}, "", "", "ja,en;q=0.8", "/unmask"))
	if !strings.Contains(ja, `lang="ja"`) || !strings.Contains(ja, "リクエストが多すぎます") {
		t.Errorf("ja render not localized:\n%s", ja)
	}

	// Arabic renders right-to-left
	if ar := string(renderRateDeny(settings.BrandingValues{}, "", "", "ar", "/unmask")); !strings.Contains(ar, `dir="rtl"`) {
		t.Errorf("ar render not rtl:\n%s", ar)
	}

	// operator override (install-wide rate-limit copy) wins over the localized
	// built-in and is shown regardless of locale
	ov := string(renderRateDeny(settings.BrandingValues{}, "Slow down", "Please retry in a bit.", "ja", "/unmask"))
	if !strings.Contains(ov, "Slow down") || !strings.Contains(ov, "Please retry in a bit.") {
		t.Errorf("override not applied:\n%s", ov)
	}
	if strings.Contains(ov, "リクエストが多すぎます") {
		t.Errorf("override should replace the i18n body, not append it")
	}

	// no LogoPath -> no logo img
	if nolog := string(renderRateDeny(settings.BrandingValues{}, "", "", "en", "/unmask")); strings.Contains(nolog, "branding/logo") {
		t.Errorf("logo img should be absent when LogoPath empty:\n%s", nolog)
	}

	// operator-controlled fields are HTML-escaped (no raw injection)
	if esc := string(renderRateDeny(settings.BrandingValues{SiteName: `<script>x</script>`}, "", "", "en", "/unmask")); strings.Contains(esc, "<script>x</script>") {
		t.Errorf("SiteName not HTML-escaped:\n%s", esc)
	}

	// a deny-copy override is HTML-escaped too (operator-controlled, not trusted markup)
	if esc := string(renderRateDeny(settings.BrandingValues{}, `<b>hi</b>`, "", "en", "/unmask")); strings.Contains(esc, "<b>hi</b>") {
		t.Errorf("deny title not HTML-escaped:\n%s", esc)
	}

	// every built-in language renders with the marker + a non-empty title/body
	for lang := range denyI18N {
		body := string(renderRateDeny(settings.BrandingValues{}, "", "", lang, "/unmask"))
		if !strings.Contains(body, "<!-- unmask:rate-deny -->") {
			t.Errorf("lang %q render missing marker", lang)
		}
		if m := denyI18N[lang]; m.Title == "" || m.Body == "" || (m.Dir != "ltr" && m.Dir != "rtl") {
			t.Errorf("lang %q has incomplete entry: %+v", lang, m)
		}
	}
}
