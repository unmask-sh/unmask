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
	out := string(renderRateDeny(br, "friendly", "auto", "en-US,en;q=0.9", "/unmask", ""))
	for _, want := range []string{
		"<!-- unmask:rate-deny -->", `lang="en"`, "Thanks for your patience.",
		"ACME", "Operated by ACME", `src="/unmask/branding/logo"`,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("default render missing %q in:\n%s", want, out)
		}
	}

	// localized (ja) by Accept-Language (friendly default)
	ja := string(renderRateDeny(settings.BrandingValues{}, "friendly", "auto", "ja,en;q=0.8", "/unmask", ""))
	if !strings.Contains(ja, `lang="ja"`) || !strings.Contains(ja, "少々お待ちください") {
		t.Errorf("ja render not localized:\n%s", ja)
	}

	// Arabic renders right-to-left
	if ar := string(renderRateDeny(settings.BrandingValues{}, "friendly", "auto", "ar", "/unmask", "")); !strings.Contains(ar, `dir="rtl"`) {
		t.Errorf("ar render not rtl:\n%s", ar)
	}

	// no LogoPath -> no logo img
	if nolog := string(renderRateDeny(settings.BrandingValues{}, "friendly", "auto", "en", "/unmask", "")); strings.Contains(nolog, "branding/logo") {
		t.Errorf("logo img should be absent when LogoPath empty:\n%s", nolog)
	}

	// operator-controlled branding fields are HTML-escaped (no raw injection)
	if esc := string(renderRateDeny(settings.BrandingValues{SiteName: `<script>x</script>`}, "friendly", "auto", "en", "/unmask", "")); strings.Contains(esc, "<script>x</script>") {
		t.Errorf("SiteName not HTML-escaped:\n%s", esc)
	}

	// theme drives the <html data-theme> attribute; an unknown value clamps to auto
	for _, tc := range []struct{ in, want string }{
		{"auto", "auto"}, {"light", "light"}, {"dark", "dark"},
		{"", "auto"}, {"neon", "auto"},
	} {
		got := string(renderRateDeny(settings.BrandingValues{}, "friendly", tc.in, "en", "/unmask", ""))
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
		got := string(renderRateDeny(settings.BrandingValues{}, tc.preset, "auto", "en", "/unmask", ""))
		if !strings.Contains(got, tc.wantBody) {
			t.Errorf("preset %q: want body %q in:\n%s", tc.preset, tc.wantBody, got)
		}
	}
	// an unknown preset falls back to friendly (denyMsgForPreset clamps)
	if fb := string(renderRateDeny(settings.BrandingValues{}, "bogus", "auto", "en", "/unmask", "")); !strings.Contains(fb, "Thanks for your patience.") {
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
			body := string(renderRateDeny(settings.BrandingValues{}, preset, "auto", lang, "/unmask", ""))
			if !strings.Contains(body, "<!-- unmask:rate-deny -->") {
				t.Errorf("preset %q lang %q render missing marker", preset, lang)
			}
		}
	}
}

func TestRenderBanDeny(t *testing.T) {
	// English (neutral) + ban marker + "blocked" wording + branding
	out := string(renderBanDeny(settings.BrandingValues{SiteName: "ACME"}, "neutral", "auto", "en", "/unmask", ""))
	for _, want := range []string{"<!-- unmask:ban-deny -->", `lang="en"`, "Access blocked", "ACME"} {
		if !strings.Contains(out, want) {
			t.Errorf("ban render missing %q in:\n%s", want, out)
		}
	}
	// distinct from the rate-limit deny: not the rate marker, not the "retry" copy
	if strings.Contains(out, "unmask:rate-deny") || strings.Contains(out, "Too many requests") {
		t.Errorf("ban page must not carry rate-limit deny marker/wording:\n%s", out)
	}

	// localized (ja) + rtl (ar) + theme honored
	if ja := string(renderBanDeny(settings.BrandingValues{}, "neutral", "auto", "ja", "/unmask", "")); !strings.Contains(ja, "ブロック") {
		t.Errorf("ja ban not localized:\n%s", ja)
	}
	if ar := string(renderBanDeny(settings.BrandingValues{}, "neutral", "dark", "ar", "/unmask", "")); !strings.Contains(ar, `dir="rtl"`) || !strings.Contains(ar, `data-theme="dark"`) {
		t.Errorf("ar/dark ban render wrong:\n%s", ar)
	}

	// the ban copy preset picks the tone; friendly adds the "mistake" line,
	// minimal is terse, neutral is the plain statement -- an unknown preset
	// falls back to friendly.
	for _, tc := range []struct{ preset, want string }{
		{settings.BrandingPresetFriendly, "If you believe this is a mistake"},
		{settings.BrandingPresetNeutral, "Your access to this site has been blocked."},
		{settings.BrandingPresetMinimal, "Access denied."},
		{"bogus", "If you believe this is a mistake"},
	} {
		got := string(renderBanDeny(settings.BrandingValues{}, tc.preset, "auto", "en", "/unmask", ""))
		if !strings.Contains(got, tc.want) {
			t.Errorf("ban preset %q: want %q in:\n%s", tc.preset, tc.want, got)
		}
	}

	// every ban preset is complete: same 18-language set as the rate-limit deny,
	// non-empty title/body, and each (preset, lang) renders with the ban marker.
	rlNeutral := denyMsgs[settings.BrandingPresetNeutral]
	for preset, table := range banDenyMsgs {
		if len(table) != len(rlNeutral) {
			t.Errorf("ban preset %q has %d languages, want %d", preset, len(table), len(rlNeutral))
		}
		for lang, m := range table {
			if _, ok := rlNeutral[lang]; !ok {
				t.Errorf("ban preset %q language %q absent from the rate-limit deny set", preset, lang)
			}
			if m.Title == "" || m.Body == "" {
				t.Errorf("ban preset %q lang %q has empty title/body: %+v", preset, lang, m)
			}
			if body := string(renderBanDeny(settings.BrandingValues{}, preset, "auto", lang, "/unmask", "")); !strings.Contains(body, "<!-- unmask:ban-deny -->") {
				t.Errorf("ban preset %q lang %q render missing marker", preset, lang)
			}
		}
	}
}

func TestResolvedBanDenyDesign(t *testing.T) {
	// ban deny theme + copy preset resolve from the appearance record,
	// independently of the rate-limit deny.
	b := settings.BrandingValues{DenyBanTheme: "dark", DenyBanCopyPreset: "minimal", CopyPreset: "friendly"}
	if got := b.ResolvedDenyBanTheme(); got != "dark" {
		t.Errorf("ban ResolvedDenyBanTheme = %q, want dark", got)
	}
	if got := b.ResolvedDenyBanCopyPreset(); got != "minimal" {
		t.Errorf("ban ResolvedDenyBanCopyPreset = %q, want minimal (explicit override)", got)
	}
	// unset -> auto theme / friendly preset.  CopyPreset is set to prove the
	// ban deny does NOT inherit the challenge copy preset.
	empty := settings.BrandingValues{CopyPreset: "neutral"}
	if got := empty.ResolvedDenyBanTheme(); got != "auto" {
		t.Errorf("unset ban theme = %q, want auto", got)
	}
	if got := empty.ResolvedDenyBanCopyPreset(); got != "friendly" {
		t.Errorf("unset ban preset = %q, want friendly (must NOT inherit CopyPreset=neutral)", got)
	}
}

func TestResolvedDenyCopyPreset(t *testing.T) {
	// The deny page does NOT inherit the challenge CopyPreset: unset / invalid
	// resolve to the friendly default, an explicit preset wins.
	cases := []struct{ deny, want string }{
		{"", "friendly"},         // unset -> friendly default (no inherit)
		{"friendly", "friendly"}, // explicit
		{"minimal", "minimal"},   // explicit override wins
		{"neutral", "neutral"},   // explicit override wins
		{"bogus", "friendly"},    // invalid -> friendly default
	}
	for _, c := range cases {
		// CopyPreset deliberately != friendly to prove the deny does not inherit it.
		b := settings.BrandingValues{DenyRateCopyPreset: c.deny, CopyPreset: "neutral"}
		if got := b.ResolvedDenyRateCopyPreset(); got != c.want {
			t.Errorf("ResolvedDenyRateCopyPreset(deny=%q) = %q, want %q (CopyPreset=neutral must not leak)", c.deny, got, c.want)
		}
	}
}

// TestDenyPageRef: the support correlation id is shown on the deny page when
// present, omitted when empty, and html-escaped (defense-in-depth -- a ref is
// bare hex, but the page renders other operator-influenced fields too).
func TestDenyPageRef(t *testing.T) {
	with := string(renderRateDeny(settings.BrandingValues{}, "friendly", "auto", "en", "/unmask", "a1b2c-3d4e5"))
	if !strings.Contains(with, "a1b2c-3d4e5") || !strings.Contains(with, `class="ref"`) {
		t.Errorf("ref not shown on the deny page:\n%s", with)
	}
	if without := string(renderRateDeny(settings.BrandingValues{}, "friendly", "auto", "en", "/unmask", "")); strings.Contains(without, `class="ref"`) {
		t.Errorf("an empty ref must omit the ref line:\n%s", without)
	}
	if esc := string(renderRateDeny(settings.BrandingValues{}, "friendly", "auto", "en", "/unmask", "<x>")); strings.Contains(esc, "<x>") {
		t.Errorf("ref not html-escaped:\n%s", esc)
	}
	// ban page carries it too.
	if b := string(renderBanDeny(settings.BrandingValues{}, "neutral", "auto", "en", "/unmask", "9f8e7-6d5c4")); !strings.Contains(b, "9f8e7-6d5c4") {
		t.Errorf("ref not shown on the ban page:\n%s", b)
	}
	// the label is the universal "Ref ID:" token -- not per-language translated.
	if en := string(renderRateDeny(settings.BrandingValues{}, "friendly", "auto", "en", "/unmask", "8e452e74ac")); !strings.Contains(en, "Ref ID: 8e452e74ac") {
		t.Errorf("ref label not 'Ref ID:':\n%s", en)
	}
	if ja := string(renderRateDeny(settings.BrandingValues{}, "friendly", "auto", "ja", "/unmask", "8e452e74ac")); !strings.Contains(ja, "Ref ID: 8e452e74ac") {
		t.Errorf("ja must use the same universal 'Ref ID:' label, not a translation:\n%s", ja)
	}
}

// TestNewRefFormat: a ref is 16 hex chars (64 bits, Cloudflare Ray ID width)
// with NO separator, so a visitor can select the whole id in a single
// double-click to copy into a support message.
func TestNewRefFormat(t *testing.T) {
	for i := 0; i < 64; i++ {
		r := newRef()
		if len(r) != 16 {
			t.Fatalf("ref %q is %d chars, want 16", r, len(r))
		}
		for _, c := range r {
			isHex := (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')
			if !isHex {
				t.Fatalf("ref %q has a non-hex char %q -- a separator breaks one-double-click selection", r, c)
			}
		}
	}
}
