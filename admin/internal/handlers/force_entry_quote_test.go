package handlers

import (
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/unmask-sh/unmask/admin/internal/i18n"
	"github.com/unmask-sh/unmask/admin/internal/settings"
)

// The entry behind a challenge is written into the page's script, and the
// two values an operator types freely -- a literal UA filter pattern and the
// organisation text of an ASN rule -- used to be saved with a quote or a
// backslash in them.  The page encodes what it writes now; the save refuses
// those characters too, by name on the row, as the regex patterns always
// were refused.
func TestOperatorEntriesWithAQuoteAreRefusedOnSave(t *testing.T) {
	want := func(v string) string { return i18n.Tf(i18n.LangEN, "err.rule_pattern_char", v) }

	for _, p := range []string{`contains:Trap "x"`, `exact:a\b`, `contains:a` + "\n" + `b`} {
		_, _, _, _, _, _, err := pairExtras("black_extra", i18n.LangEN, []string{p}, []string{""}, []string{"1"}, []string{"0"}, []string{"0"}, []string{"captcha_only"})
		fe, is := err.(*listFieldError)
		if !is || fe.Value != p || fe.Msg != want(p) {
			t.Errorf("literal pattern %q: not refused on its row, got %v", p, err)
		}
	}
	for _, p := range []string{`contains:Trap x`, `exact:plain`, `X11; Linux x86_64`} {
		if _, _, _, _, _, _, err := pairExtras("black_extra", i18n.LangEN, []string{p}, []string{""}, []string{"1"}, []string{"0"}, []string{"0"}, []string{"captcha_only"}); err != nil {
			t.Errorf("pattern %q: refused, %v", p, err)
		}
	}

	asn := func(value string) error {
		t.Helper()
		form := url.Values{}
		form["asn_number"] = []string{value}
		form["asn_label"] = []string{""}
		form["asn_action"] = []string{"captcha_only"}
		r := httptest.NewRequest("POST", "/x?section=asn", strings.NewReader(form.Encode()))
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		if err := r.ParseForm(); err != nil {
			t.Fatal(err)
		}
		var c settings.AsnConfig
		return applyAsnForm(&c, r, i18n.LangEN)
	}
	for _, v := range []string{`Farm "x"`, `Farm\x`} {
		fe, is := asn(v).(*listFieldError)
		if !is || fe.Field != "asn_number" || fe.Value != v || fe.Msg != want(v) {
			t.Errorf("organisation %q: not refused on its row", v)
		}
	}
	if err := asn("Plain Farm Ltd"); err != nil {
		t.Errorf("organisation text without those characters: refused, %v", err)
	}
}
