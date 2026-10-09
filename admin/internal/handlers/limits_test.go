package handlers

import (
	"io/fs"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"testing"

	"github.com/unmask-sh/unmask/admin/assets"
	"github.com/unmask-sh/unmask/admin/internal/i18n"
	"github.com/unmask-sh/unmask/admin/internal/settings"
	"github.com/unmask-sh/unmask/admin/internal/user"
)

// A field with a character limit says so (partial_maxchars.html: the field
// turns red as the value runs past the limit, the words appear under it, the
// save waits), and a value that still arrives past it is refused with the same
// limit rather than cut.  These hold the pieces together: the two branding
// fields, the hub name's rule, and the policy that no field stops the typing
// with a bare maxlength.
func TestBrandingTextLimits(t *testing.T) {
	for _, tc := range []struct {
		field string
		max   int
	}{
		{"branding_site_name", brandingSiteNameMax},
		{"branding_footer_text", brandingFooterMax},
	} {
		var cur settings.BrandingValues
		if err := applyBrandingForm(&cur, "", brandingFieldsReq(t, map[string]string{tc.field: strings.Repeat("あ", tc.max)})); err != nil {
			t.Errorf("%s at the limit rejected: %v", tc.field, err)
		}
		err := applyBrandingForm(&cur, "", brandingFieldsReq(t, map[string]string{tc.field: strings.Repeat("あ", tc.max+1)}))
		if err == nil || !strings.Contains(err.Error(), strconv.Itoa(tc.max)) {
			t.Errorf("%s one past the limit: err=%v, want a refusal naming %d", tc.field, err, tc.max)
		}
	}
}

func TestHNOverrideValidated(t *testing.T) {
	post := func(v string) (settings.CommunityBans, error) {
		t.Helper()
		form := url.Values{"hn_override": {v}}
		r := httptest.NewRequest("POST", "/x?section=community-bans", strings.NewReader(form.Encode()))
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		if err := r.ParseForm(); err != nil {
			t.Fatal(err)
		}
		var c settings.CommunityBans
		err := applyCommunityBansForm(&c, r, i18n.LangEN)
		return c, err
	}
	for _, v := range []string{"", "  Node-01 ", "a_b", strings.Repeat("x", 32)} {
		c, err := post(v)
		if err != nil {
			t.Errorf("%q refused: %v", v, err)
		}
		if want := strings.ToLower(strings.TrimSpace(v)); c.HNOverride != want {
			t.Errorf("%q saved as %q, want %q", v, c.HNOverride, want)
		}
	}
	want := i18n.T(i18n.LangEN, "err.hn_override_format")
	for _, v := range []string{"ab", "bad!name", "-leading", "trailing_", strings.Repeat("x", 33), "名前"} {
		c, err := post(v)
		if err == nil || err.Error() != want {
			t.Errorf("%q: err=%v, want the rule; saved %q", v, err, c.HNOverride)
		}
	}
}

// No field may stop the typing with a bare maxlength: a limit is said on the
// field (data-maxchars) so the operator sees it.  The one exception is the
// colour picker's hex box, whose 7 is the format, not a budget.
func TestNoSilentMaxlength(t *testing.T) {
	tag := regexp.MustCompile(`<(?:input|textarea)\b[^>]*\bmaxlength=[^>]*>`)
	err := fs.WalkDir(assets.Templates, "templates", func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() || !strings.HasSuffix(path, ".html") {
			return err
		}
		b, err := fs.ReadFile(assets.Templates, path)
		if err != nil {
			return err
		}
		for _, m := range tag.FindAllString(string(b), -1) {
			if strings.Contains(m, `id="uc-hex"`) {
				continue
			}
			t.Errorf("%s: a field stops the typing without a word: %s", path, m)
		}
		// Script-built fields (community_bans.html) are strings, not tags.
		if strings.Contains(string(b), `maxlength="`) && !strings.Contains(string(b), `id="uc-hex"`) {
			t.Errorf("%s: maxlength in a script-built field", path)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

// The BAN dialog's two limits are literals in the partial (it is rendered by
// several pages); they have to be the numbers the hunt handler refuses at.
func TestBanDialogLimitsMatchTheHandler(t *testing.T) {
	b, err := fs.ReadFile(assets.Templates, "templates/partial_ban_dialog.html")
	if err != nil {
		t.Fatal(err)
	}
	s := string(b)
	for _, w := range []string{
		`id="ban-dialog-reason" placeholder="{{ t .Lang "hunt.ban.reason_placeholder" }}" data-maxchars="` + strconv.Itoa(banReasonMax) + `"`,
		`id="ban-dialog-comment" rows="2" placeholder="{{ t .Lang "hunt.ban.comment_placeholder" }}" data-maxchars="` + strconv.Itoa(shareCommentMax) + `"`,
	} {
		if !strings.Contains(s, w) {
			t.Errorf("the BAN dialog does not carry %s", w)
		}
	}
}

// Every signed-in page carries the check (header_tools), and the fields with
// a limit carry their number and their words.
func TestLimitsOnThePage(t *testing.T) {
	h := vacuumHandler(t, 10)
	body := renderTab(t, h, "honeypot", user.RoleSuperadmin, "en")
	if !strings.Contains(body, "window.unmaskMaxChars") {
		t.Error("the settings page does not carry the character-limit check")
	}
	// The branding tab: site name and footer text.
	body = renderTab(t, h, "theme", user.RoleSuperadmin, "en")
	for _, w := range []string{
		`name="branding_site_name" data-maxchars="` + strconv.Itoa(brandingSiteNameMax) + `" data-maxchars-msg="` + i18n.Tf(i18n.LangEN, "err.value_long", brandingSiteNameMax) + `"`,
		`name="branding_footer_text" data-maxchars="` + strconv.Itoa(brandingFooterMax) + `" data-maxchars-msg="` + i18n.Tf(i18n.LangEN, "err.value_long", brandingFooterMax) + `"`,
	} {
		if !strings.Contains(body, w) {
			t.Errorf("the branding tab lacks %s", w)
		}
	}
	// The hub name: the pattern stays, our words for its bubble.
	body = renderTab(t, h, "community-bans", user.RoleSuperadmin, "en")
	if !strings.Contains(body, `name="hn_override"`) || !strings.Contains(body, `data-invalid-msg="`+i18n.T(i18n.LangEN, "err.hn_override_format")+`"`) {
		t.Error("the hub name field does not carry the rule for its bubble")
	}
}
