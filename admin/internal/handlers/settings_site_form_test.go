package handlers

import (
	"bytes"
	"encoding/json"
	"fmt"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"strings"
	"testing"

	"github.com/unmask-sh/unmask/admin/internal/settings"
)

// The per-site forms of the challenge and theme tabs, taken through what an
// operator does with them, the way the no-op test of the Default forms
// (TestSettingsTabsNoOpSave) takes those: the page is rendered, its form is
// read back as a browser would submit it, and that is posted.
//
// A site's record says only what the site set; the rest follows Default.  The
// form therefore has to show what the site gets -- its own values over
// Default's -- or saving it as shown states something else: the form showed
// the record itself, where a field the site had not set read as the built-in
// value, and one save without a change fixed the site's cookie lifetime at
// seven days where Default said one, and its theme at "auto" where Default
// said dark.

const formSite = "shop.example.com"

type siteEnv struct {
	t *testing.T
	h *Handler
}

// customisedDefault: a Default record that says something other than the
// built-in value in every field the two forms carry, so that "what the site
// inherits" and "what unset means" are never the same thing.
func customisedDefault(s *settings.Settings) {
	minDisplay, fade := 0, 0
	c := &s.Challenge.Default
	c.PowCookieValidSeconds = 86400
	c.CaptchaCookieValidSeconds = 172800
	c.PowDifficulty = 20
	c.DisplayStyle = settings.ChallengeDisplayInvisible
	c.MinDisplayMS = &minDisplay
	c.InvisibleRevealMS = 3000
	c.RevealFadeMS = &fade
	c.DebugRateLimitPer5Min = 50
	c.PublicTestPages = settings.BoolPtr(true)
	c.PublicTestPagesPassword = "s3cret"
	c.PublicTestPagesSitePicker = settings.BoolPtr(false)
	b := &s.Branding.Default
	b.SiteName = "Example"
	b.FooterText = "Operated by Example"
	b.LogoHeight = 48
	b.CopyPreset = settings.BrandingPresetNeutral
	b.Theme = "dark"
	b.CustomColors = map[string]settings.ChallengeThemeColors{"dark": {Bg: "#112233", Text: "#ffeedd"}}
	b.ShowCredit = settings.BoolPtr(true)
	b.DenyRateTheme = settings.DenyThemeDark
	b.DenyRateCopyPreset = settings.BrandingPresetMinimal
	b.DenyRateColors = map[string]settings.ChallengeThemeColors{"light": {Bg: "#fafafa", Text: "#111111"}}
	b.DenyBanTheme = settings.DenyThemeLight
	b.DenyBanCopyPreset = settings.BrandingPresetNeutral
	b.DenyBanColors = map[string]settings.ChallengeThemeColors{"dark": {Bg: "#000000", Text: "#eeeeee"}}
}

var siteDefaultStates = []struct {
	name      string
	customise func(*settings.Settings)
}{
	{"Default as installed", nil},
	{"Default customised", customisedDefault},
}

func newSiteEnv(t *testing.T, customise func(*settings.Settings)) *siteEnv {
	t.Helper()
	h := newTestHandler(t)
	dir := t.TempDir()
	// A real fresh install's settings, as TestSettingsTabsNoOpSave seeds them.
	empty := filepath.Join(dir, "empty-seed.yml")
	if err := os.WriteFile(empty, []byte("{}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	s, err := settings.Load(empty)
	if err != nil {
		t.Fatal(err)
	}
	s.Server.Bind = "127.0.0.1"
	s.Server.Port = 9477
	s.Server.BasePath = "/unmask"
	h.Version = "9.9.9"
	s.Nginx.SeenVersion = "v9.9.9"
	s.Nginx.OutputDir = filepath.Join(dir, "nginx")
	s.CommunityBans.MapDir = dir
	if customise != nil {
		customise(&s)
	}
	h.ConfigPath = filepath.Join(dir, "config.yml")
	e := &siteEnv{t: t, h: h}
	e.store(s)
	return e
}

// store writes s and publishes it as a fresh Load reads it.
func (e *siteEnv) store(s settings.Settings) {
	e.t.Helper()
	if err := settings.Save(s, e.h.ConfigPath); err != nil {
		e.t.Fatal(err)
	}
	e.h.SetSettings(e.load())
}

func (e *siteEnv) load() settings.Settings {
	e.t.Helper()
	s, err := settings.Load(e.h.ConfigPath)
	if err != nil {
		e.t.Fatal(err)
	}
	return s
}

func (e *siteEnv) yaml() string {
	e.t.Helper()
	y, err := settings.MarshalYAML(e.load())
	if err != nil {
		e.t.Fatal(err)
	}
	return y
}

// setDefault changes the Default records behind the forms' back, as a save
// of the Default scope does.
func (e *siteEnv) setDefault(change func(*settings.Settings)) {
	e.t.Helper()
	s := e.load()
	change(&s)
	e.store(s)
}

// page renders tab at the site's scope.
func (e *siteEnv) page(tab string) string {
	e.t.Helper()
	req := httptest.NewRequest(http.MethodGet, "/unmask/admin/settings/"+tab+"/?scope="+url.QueryEscape(formSite), nil)
	req.SetPathValue("tab", tab)
	rr := httptest.NewRecorder()
	e.h.AdminSettingsIndex(rr, req)
	if rr.Code != http.StatusOK {
		e.t.Fatalf("GET %s at scope %s: %d", tab, formSite, rr.Code)
	}
	return rr.Body.String()
}

// form: the site's form on tab.
func (e *siteEnv) form(tab string) htmlForm {
	e.t.Helper()
	forms := parseFormsWhere(e.page(tab), func(action string) bool { return strings.Contains(action, "/site/save") })
	if len(forms) != 1 {
		e.t.Fatalf("tab %s at scope %s: %d per-site forms, want 1", tab, formSite, len(forms))
	}
	return forms[0]
}

func siteToggleOn(f htmlForm) bool {
	for _, fld := range f.fields {
		if fld.name == "use_site_override" {
			return fld.checked
		}
	}
	return false
}

// siteFormValues: what the browser posts for the site's form.  While the
// override toggle is off the page's script disables every other control, the
// hidden ones included, so such a form posts nothing (the site travels in the
// action's query); tick says the operator turns the toggle on first.
func siteFormValues(f htmlForm, tick bool) url.Values {
	if !siteToggleOn(f) && !tick {
		return url.Values{}
	}
	v := f.values()
	v.Set("use_site_override", "1")
	return v
}

// fieldValue: the value the form shows in its (first) field of that name.
func fieldValue(f htmlForm, name string) string {
	for _, fld := range f.fields {
		if fld.name == name {
			return fld.value
		}
	}
	return "(no field " + name + ")"
}

// post submits vals to the form's own action and wants the save to be taken.
func (e *siteEnv) post(tab string, f htmlForm, vals url.Values) {
	e.t.Helper()
	var req *http.Request
	if tab == "theme" {
		var buf bytes.Buffer
		mw := multipart.NewWriter(&buf)
		for k, vs := range vals {
			for _, v := range vs {
				if err := mw.WriteField(k, v); err != nil {
					e.t.Fatal(err)
				}
			}
		}
		_ = mw.Close()
		req = httptest.NewRequest(http.MethodPost, f.action, &buf)
		req.Header.Set("Content-Type", mw.FormDataContentType())
	} else {
		req = httptest.NewRequest(http.MethodPost, f.action, strings.NewReader(vals.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	rr := httptest.NewRecorder()
	if tab == "theme" {
		e.h.AdminBrandingSiteSave(rr, req)
	} else {
		e.h.AdminChallengeSiteSave(rr, req)
	}
	if rr.Code != http.StatusFound {
		e.t.Fatalf("save of the %s form: %d %s", tab, rr.Code, rr.Body.String())
	}
	if loc := rr.Header().Get("Location"); !strings.Contains(loc, "saved=1") {
		e.t.Fatalf("save of the %s form was refused: %s", tab, loc)
	}
}

// untouched saves the form as the page shows it and wants nothing to change.
func (e *siteEnv) untouched(tab, when string) {
	e.t.Helper()
	before := e.yaml()
	f := e.form(tab)
	e.post(tab, f, siteFormValues(f, false))
	if after := e.yaml(); after != before {
		e.t.Errorf("%s: saving the %s form as it is shown changed the config:\n%s", when, tab, yamlDiff(before, after))
	}
}

// fieldOverrides: the map the page hands its script to mark the fields the
// site does not set as inherited.
func (e *siteEnv) fieldOverrides(tab string) map[string]bool {
	e.t.Helper()
	m := regexp.MustCompile(`(?s)class="field-overrides">(.*?)</script>`).FindStringSubmatch(e.page(tab))
	if m == nil {
		e.t.Fatalf("tab %s: no field-overrides block", tab)
	}
	out := map[string]bool{}
	if err := json.Unmarshal([]byte(m[1]), &out); err != nil {
		e.t.Fatalf("tab %s: field-overrides: %v (%s)", tab, err, m[1])
	}
	return out
}

// wantOwn: exactly these fields are marked as the site's own.
func wantOwn(t *testing.T, got map[string]bool, own ...string) {
	t.Helper()
	want := map[string]bool{}
	for _, n := range own {
		want[n] = true
		if _, ok := got[n]; !ok {
			t.Errorf("the page's override map has no entry for the field %q", n)
		}
	}
	for n, on := range got {
		if on != want[n] {
			t.Errorf("field %q: marked as the site's own = %v, want %v", n, on, want[n])
		}
	}
}

// challengeMeaning / brandingMeaning: what a record comes to, field by field,
// with unset read as what unset means.
func challengeMeaning(v settings.ChallengeValues) string {
	return fmt.Sprintf("pow_cookie=%d captcha_cookie=%d difficulty=%d style=%s min_display=%d reveal=%d fade=%d debug_rate=%d test_pages=%v test_password=%q site_picker=%v",
		v.PowCookieValidSecondsResolved(), v.CaptchaCookieValidSecondsResolved(), v.ResolvedPowDifficulty(),
		v.ResolvedDisplayStyle(), v.ResolvedMinDisplayMS(), v.ResolvedInvisibleRevealMS(), v.ResolvedRevealFadeMS(),
		v.DebugRateLimitPer5Min, v.IsPublicTestPages(), v.PublicTestPagesPassword, v.IsPublicTestPagesSitePicker())
}

func colorsOf(v settings.BrandingValues) string {
	var sb strings.Builder
	for _, th := range []string{"light", "dark", "terminal", "paper", "cat"} {
		if bg, text := v.CustomColorsFor(th); bg != "" {
			fmt.Fprintf(&sb, "%s=%s/%s ", th, bg, text)
		}
	}
	for _, th := range []string{"light", "dark"} {
		if bg, text := v.DenyRateColorsFor(th); bg != "" {
			fmt.Fprintf(&sb, "deny-%s=%s/%s ", th, bg, text)
		}
		if bg, text := v.DenyBanColorsFor(th); bg != "" {
			fmt.Fprintf(&sb, "ban-%s=%s/%s ", th, bg, text)
		}
	}
	return "[" + strings.TrimSpace(sb.String()) + "]"
}

func themeOf(v settings.BrandingValues) string {
	if challengeThemes[v.Theme] {
		return v.Theme
	}
	return "auto"
}

func brandingMeaning(v settings.BrandingValues) string {
	return fmt.Sprintf("name=%q footer=%q logo_height=%d preset=%s theme=%s credit=%v deny=%s/%s ban=%s/%s colors=%s",
		v.SiteName, v.FooterText, v.LogoHeight, v.ResolvedCopyPreset(), themeOf(v), v.IsShowCredit(),
		v.ResolvedDenyRateTheme(), v.ResolvedDenyRateCopyPreset(), v.ResolvedDenyBanTheme(), v.ResolvedDenyBanCopyPreset(),
		colorsOf(v))
}

func TestSiteChallengeFormSavesOnlyWhatTheSiteSets(t *testing.T) {
	for _, st := range siteDefaultStates {
		t.Run(st.name, func(t *testing.T) {
			e := newSiteEnv(t, st.customise)
			site := func() settings.ChallengeValues { return e.load().Challenge.Resolve(formSite) }
			def := func() settings.ChallengeValues { return e.load().Challenge.Default }

			// The override turned on, nothing else touched: the site has a
			// record, and the record says nothing.
			f := e.form("challenge")
			if siteToggleOn(f) {
				t.Fatal("a site with no record has its override toggle on")
			}
			e.post("challenge", f, siteFormValues(f, true))
			rec, ok := e.load().Challenge.Sites[formSite]
			if !ok || rec.Disabled {
				t.Fatalf("no record in force after the save (found=%v disabled=%v)", ok, rec.Disabled)
			}
			if !reflect.DeepEqual(rec, settings.ChallengeValues{}) {
				t.Errorf("the record of a site that set nothing says something: %+v", rec)
			}
			if got, want := challengeMeaning(site()), challengeMeaning(def()); got != want {
				t.Errorf("the site that set nothing does not get Default:\n  site    %s\n  Default %s", got, want)
			}
			wantOwn(t, e.fieldOverrides("challenge"))
			e.untouched("challenge", "a record that sets nothing")

			// The operator sets four fields; the display style is set to the
			// one Default does not have.
			style := settings.ChallengeDisplayInvisible
			if def().ResolvedDisplayStyle() == style {
				style = settings.ChallengeDisplayVisible
			}
			f = e.form("challenge")
			vals := siteFormValues(f, false)
			vals.Set("pow_difficulty", "12")
			vals.Set("pow_cookie_valid_seconds", "3600")
			vals.Set("min_display_ms", "250")
			vals.Set("challenge_display_style", style)
			e.post("challenge", f, vals)
			got, d := site(), def()
			if got.ResolvedPowDifficulty() != 12 || got.PowCookieValidSecondsResolved() != 3600 || got.ResolvedMinDisplayMS() != 250 || got.ResolvedDisplayStyle() != style {
				t.Errorf("the site does not get what was set for it (difficulty 12, PoW cookie 3600, min display 250, style %s): %s", style, challengeMeaning(got))
			}
			if got.CaptchaCookieValidSecondsResolved() != d.CaptchaCookieValidSecondsResolved() ||
				got.ResolvedInvisibleRevealMS() != d.ResolvedInvisibleRevealMS() || got.ResolvedRevealFadeMS() != d.ResolvedRevealFadeMS() ||
				got.DebugRateLimitPer5Min != d.DebugRateLimitPer5Min || got.IsPublicTestPages() != d.IsPublicTestPages() ||
				got.PublicTestPagesPassword != d.PublicTestPagesPassword || got.IsPublicTestPagesSitePicker() != d.IsPublicTestPagesSitePicker() {
				t.Errorf("a field the site did not set left Default:\n  site    %s\n  Default %s", challengeMeaning(got), challengeMeaning(d))
			}
			wantOwn(t, e.fieldOverrides("challenge"), "pow_difficulty", "pow_cookie_valid_seconds", "min_display_ms", "challenge_display_style")
			e.untouched("challenge", "a record that sets four fields")

			// Default moves: the site follows in what it did not set, the form
			// shows the new value, and saving the form does not hold it there.
			e.setDefault(func(s *settings.Settings) {
				s.Challenge.Default.CaptchaCookieValidSeconds = 43200
				s.Challenge.Default.InvisibleRevealMS = 2000
				s.Challenge.Default.PowDifficulty = 22
			})
			if got := site(); got.CaptchaCookieValidSecondsResolved() != 43200 || got.ResolvedInvisibleRevealMS() != 2000 || got.ResolvedPowDifficulty() != 12 {
				t.Errorf("after Default moved (CAPTCHA cookie 43200, reveal 2000, difficulty 22) the site, which set its difficulty to 12, gets: %s", challengeMeaning(got))
			}
			if shown := fieldValue(e.form("challenge"), "captcha_cookie_valid_seconds"); shown != "43200" {
				t.Errorf("the site's form shows CAPTCHA cookie %s, the site gets 43200", shown)
			}
			e.untouched("challenge", "after Default moved")
			e.setDefault(func(s *settings.Settings) { s.Challenge.Default.CaptchaCookieValidSeconds = 21600 })
			if got := site().CaptchaCookieValidSecondsResolved(); got != 21600 {
				t.Errorf("a save of the form as shown held the site's CAPTCHA cookie at %d; Default says 21600 and the site never set it", got)
			}

			// The override off: Default, with the record kept; on again: what
			// the site had.
			had := challengeMeaning(site())
			f = e.form("challenge")
			e.post("challenge", f, url.Values{})
			if rec := e.load().Challenge.Sites[formSite]; !rec.Disabled {
				t.Error("the override turned off left the record in force")
			}
			if got, want := challengeMeaning(site()), challengeMeaning(def()); got != want {
				t.Errorf("with the override off the site does not get Default:\n  site    %s\n  Default %s", got, want)
			}
			e.untouched("challenge", "with the override off")
			f = e.form("challenge")
			if siteToggleOn(f) {
				t.Error("the toggle of a record that is off is shown on")
			}
			e.post("challenge", f, siteFormValues(f, true))
			if got := challengeMeaning(site()); got != had {
				t.Errorf("the override turned off and on again changed what the site gets:\n  before %s\n  after  %s", had, got)
			}
			e.untouched("challenge", "the override on again")
		})
	}
}

func TestSiteThemeFormSavesOnlyWhatTheSiteSets(t *testing.T) {
	for _, st := range siteDefaultStates {
		t.Run(st.name, func(t *testing.T) {
			e := newSiteEnv(t, st.customise)
			site := func() settings.BrandingValues { return e.load().Branding.Resolve(formSite) }
			def := func() settings.BrandingValues { return e.load().Branding.Default }

			f := e.form("theme")
			if siteToggleOn(f) {
				t.Fatal("a site with no record has its override toggle on")
			}
			e.post("theme", f, siteFormValues(f, true))
			rec, ok := e.load().Branding.Sites[formSite]
			if !ok || rec.Disabled {
				t.Fatalf("no record in force after the save (found=%v disabled=%v)", ok, rec.Disabled)
			}
			if !reflect.DeepEqual(rec, settings.BrandingValues{}) {
				t.Errorf("the record of a site that set nothing says something: %+v", rec)
			}
			if got, want := brandingMeaning(site()), brandingMeaning(def()); got != want {
				t.Errorf("the site that set nothing does not get Default:\n  site    %s\n  Default %s", got, want)
			}
			wantOwn(t, e.fieldOverrides("theme"))
			e.untouched("theme", "a record that sets nothing")

			// The operator names the site, picks the paper theme, recolours
			// it, picks a deny theme, and turns the credit line the other way.
			credit := !def().IsShowCredit()
			f = e.form("theme")
			vals := siteFormValues(f, false)
			vals.Set("branding_site_name", "Shop")
			vals.Set("theme", "paper")
			vals.Set("custom_on_paper", tickedValue(t, f, "custom_on_paper"))
			vals.Set("custom_bg_paper", "#101010")
			vals.Set("custom_text_paper", "#fafafa")
			vals.Set("deny_theme", settings.DenyThemeLight)
			if credit {
				vals.Set("show_credit", tickedValue(t, f, "show_credit"))
			} else {
				vals.Del("show_credit")
			}
			e.post("theme", f, vals)
			got, d := site(), def()
			bg, text := got.CustomColorsFor("paper")
			if got.SiteName != "Shop" || themeOf(got) != "paper" || bg != "#101010" || text != "#fafafa" || got.ResolvedDenyRateTheme() != settings.DenyThemeLight || got.IsShowCredit() != credit {
				t.Errorf("the site does not get what was set for it (name Shop, theme paper recoloured #101010/#fafafa, deny theme light, credit %v): %s", credit, brandingMeaning(got))
			}
			dbg, dtext := d.CustomColorsFor("dark")
			if sbg, stext := got.CustomColorsFor("dark"); sbg != dbg || stext != dtext {
				t.Errorf("the dark theme's colours, which the form showed and the operator left: site %s/%s, Default %s/%s", sbg, stext, dbg, dtext)
			}
			if got.FooterText != d.FooterText || got.LogoHeight != d.LogoHeight || got.ResolvedCopyPreset() != d.ResolvedCopyPreset() ||
				got.ResolvedDenyRateCopyPreset() != d.ResolvedDenyRateCopyPreset() || got.ResolvedDenyBanTheme() != d.ResolvedDenyBanTheme() ||
				got.ResolvedDenyBanCopyPreset() != d.ResolvedDenyBanCopyPreset() {
				t.Errorf("a field the site did not set left Default:\n  site    %s\n  Default %s", brandingMeaning(got), brandingMeaning(d))
			}
			// The previews are drawn with what the form shows, the credit
			// line included.
			wantCredit := "_preview_show_credit=0"
			if credit {
				wantCredit = "_preview_show_credit=1"
			}
			if body := e.page("theme"); !strings.Contains(body, wantCredit) {
				t.Errorf("the site's credit line is %v and the page's previews do not carry %s", credit, wantCredit)
			}
			over := e.fieldOverrides("theme")
			for _, n := range []string{"branding_site_name", "theme", "show_credit", "deny_theme"} {
				if !over[n] {
					t.Errorf("field %q, which the site sets, is not marked as its own", n)
				}
			}
			for _, n := range []string{"branding_footer_text", "branding_logo_height", "branding_copy_preset", "deny_copy_preset", "ban_deny_theme", "ban_copy_preset", "branding_logo_file"} {
				if on, ok := over[n]; !ok || on {
					t.Errorf("field %q, which the site does not set: in the override map = %v, marked as its own = %v", n, ok, on)
				}
			}
			e.untouched("theme", "a record that sets five fields")

			// Default moves.
			e.setDefault(func(s *settings.Settings) {
				s.Branding.Default.FooterText = "A new footer"
				s.Branding.Default.Theme = "cat"
				s.Branding.Default.CopyPreset = settings.BrandingPresetMinimal
			})
			if got := site(); got.FooterText != "A new footer" || got.ResolvedCopyPreset() != settings.BrandingPresetMinimal || themeOf(got) != "paper" {
				t.Errorf("after Default moved (footer, preset minimal, theme cat) the site, which set its theme to paper, gets: %s", brandingMeaning(got))
			}
			if shown := fieldValue(e.form("theme"), "branding_footer_text"); shown != "A new footer" {
				t.Errorf("the site's form shows the footer %q, the site gets %q", shown, "A new footer")
			}
			e.untouched("theme", "after Default moved")
			e.setDefault(func(s *settings.Settings) { s.Branding.Default.CopyPreset = settings.BrandingPresetNeutral })
			if got := site().ResolvedCopyPreset(); got != settings.BrandingPresetNeutral {
				t.Errorf("a save of the form as shown held the site's wording at %s; Default says neutral and the site never set it", got)
			}

			// The built-in value is a value a site can choose where Default
			// says another: the theme that follows the visitor's system, the
			// friendly wording, a deny page that follows the system, no
			// colours of its own.
			f = e.form("theme")
			vals = siteFormValues(f, false)
			vals.Set("theme", "auto")
			vals.Set("branding_copy_preset", settings.BrandingPresetFriendly)
			vals.Set("deny_theme", settings.DenyThemeAuto)
			vals.Set("ban_deny_theme", settings.DenyThemeAuto)
			for _, th := range []string{"light", "dark", "terminal", "paper", "cat"} {
				vals.Del("custom_on_" + th)
			}
			e.post("theme", f, vals)
			got = site()
			if themeOf(got) != "auto" || got.ResolvedCopyPreset() != settings.BrandingPresetFriendly ||
				got.ResolvedDenyRateTheme() != settings.DenyThemeAuto || got.ResolvedDenyBanTheme() != settings.DenyThemeAuto {
				t.Errorf("the site was set to theme auto, friendly wording, deny and ban theme auto, and gets: %s", brandingMeaning(got))
			}
			for _, th := range []string{"light", "dark", "terminal", "paper", "cat"} {
				if bg, _ := got.CustomColorsFor(th); bg != "" {
					t.Errorf("every theme's own colours were turned off for the site; the %s theme still has %s", th, bg)
				}
			}
			e.untouched("theme", "a site set to the built-in values")

			// The override off and on again.
			had := brandingMeaning(site())
			f = e.form("theme")
			e.post("theme", f, url.Values{})
			if rec := e.load().Branding.Sites[formSite]; !rec.Disabled {
				t.Error("the override turned off left the record in force")
			}
			if got, want := brandingMeaning(site()), brandingMeaning(def()); got != want {
				t.Errorf("with the override off the site does not get Default:\n  site    %s\n  Default %s", got, want)
			}
			e.untouched("theme", "with the override off")
			f = e.form("theme")
			e.post("theme", f, siteFormValues(f, true))
			if got := brandingMeaning(site()); got != had {
				t.Errorf("the override turned off and on again changed what the site gets:\n  before %s\n  after  %s", had, got)
			}
			e.untouched("theme", "the override on again")
		})
	}
}

// The challenge form too has built-in values a site can choose where Default
// says another: the visible page under an invisible Default, the public test
// pages off under a Default that has them on, the seven-day cookie under a
// one-day Default, and the site picker -- on unless turned off -- on under a
// Default that turned it off.
func TestSiteChallengeFormCanChooseTheBuiltinValue(t *testing.T) {
	e := newSiteEnv(t, customisedDefault)
	f := e.form("challenge")
	vals := siteFormValues(f, true)
	vals.Set("challenge_display_style", settings.ChallengeDisplayVisible)
	vals.Del("public_test_pages")
	vals.Set("public_test_pages_site_picker", tickedValue(t, f, "public_test_pages_site_picker"))
	vals.Set("pow_cookie_valid_seconds", "604800")
	e.post("challenge", f, vals)
	if e.load().Challenge.Default.IsPublicTestPagesSitePicker() {
		t.Fatal("Default's site picker, turned off, is on in the config that was written")
	}
	got := e.load().Challenge.Resolve(formSite)
	if got.ResolvedDisplayStyle() != settings.ChallengeDisplayVisible || got.IsPublicTestPages() || !got.IsPublicTestPagesSitePicker() || got.PowCookieValidSecondsResolved() != 604800 {
		t.Errorf("the site was set to the visible page, no public test pages, the site picker on and a seven-day PoW cookie, and gets: %s", challengeMeaning(got))
	}
	wantOwn(t, e.fieldOverrides("challenge"), "challenge_display_style", "public_test_pages", "public_test_pages_site_picker", "pow_cookie_valid_seconds")
	e.untouched("challenge", "a site set to the built-in values")
}
