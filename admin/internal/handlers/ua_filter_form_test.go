package handlers

import (
	"net/http/httptest"
	"net/url"
	"reflect"
	"strings"
	"testing"

	"github.com/unmask-sh/unmask/admin/internal/i18n"
	"github.com/unmask-sh/unmask/admin/internal/settings"
)

// TestApplyUAFilterFormPatternModes pins the intake of the crawlers set one
// by one: each upstream_pattern_mode is "<mode>:<pattern>" split at the first
// colon (a pattern may hold more), an unknown mode or a blank pattern is
// dropped, a pattern named in upstream_pattern_drop is removed, and the map is
// the whole state -- a saved one that the form does not repeat is gone.
func TestApplyUAFilterFormPatternModes(t *testing.T) {
	form := url.Values{}
	form.Add("upstream_pattern_mode", `black:MJ12bot`)
	form.Add("upstream_pattern_mode", `white:^curl`)
	form.Add("upstream_pattern_mode", `none:(?:foo):bar`) // colons inside the pattern
	form.Add("upstream_pattern_mode", `maybe:dotbot`)     // unknown mode -> dropped
	form.Add("upstream_pattern_mode", `none:  `)          // blank pattern -> dropped
	form.Add("upstream_pattern_mode", `nocolon`)          // malformed -> dropped
	form.Add("upstream_pattern_mode", `none:old-name-bot`)
	form.Add("upstream_pattern_drop", `old-name-bot`)

	r := httptest.NewRequest("POST", "/unmask/admin/settings/", strings.NewReader(form.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if err := r.ParseForm(); err != nil {
		t.Fatal(err)
	}

	var n settings.Nginx
	n.SearchBots.UpstreamPatternMode = map[string]string{`GPTBot`: "black"} // saved before, not posted
	if err := applyUAFilterForm(&n, r, i18n.LangEN); err != nil {
		t.Fatalf("applyUAFilterForm: %v", err)
	}
	want := map[string]string{`MJ12bot`: "black", `^curl`: "white", `(?:foo):bar`: "none"}
	if got := n.SearchBots.UpstreamPatternMode; !reflect.DeepEqual(got, want) {
		t.Errorf("UpstreamPatternMode = %q, want %q", got, want)
	}

	// Nothing posted: every crawler follows its group, and the config holds
	// no empty map.
	empty := httptest.NewRequest("POST", "/unmask/admin/settings/", strings.NewReader(""))
	empty.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if err := empty.ParseForm(); err != nil {
		t.Fatal(err)
	}
	if err := applyUAFilterForm(&n, empty, i18n.LangEN); err != nil {
		t.Fatalf("applyUAFilterForm: %v", err)
	}
	if n.SearchBots.UpstreamPatternMode != nil {
		t.Errorf("UpstreamPatternMode = %q, want nil", n.SearchBots.UpstreamPatternMode)
	}
}
