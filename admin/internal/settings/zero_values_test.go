package settings

import (
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"
)

// zeroMeansDefault lists the settings whose zero value (0, "", an empty list)
// cannot be saved: Save leaves a zero out of the file (omitempty), and Load
// starts from defaults(), so the value comes back as the default.  That is
// right for these, and only for these -- for each, zero is not something an
// operator can choose, and the entry says why.
//
// A setting that is NOT in this table and whose default is not zero must be
// written out when it is zero (no omitempty in its yaml tag).  The settings
// page publishes what it saved as the live settings while the file says the
// default: header_integrity was such a one, and an unticked box was ticked
// again at the next restart, at the next save of any other tab, and within
// the hour when the Community Bans pull wrote its own state back (each loads
// the file first).  TestZeroValuesAreKept keeps the table and the tags true.
var zeroMeansDefault = map[string]string{
	// A choice from a list that has no empty member, or whose "unset" member
	// is the default under another name.
	"branding.default.copy_preset":       "a preset from a list",
	"branding.default.theme":             "a theme from a list",
	"challenge.default.captcha.provider": "a provider from a list",
	"community_bans.subscribe_mode":      "a mode from a list; off is spelled \"off\"",
	"global.known_browser_action":        "a chain from a list; the page's \"unset\" row names the default",
	"notifications.format":               "a format from a list",
	"rate_limit.default.challenge_mode":  "a chain from a list",
	"rate_limit.default.name":            "the zone has to have a name",
	"community_bans.aggregate_url":       "an address; no address means the stock one (subscribe_mode turns the feature off)",
	"community_bans.feed_url":            "as aggregate_url",
	"community_bans.register_url":        "as aggregate_url",
	"community_bans.submit_url":          "as aggregate_url",
	"nginx.honeypot.ban_file_path":       "a path, config file only; no path means the stock one",

	// A quantity that has to be positive.  The settings page refuses a zero
	// or puts the default in its place before it saves.
	"challenge.default.captcha.builtin_score_threshold": "applyCaptchaForm replaces a value <= 0 with 0.5",
	"challenge.default.captcha.recaptcha_min_score":     "applyCaptchaForm replaces a value <= 0 with 0.5",
	"challenge.default.captcha_cookie_valid_seconds":    "a lifetime; 0 reads as the default (CaptchaCookieValidSecondsResolved)",
	"challenge.default.pow_cookie_valid_seconds":        "a lifetime; 0 reads as the default (PowCookieValidSecondsResolved)",
	"events_batch_interval_ms":                          "an interval, config file only",
	"events_batch_size":                                 "a size, config file only",
	"nginx.honeypot.ban_duration_sec":                   "a duration; 0 reads as the default (ResolvedBanDurationSec) and the page refuses it",
	"notifications.burst_threshold_per_5m":              "a floor of 1 or more on the page; challenge_burst is the switch",
	"rate_limit.default.window_sec":                     "a window",
	"smtp.port":                                         "a port",

	// Written by the daemon, not chosen: generated when empty, or a stamp.
	"nginx.seen_version":               "the admin's version at the last save of the settings page",
	"rate_limit.presets_backfilled_at": "a stamp of the preset backfill",
	"secret.admin_secret":              "generated when empty",
	"secret.bv_secret":                 "generated when empty",
	"secret.captcha_secret_base":       "generated when empty",
}

type settingLeaf struct {
	path  string
	index []int
}

// settingLeaves walks the settings struct the way yaml does and returns every
// field that is not itself a struct, by its dotted yaml path.
func settingLeaves(t reflect.Type, prefix string, index []int, out *[]settingLeaf) {
	for i := 0; i < t.NumField(); i++ {
		f := t.Field(i)
		if f.PkgPath != "" {
			continue
		}
		tag := f.Tag.Get("yaml")
		name := strings.Split(tag, ",")[0]
		if name == "-" {
			continue
		}
		if name == "" {
			name = strings.ToLower(f.Name)
		}
		idx := append(append([]int{}, index...), i)
		if f.Type.Kind() == reflect.Struct {
			sub := prefix + name + "."
			if strings.Contains(tag, ",inline") {
				sub = prefix
			}
			settingLeaves(f.Type, sub, idx, out)
			continue
		}
		*out = append(*out, settingLeaf{path: prefix + name, index: idx})
	}
}

func emptyValue(v reflect.Value) bool {
	switch v.Kind() {
	case reflect.Slice, reflect.Map:
		return v.Len() == 0
	}
	return v.IsZero()
}

// TestZeroValuesAreKept: for every setting that a fresh install leaves at
// something other than zero, set it to zero (off, 0, "", an empty list), save
// and load.  It has to come back as it was saved, unless zeroMeansDefault
// says why zero is not a value an operator can choose there.
func TestZeroValuesAreKept(t *testing.T) {
	prev := log.Writer()
	log.SetOutput(io.Discard)
	t.Cleanup(func() { log.SetOutput(prev) })

	dir := t.TempDir()
	empty := filepath.Join(dir, "empty.yml")
	if err := os.WriteFile(empty, []byte("{}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	fresh, err := Load(empty)
	if err != nil {
		t.Fatal(err)
	}
	var leaves []settingLeaf
	settingLeaves(reflect.TypeOf(fresh), "", nil, &leaves)
	if len(leaves) < 200 {
		t.Fatalf("the walk found only %d settings; it no longer reads the struct the way yaml does", len(leaves))
	}

	back := map[string]string{} // path -> what a saved zero came back as
	probed := 0
	for _, lf := range leaves {
		if emptyValue(reflect.ValueOf(fresh).FieldByIndex(lf.index)) {
			continue
		}
		probed++
		s, err := Load(empty)
		if err != nil {
			t.Fatal(err)
		}
		fv := reflect.ValueOf(&s).Elem().FieldByIndex(lf.index)
		if fv.Kind() == reflect.Slice {
			fv.Set(reflect.MakeSlice(fv.Type(), 0, 0)) // what a form with every row unticked leaves
		} else {
			fv.Set(reflect.Zero(fv.Type()))
		}
		p := filepath.Join(dir, "probe.yml")
		if err := Save(s, p); err != nil {
			t.Errorf("%s: Save refuses the zero value: %v", lf.path, err)
			continue
		}
		got, err := Load(p)
		if err != nil {
			t.Errorf("%s: Load fails on the file a saved zero value left: %v", lf.path, err)
			continue
		}
		if rv := reflect.ValueOf(got).FieldByIndex(lf.index); !emptyValue(rv) {
			back[lf.path] = fmt.Sprintf("%v", rv.Interface())
		}
	}
	if probed < 40 {
		t.Fatalf("only %d settings have a default that is not zero; defaults() is not what this test was written for", probed)
	}

	var paths []string
	for p := range back {
		paths = append(paths, p)
	}
	sort.Strings(paths)
	for _, p := range paths {
		if _, ok := zeroMeansDefault[p]; !ok {
			t.Errorf("%s: saved as zero, loaded as %s.  If off / 0 / empty is a value an operator can choose, "+
				"take omitempty off its yaml tag; if it is not, add it to zeroMeansDefault with the reason", p, back[p])
		}
	}
	for p, why := range zeroMeansDefault {
		if _, ok := back[p]; !ok {
			t.Errorf("%s is in zeroMeansDefault (%s), but a zero saved there is kept now: take it out of the table", p, why)
		}
	}
}
