package handlers

import (
	"bytes"
	"fmt"
	"html"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/unmask-sh/unmask/admin/internal/settings"
)

// A settings tab must survive a no-op save: GET the page, serialize each form
// exactly the way a browser would (selected options, checked boxes, field
// values), POST it back unchanged, and the persisted config must not change.
//
// This guards a whole bug class, not one field: a <select> that cannot express
// "unset" silently pins its displayed value on the first save of an unrelated
// field on the same tab.  That is exactly how challenge_targets.default_action
// became pow_then_captcha on every fleet node (enabling the stale-browser tier
// saved the ua-filter tab, the picker's displayed fallback got persisted, and
// the then-unscoped default escalated every plain challenge to the CAPTCHA
// leg).  Any future tab/field with the same shape fails here automatically.

// ---- minimal form parser for our own rendered template output ----
//
// The admin templates are hand-written lowercase HTML, so a lightweight
// scanner is enough; x/net/html would be a new dependency for test-only use.

type formField struct {
	tag        string // "input" | "textarea" | "select"
	typ        string // input type, lowercased
	name       string
	value      string
	checked    bool
	disabled   bool
	selectVals []string // resolved selected option values (select only)
}

type htmlForm struct {
	action string
	fields []formField
}

// parseAttrs tokenizes the inside of a tag (`input type="text" name=x checked`)
// into a key -> value map; boolean attributes get "".
func parseAttrs(tag string) map[string]string {
	attrs := map[string]string{}
	i := 0
	n := len(tag)
	for i < n {
		for i < n && (tag[i] == ' ' || tag[i] == '\t' || tag[i] == '\n' || tag[i] == '\r' || tag[i] == '/') {
			i++
		}
		start := i
		for i < n && tag[i] != '=' && tag[i] != ' ' && tag[i] != '\t' && tag[i] != '\n' && tag[i] != '\r' && tag[i] != '/' {
			i++
		}
		if start == i {
			break
		}
		name := strings.ToLower(tag[start:i])
		val := ""
		if i < n && tag[i] == '=' {
			i++
			if i < n && (tag[i] == '"' || tag[i] == '\'') {
				q := tag[i]
				i++
				vs := i
				for i < n && tag[i] != q {
					i++
				}
				val = tag[vs:i]
				if i < n {
					i++
				}
			} else {
				vs := i
				for i < n && tag[i] != ' ' && tag[i] != '\t' && tag[i] != '\n' && tag[i] != '\r' {
					i++
				}
				val = tag[vs:i]
			}
		}
		attrs[name] = html.UnescapeString(val)
	}
	return attrs
}

// scanTag returns the tag body between `<name` and the closing `>` starting at
// or after `from`, plus the index just past the `>`; start=-1 when absent.
func scanTag(doc, name string, from int) (body string, start, end int) {
	i := strings.Index(doc[from:], "<"+name)
	if i < 0 {
		return "", -1, -1
	}
	start = from + i
	g := strings.IndexByte(doc[start:], '>')
	if g < 0 {
		return "", -1, -1
	}
	end = start + g + 1
	return doc[start+1+len(name) : start+g], start, end
}

// parseSelect resolves a <select> block to its browser-submitted value(s):
// every option carrying `selected`, else the first option (the browser
// default — the exact mechanism that pins a displayed fallback on save).
func parseSelect(attrs map[string]string, inner string) formField {
	f := formField{tag: "select", name: attrs["name"]}
	_, f.disabled = attrs["disabled"]
	firstVal := ""
	first := true
	pos := 0
	for {
		body, s, e := scanTag(inner, "option", pos)
		if s < 0 {
			break
		}
		oa := parseAttrs(body)
		val, hasVal := oa["value"]
		if !hasVal {
			// No value attribute: the option's text content is submitted.
			rest := inner[e:]
			stop := len(rest)
			if j := strings.IndexByte(rest, '<'); j >= 0 {
				stop = j
			}
			val = strings.TrimSpace(html.UnescapeString(rest[:stop]))
		}
		if first {
			firstVal = val
			first = false
		}
		if _, ok := oa["selected"]; ok {
			f.selectVals = append(f.selectVals, val)
		}
		pos = e
	}
	if len(f.selectVals) == 0 && !first {
		f.selectVals = []string{firstVal}
	}
	return f
}

// parseForms extracts every <form> whose action targets /admin/settings/save.
func parseForms(doc string) []htmlForm {
	var forms []htmlForm
	pos := 0
	for {
		body, s, e := scanTag(doc, "form", pos)
		if s < 0 {
			break
		}
		endIdx := strings.Index(doc[e:], "</form>")
		if endIdx < 0 {
			break
		}
		inner := doc[e : e+endIdx]
		pos = e + endIdx + len("</form>")

		attrs := parseAttrs(body)
		f := htmlForm{action: attrs["action"]}
		if !strings.Contains(f.action, "/admin/settings/save") {
			continue
		}

		ip := 0
		for {
			// Find the nearest of input / textarea / select from ip.
			ti, tin := -1, ""
			for _, cand := range []string{"input", "textarea", "select"} {
				_, cs, _ := scanTag(inner, cand, ip)
				if cs >= 0 && (ti < 0 || cs < ti) {
					ti, tin = cs, cand
				}
			}
			if ti < 0 {
				break
			}
			body, _, te := scanTag(inner, tin, ti)
			a := parseAttrs(body)
			switch tin {
			case "input":
				fld := formField{tag: "input", typ: strings.ToLower(a["type"]), name: a["name"], value: a["value"]}
				_, fld.checked = a["checked"]
				_, fld.disabled = a["disabled"]
				f.fields = append(f.fields, fld)
				ip = te
			case "textarea":
				closeIdx := strings.Index(inner[te:], "</textarea>")
				if closeIdx < 0 {
					ip = te
					continue
				}
				fld := formField{tag: "textarea", name: a["name"],
					value: html.UnescapeString(inner[te : te+closeIdx])}
				_, fld.disabled = a["disabled"]
				f.fields = append(f.fields, fld)
				ip = te + closeIdx + len("</textarea>")
			case "select":
				closeIdx := strings.Index(inner[te:], "</select>")
				if closeIdx < 0 {
					ip = te
					continue
				}
				f.fields = append(f.fields, parseSelect(a, inner[te:te+closeIdx]))
				ip = te + closeIdx + len("</select>")
			}
		}
		forms = append(forms, f)
	}
	return forms
}

// values serializes the form the way a browser submit would.
func (f htmlForm) values() url.Values {
	v := url.Values{}
	for _, fld := range f.fields {
		if fld.disabled || fld.name == "" {
			continue
		}
		switch fld.tag {
		case "input":
			switch fld.typ {
			case "checkbox", "radio":
				if fld.checked {
					val := fld.value
					if val == "" {
						val = "on"
					}
					v.Add(fld.name, val)
				}
			case "submit", "button", "image", "file", "reset":
				// Not part of a plain submit (submit buttons only send when
				// clicked; file inputs are empty).
			default:
				v.Add(fld.name, fld.value)
			}
		case "textarea":
			v.Add(fld.name, fld.value)
		case "select":
			for _, val := range fld.selectVals {
				v.Add(fld.name, val)
			}
		}
	}
	return v
}

// sectionOf pulls the ?section= value out of a form action.
func sectionOf(action string) string {
	u, err := url.Parse(action)
	if err != nil {
		return ""
	}
	return u.Query().Get("section")
}

// multipartSections mirrors AdminSettingsSave's multipart branch.
var multipartSections = map[string]bool{"branding": true, "appearance": true}

func TestSettingsTabsNoOpSave(t *testing.T) {
	h := newTestHandler(t)
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.yml")

	// Seed = a REAL fresh install: full defaults() (via loading an empty yaml —
	// Load("") would fall through to /etc/unmask/config.yml on a dev box) plus
	// what config-init writes (server listen + stale_browser_challenge).  A
	// hand-built partial struct would persist zero values that defaults() never
	// produces ("" mmdb_path, 0 rate limits) and report divergences no real
	// install can hit.
	emptyPath := filepath.Join(dir, "empty-seed.yml")
	if err := os.WriteFile(emptyPath, []byte("{}\n"), 0o600); err != nil {
		t.Fatalf("seed empty yaml: %v", err)
	}
	s, err := settings.Load(emptyPath)
	if err != nil {
		t.Fatalf("load defaults: %v", err)
	}
	s.Server.Bind = "127.0.0.1"
	s.Server.Port = 9477
	s.Server.BasePath = "/unmask"
	s.Global.StaleBrowserChallenge = true
	// Pin the version the same way a released binary runs: the save path stamps
	// SeenVersion with h.Version, and the render treats presets newer than
	// SeenVersion as NEW (= forced-off checkboxes that a save then drops —
	// review-gate semantics, not a no-op bug).
	h.Version = "9.9.9"
	s.Nginx.SeenVersion = "v9.9.9"
	s.Nginx.OutputDir = dir
	s.CommunityBans.MapDir = dir
	// Advanced-gated tabs (web-bot-auth / privacy-pass) redirect to About when
	// the master switch is off; enable it so their forms render and get tested.
	s.Nginx.AdvancedEnabled = true
	if err := settings.Save(s, cfgPath); err != nil {
		t.Fatalf("seed config: %v", err)
	}
	h.ConfigPath = cfgPath
	// Publish the seed exactly as a fresh Load sees it, so the in-memory copy
	// the GET renders from matches what the save path re-reads from disk.
	loaded, err := settings.Load(cfgPath)
	if err != nil {
		t.Fatalf("load seed: %v", err)
	}
	h.SetSettings(loaded)

	// Every form lives behind a `{{ if eq .Tab ... }}` guard, so collect them
	// tab by tab (list mirrors AdminSettingsIndex's tab switch).
	tabs := []string{"top", "network", "global", "ua-filter", "ja4-verdicts",
		"honeypot", "bypass-ips", "bypass-paths", "web-bot-auth", "privacy-pass",
		"protected", "captcha", "challenge", "rate-limit", "deny-design", "geo",
		"theme", "notifications", "retention", "community-bans", "sites",
		"about"}
	var forms []htmlForm
	for _, tab := range tabs {
		req := httptest.NewRequest(http.MethodGet, "/unmask/admin/settings/?tab="+tab, nil)
		req.SetPathValue("tab", tab)
		rr := httptest.NewRecorder()
		h.AdminSettingsIndex(rr, req)
		if rr.Code != http.StatusOK {
			t.Fatalf("settings GET tab=%s: want 200, got %d", tab, rr.Code)
		}
		forms = append(forms, parseForms(rr.Body.String())...)
	}
	if len(forms) < 15 {
		t.Fatalf("parsed only %d settings forms — parser or template regression", len(forms))
	}

	seen := map[string]bool{}
	for _, f := range forms {
		section := sectionOf(f.action)
		if section == "" || seen[section] {
			// Per-site subforms (branding/challenge site rows) POST to their
			// own endpoints; duplicates of a section keep the first (main) form.
			continue
		}
		seen[section] = true
		t.Run(section, func(t *testing.T) {
			before, err := settings.Load(cfgPath)
			if err != nil {
				t.Fatalf("load before: %v", err)
			}
			beforeYAML, err := settings.MarshalYAML(before)
			if err != nil {
				t.Fatalf("marshal before: %v", err)
			}

			var req *http.Request
			if multipartSections[section] {
				var buf bytes.Buffer
				mw := multipart.NewWriter(&buf)
				for key, vals := range f.values() {
					for _, val := range vals {
						if err := mw.WriteField(key, val); err != nil {
							t.Fatalf("multipart field: %v", err)
						}
					}
				}
				mw.Close()
				req = httptest.NewRequest(http.MethodPost,
					"/unmask/admin/settings/save?section="+url.QueryEscape(section), &buf)
				req.Header.Set("Content-Type", mw.FormDataContentType())
			} else {
				req = httptest.NewRequest(http.MethodPost,
					"/unmask/admin/settings/save?section="+url.QueryEscape(section),
					strings.NewReader(f.values().Encode()))
				req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			}
			rr := httptest.NewRecorder()
			h.AdminSettingsSave(rr, req)
			if rr.Code != http.StatusFound {
				t.Fatalf("save: want 302, got %d body=%s", rr.Code, rr.Body.String())
			}
			if loc := rr.Header().Get("Location"); !strings.Contains(loc, "saved=1") {
				t.Fatalf("save redirected with an error (flash), Location=%q", loc)
			}

			after, err := settings.Load(cfgPath)
			if err != nil {
				t.Fatalf("load after: %v", err)
			}
			afterYAML, err := settings.MarshalYAML(after)
			if err != nil {
				t.Fatalf("marshal after: %v", err)
			}
			if beforeYAML != afterYAML {
				t.Errorf("no-op save changed the persisted config:\n%s",
					yamlDiff(beforeYAML, afterYAML))
			}
		})
	}
	if !seen["ua-filter"] || !seen["global"] {
		t.Errorf("expected core sections in the rendered page, got %v", seen)
	}
}

// yamlDiff renders a compact line diff (removed/added) for the failure report.
func yamlDiff(before, after string) string {
	bl := strings.Split(before, "\n")
	al := strings.Split(after, "\n")
	bset := map[string]int{}
	for _, l := range bl {
		bset[l]++
	}
	aset := map[string]int{}
	for _, l := range al {
		aset[l]++
	}
	var sb strings.Builder
	for _, l := range bl {
		if aset[l] == 0 {
			fmt.Fprintf(&sb, "  - %s\n", l)
		} else {
			aset[l]--
		}
	}
	for _, l := range al {
		if bset[l] == 0 {
			fmt.Fprintf(&sb, "  + %s\n", l)
		} else {
			bset[l]--
		}
	}
	if sb.Len() == 0 {
		return "  (byte-level difference only — key order or whitespace)"
	}
	return sb.String()
}
