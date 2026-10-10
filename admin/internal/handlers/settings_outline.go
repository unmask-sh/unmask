package handlers

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"regexp"
	"sort"
	"strings"

	"golang.org/x/net/html"

	"github.com/unmask-sh/unmask/admin/internal/i18n"
)

// The settings outline: what the ask page's assistant reads to say where a
// setting lives.  Each tab is rendered as the operator would see it -- their
// language, the current values -- and reduced to its headings, help, field
// labels, names and values.  The page is the catalog, so nothing here goes
// stale when a tab changes, and an answer can name the tab, the section and
// the field as the operator will find them.

// settingsTabOrder lists the tabs as the nav does.
var settingsTabOrder = []string{
	"top", "network", "global", "ua-filter", "ja4-verdicts", "honeypot", "bypass-ips", "bypass-paths",
	"web-bot-auth", "privacy-pass", "protected", "captcha", "challenge", "rate-limit", "deny-design",
	"geo", "asn", "custom-rules", "theme", "notifications", "retention", "performance", "community-bans", "sites",
	"gateway", "ai-advisor", "about",
}

// SettingsField is one control on a settings tab.
type SettingsField struct {
	Label  string `json:"label,omitempty"`
	Name   string `json:"name"`             // the form field's name
	Option string `json:"option,omitempty"` // a checkbox's or radio's own value, when the name is shared
	Kind   string `json:"kind"`             // checkbox / radio / text / number / select / textarea ...
	Value  string `json:"value,omitempty"`  // the current value; a secret is only said to be set
}

// SettingsSection is one heading of a tab with what sits under it.
type SettingsSection struct {
	Heading string          `json:"heading"`
	Help    string          `json:"help,omitempty"`
	Notes   []string        `json:"notes,omitempty"`
	Fields  []SettingsField `json:"fields,omitempty"`
}

// SettingsTabOutline is one tab reduced to its outline.
type SettingsTabOutline struct {
	Tab      string            `json:"tab"`
	Path     string            `json:"path"`
	Title    string            `json:"title"`
	Sections []SettingsSection `json:"sections"`
}

// SettingsMatch is one section that answered a search, with where it is.
type SettingsMatch struct {
	Tab     string          `json:"tab"`
	Path    string          `json:"path"`
	Title   string          `json:"title"`
	Heading string          `json:"heading"`
	Help    string          `json:"help,omitempty"`
	Notes   []string        `json:"notes,omitempty"`
	Fields  []SettingsField `json:"fields,omitempty"`
	score   int
}

// bufResponse collects a handler's output in memory.
type bufResponse struct {
	hdr  http.Header
	code int
	body strings.Builder
}

func (b *bufResponse) Header() http.Header {
	if b.hdr == nil {
		b.hdr = http.Header{}
	}
	return b.hdr
}
func (b *bufResponse) Write(p []byte) (int, error) { return b.body.Write(p) }
func (b *bufResponse) WriteHeader(c int)           { b.code = c }

var secretFieldRE = regexp.MustCompile(`(?i)(secret|password|passwd|token|api_key|apikey|_key$|^key$|dsn)`)

// SettingsTabOutline renders one tab for the operator in ctx (their session
// and language) and reduces it to its outline.
func (h *Handler) SettingsTabOutline(ctx context.Context, lang i18n.Lang, tab string) (*SettingsTabOutline, error) {
	if !settingsTabs[tab] {
		return nil, fmt.Errorf("no settings tab %q; the tabs are %s", tab, strings.Join(settingsTabOrder, ", "))
	}
	path := h.basePath() + "/admin/settings/" + tab + "/"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, path, nil)
	if err != nil {
		return nil, err
	}
	req.SetPathValue("tab", tab)
	req.AddCookie(&http.Cookie{Name: i18n.CookieName, Value: string(lang)})
	w := &bufResponse{}
	h.AdminSettingsIndex(w, req)
	if w.code != 0 && w.code != http.StatusOK {
		// The advanced tabs redirect to About while the master switch is off.
		return nil, fmt.Errorf("the %s tab is not shown on this install (its switch is off)", tab)
	}
	doc, err := html.Parse(strings.NewReader(w.body.String()))
	if err != nil {
		return nil, err
	}
	out := &SettingsTabOutline{Tab: tab, Path: path, Title: i18n.T(lang, "settings.tab."+strings.ReplaceAll(tab, "-", "_"))}
	root := findNode(doc, func(n *html.Node) bool {
		return n.Type == html.ElementNode && n.Data == "section" && hasClass(n, "settings-content")
	})
	if root == nil {
		root = doc
	}
	labels := labelsByFor(root)
	cur := -1
	lastH2 := ""
	section := func() *SettingsSection {
		if cur < 0 {
			out.Sections = append(out.Sections, SettingsSection{Heading: out.Title})
			cur = len(out.Sections) - 1
		}
		return &out.Sections[cur]
	}
	var walk func(n *html.Node)
	walk = func(n *html.Node) {
		if n.Type == html.ElementNode {
			switch {
			case n.Data == "script" || n.Data == "style" || n.Data == "template" || hasClass(n, "info-tip") || hasAttr(n, "hidden"):
				return
			case n.Data == "h2" || n.Data == "h3":
				// An h3 is a part of the h2 above it (a card's "preset" and
				// "custom" halves), so it is named under that heading.
				if t := cleanText(n); t != "" {
					if n.Data == "h2" {
						lastH2 = t
					} else if lastH2 != "" {
						t = lastH2 + " › " + t
					}
					out.Sections = append(out.Sections, SettingsSection{Heading: t, Help: clip(popupText(n), 300)})
					cur = len(out.Sections) - 1
				}
				return
			case n.Data == "p" && hasClass(n, "desc"):
				if t := cleanText(n); t != "" {
					if s := section(); len(s.Notes) < 6 {
						s.Notes = append(s.Notes, clip(t, 200))
					}
				}
				return
			case n.Data == "input" || n.Data == "select" || n.Data == "textarea":
				if f, ok := fieldOf(n, labels); ok {
					s := section()
					s.Fields = append(s.Fields, f)
				}
				return
			}
		}
		for c := n.FirstChild; c != nil; c = c.NextSibling {
			walk(c)
		}
	}
	walk(root)
	kept := out.Sections[:0]
	for _, s := range out.Sections {
		if len(s.Fields) > 0 || len(s.Notes) > 0 || s.Help != "" {
			kept = append(kept, s)
		}
	}
	out.Sections = kept
	return out, nil
}

// SettingsFind searches every tab's outline for the words of query and
// returns the sections that carry them, best first.
func (h *Handler) SettingsFind(ctx context.Context, lang i18n.Lang, query string) ([]SettingsMatch, error) {
	terms := searchTerms(query)
	if len(terms) == 0 {
		return nil, errors.New("give one or more words to look for (a setting's name, a vendor, a header...)")
	}
	var all []SettingsMatch
	for _, tab := range settingsTabOrder {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		o, err := h.SettingsTabOutline(ctx, lang, tab)
		if err != nil {
			continue // a tab this install does not show
		}
		for _, s := range o.Sections {
			hay := strings.ToLower(s.Heading + " " + s.Help + " " + strings.Join(s.Notes, " "))
			head := 0
			for _, t := range terms {
				if strings.Contains(hay, t) {
					head++
				}
			}
			var fields []SettingsField
			for _, f := range s.Fields {
				ft := strings.ToLower(f.Label + " " + f.Name + " " + f.Option + " " + f.Value)
				for _, t := range terms {
					if strings.Contains(ft, t) {
						fields = append(fields, f)
						break
					}
				}
			}
			if head == 0 && len(fields) == 0 {
				continue
			}
			m := SettingsMatch{Tab: tab, Path: o.Path, Title: o.Title, Heading: s.Heading, Help: s.Help, Notes: s.Notes, score: head*3 + min(len(fields), 5)}
			if head > 0 && len(fields) == 0 {
				fields = s.Fields // the heading answered: show what sits under it
			}
			if len(fields) > 25 {
				fields = fields[:25]
			}
			m.Fields = fields
			all = append(all, m)
		}
	}
	sort.SliceStable(all, func(i, j int) bool { return all[i].score > all[j].score })
	if len(all) > 10 {
		all = all[:10]
	}
	return all, nil
}

// searchTerms splits a query into lower-cased words, dropping the ones
// that would match every page (particles, "setting", "where").
func searchTerms(q string) []string {
	stop := map[string]bool{
		"の": true, "は": true, "を": true, "が": true, "に": true, "で": true, "と": true, "や": true, "も": true, "へ": true,
		"から": true, "まで": true, "する": true, "した": true, "して": true, "です": true, "ます": true, "ある": true, "どこ": true,
		"設定": true, "項目": true, "場所": true, "画面": true, "方法": true, "the": true, "is": true, "a": true, "an": true, "of": true,
		"to": true, "in": true, "on": true, "for": true, "and": true, "or": true, "where": true, "how": true, "do": true, "i": true,
		"set": true, "setting": true, "settings": true, "config": true, "configure": true, "option": true, "page": true, "tab": true,
	}
	var out []string
	for _, w := range strings.FieldsFunc(strings.ToLower(q), func(r rune) bool {
		return r == ' ' || r == '\t' || r == '\n' || r == ',' || r == '、' || r == '・' || r == '?' || r == '？' || r == '/' || r == '(' || r == ')' || r == '（' || r == '）'
	}) {
		w = strings.Trim(w, ".:;\"'「」『』")
		if w == "" || stop[w] || (len([]rune(w)) < 2 && w < "\u0080") {
			continue
		}
		out = append(out, w)
	}
	return out
}

// fieldOf reduces a control to a field: its label (by for=id, the enclosing
// label, the preset row's title, or the placeholder), its name and kind, and
// its current value.  Hidden inputs and the CSRF token are not fields.
func fieldOf(n *html.Node, labels map[string]string) (SettingsField, bool) {
	name := attr(n, "name")
	typ := attr(n, "type")
	if name == "" || name == "_csrf" || (n.Data == "input" && typ == "hidden") {
		return SettingsField{}, false
	}
	if n.Data != "input" || typ == "" {
		typ = n.Data
	}
	f := SettingsField{Name: name, Kind: typ}
	if id := attr(n, "id"); id != "" {
		f.Label = labels[id]
	}
	if f.Label == "" {
		if l := ancestor(n, func(a *html.Node) bool { return a.Data == "label" }); l != nil {
			f.Label = clip(cleanText(l), 120)
		}
	}
	if f.Label == "" {
		if p := ancestor(n, func(a *html.Node) bool { return hasClass(a, "preset") || hasClass(a, "rule-row") }); p != nil {
			if t := findNode(p, func(a *html.Node) bool {
				return a.Type == html.ElementNode && (hasClass(a, "ttl") || hasClass(a, "rule-title"))
			}); t != nil {
				if hasClass(t, "rule-title") {
					f.Label = clip(attr(t, "value"), 120)
				} else {
					f.Label = clip(cleanText(t), 120)
				}
			}
		}
	}
	if f.Label == "" {
		f.Label = clip(attr(n, "placeholder"), 120)
	}
	if f.Label == "" {
		f.Label = clip(attr(n, "aria-label"), 120)
	}
	switch {
	case typ == "checkbox":
		if v := attr(n, "value"); v != "" && v != "1" && v != "on" {
			f.Option = v
		}
		if hasAttr(n, "checked") {
			f.Value = "on"
		} else {
			f.Value = "off"
		}
	case typ == "radio":
		f.Option = attr(n, "value")
		if hasAttr(n, "checked") {
			f.Value = "selected"
		}
	case n.Data == "select":
		var first, chosen string
		for c := n.FirstChild; c != nil; c = c.NextSibling {
			if c.Type != html.ElementNode || c.Data != "option" {
				continue
			}
			t := cleanText(c)
			if first == "" {
				first = t
			}
			if hasAttr(c, "selected") {
				chosen = t
			}
		}
		if chosen == "" {
			chosen = first
		}
		f.Value = clip(chosen, 120)
	case n.Data == "textarea":
		f.Value = clip(cleanText(n), 160)
	default:
		f.Value = clip(attr(n, "value"), 160)
	}
	if (typ == "password" || secretFieldRE.MatchString(name)) && f.Value != "" && f.Value != "on" && f.Value != "off" {
		f.Value = "(set; not shown)"
	}
	return f, true
}

func labelsByFor(root *html.Node) map[string]string {
	out := map[string]string{}
	var walk func(n *html.Node)
	walk = func(n *html.Node) {
		if n.Type == html.ElementNode && n.Data == "label" {
			if id := attr(n, "for"); id != "" {
				// A preset row's label carries the title and a CIDR list; the
				// title alone names it.
				if t := findNode(n, func(a *html.Node) bool { return a.Type == html.ElementNode && hasClass(a, "ttl") }); t != nil {
					out[id] = clip(cleanText(t), 120)
				} else {
					out[id] = clip(cleanText(n), 120)
				}
			}
		}
		for c := n.FirstChild; c != nil; c = c.NextSibling {
			walk(c)
		}
	}
	walk(root)
	return out
}

// cleanText is the node's text, help tips and scripts left out, whitespace
// collapsed.
func cleanText(n *html.Node) string {
	var b strings.Builder
	var walk func(n *html.Node)
	walk = func(n *html.Node) {
		switch {
		case n.Type == html.TextNode:
			b.WriteString(n.Data)
			b.WriteByte(' ')
		case n.Type == html.ElementNode && (n.Data == "script" || n.Data == "style" || hasClass(n, "info-tip") || hasClass(n, "info-popup")):
			return
		}
		for c := n.FirstChild; c != nil; c = c.NextSibling {
			walk(c)
		}
	}
	walk(n)
	return strings.Join(strings.Fields(b.String()), " ")
}

// popupText is the help tip's text under a heading.
func popupText(n *html.Node) string {
	p := findNode(n, func(a *html.Node) bool { return a.Type == html.ElementNode && hasClass(a, "info-popup") })
	if p == nil {
		return ""
	}
	var b strings.Builder
	var walk func(n *html.Node)
	walk = func(n *html.Node) {
		if n.Type == html.TextNode {
			b.WriteString(n.Data)
			b.WriteByte(' ')
		}
		if n.Type == html.ElementNode && n.Data == "br" {
			b.WriteByte(' ')
		}
		for c := n.FirstChild; c != nil; c = c.NextSibling {
			walk(c)
		}
	}
	walk(p)
	return strings.Join(strings.Fields(b.String()), " ")
}

func findNode(n *html.Node, ok func(*html.Node) bool) *html.Node {
	if ok(n) {
		return n
	}
	for c := n.FirstChild; c != nil; c = c.NextSibling {
		if f := findNode(c, ok); f != nil {
			return f
		}
	}
	return nil
}

func ancestor(n *html.Node, ok func(*html.Node) bool) *html.Node {
	for p := n.Parent; p != nil; p = p.Parent {
		if p.Type == html.ElementNode && ok(p) {
			return p
		}
	}
	return nil
}

func attr(n *html.Node, name string) string {
	for _, a := range n.Attr {
		if a.Key == name {
			return a.Val
		}
	}
	return ""
}

func hasAttr(n *html.Node, name string) bool {
	for _, a := range n.Attr {
		if a.Key == name {
			return true
		}
	}
	return false
}

func hasClass(n *html.Node, class string) bool {
	for _, c := range strings.Fields(attr(n, "class")) {
		if c == class {
			return true
		}
	}
	return false
}

func clip(s string, n int) string {
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	return string(r[:n]) + "…"
}
