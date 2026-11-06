package handlers

import (
	"fmt"
	"io/fs"
	"regexp"
	"sort"
	"strings"
	"testing"
	"text/template/parse"

	"github.com/unmask-sh/unmask/admin/assets"
)

// The admin's script policy (csp_nonce.go) runs a script only when its tag
// carries the response's nonce, and runs no inline handler at all.  A
// template that forgets either does not fail anywhere a Go test would see:
// the page renders, and in the browser a button does nothing.  These tests
// read the templates and the static scripts the way the browser will, and
// fail on what the policy would refuse:
//
//   - a <script> tag without nonceAttr, or with a nonceAttr that is handed
//     something other than the page's data (the dot inside a range or a
//     with, a partial called with a sub-value);
//   - an on* attribute in the markup, and a javascript: link;
//   - the same written into an HTML string a script builds, or set with
//     setAttribute;
//   - eval, new Function and string timers, which need 'unsafe-eval'.
//
// The reading is exact where a grep would not be: template and HTML comments
// are not markup, "<script>" inside a script's own comment is not a tag,
// data-on* and name="onward" are not handlers, el.onclick = function is not
// an attribute, and a partial is read where it is called from -- the JavaScript
// a page splices into its <script> is read as JavaScript.

// Markers the flattened template carries where an action stood.
const (
	cspMarkNonceOK  = "\x01" // nonceAttr, given the page's data
	cspMarkNonceBad = "\x02" // nonceAttr, given something else
	cspMarkAction   = "\x03" // any other action that prints
)

// cspScan reads a set of templates (name -> source) and static scripts and
// returns what the policy would refuse, one "file:line: what" per finding.
func cspScan(templates, scripts map[string]string) ([]string, error) {
	set := map[string]*parse.Tree{}
	for name, src := range templates {
		if strings.ContainsAny(src, cspMarkNonceOK+cspMarkNonceBad+cspMarkAction) {
			return nil, fmt.Errorf("%s contains a control character this scan uses as a marker", name)
		}
		tr := parse.New(name)
		tr.Mode = parse.SkipFuncCheck
		if _, err := tr.Parse(src, "", "", set); err != nil {
			return nil, err
		}
	}
	// A template nothing calls is a page, or a fragment a handler executes:
	// its dot is the page's data.
	called := map[string]bool{}
	for _, tr := range set {
		cspWalkCalls(tr.Root, called)
	}
	var names []string
	for name := range set {
		if !called[name] {
			names = append(names, name)
		}
	}
	sort.Strings(names)

	found := map[string]bool{}
	for _, name := range names {
		f := &cspFlat{set: set, sources: templates}
		f.walk(set[name], set[name].Root, true, true, 0)
		s := f.b.String()
		cspLexHTML(s, 0, func(off int, what string) {
			found[f.where(off)+": "+what] = true
		})
	}
	for name, src := range scripts {
		// A script the page loads may add script elements of its own only
		// where the page's policy gives it the nonce to put on them: the
		// challenge page does, the admin does not.
		admin := !strings.HasPrefix(name, "challenge")
		cspCheckJS(src, admin, func(off int, what string) {
			found[fmt.Sprintf("%s:%d: %s", name, 1+strings.Count(src[:off], "\n"), what)] = true
		})
	}
	out := make([]string, 0, len(found))
	for f := range found {
		out = append(out, f)
	}
	sort.Strings(out)
	return out, nil
}

// cspWalkCalls collects the names the tree calls with {{ template }}.
func cspWalkCalls(n parse.Node, called map[string]bool) {
	switch n := n.(type) {
	case *parse.ListNode:
		if n != nil {
			for _, c := range n.Nodes {
				cspWalkCalls(c, called)
			}
		}
	case *parse.IfNode:
		cspWalkCalls(n.List, called)
		cspWalkCalls(n.ElseList, called)
	case *parse.RangeNode:
		cspWalkCalls(n.List, called)
		cspWalkCalls(n.ElseList, called)
	case *parse.WithNode:
		cspWalkCalls(n.List, called)
		cspWalkCalls(n.ElseList, called)
	case *parse.TemplateNode:
		called[n.Name] = true
	}
}

// cspFlat is one page as the browser gets it, give or take the values: the
// text of the template and of every partial it calls, in order, with a marker
// where an action stood.  Both branches of an if are kept, one after the
// other.
type cspFlat struct {
	set     map[string]*parse.Tree
	sources map[string]string
	b       strings.Builder
	spans   []cspSpan
}

// cspSpan says where a stretch of the flattened text came from: what starts
// at offset at was read from file, at offset off.
type cspSpan struct {
	at   int
	file string
	off  int
}

// walk flattens n.  dot and root say whether "." and "$" are the page's data
// at this point.
func (f *cspFlat) walk(tr *parse.Tree, n parse.Node, dot, root bool, depth int) {
	switch n := n.(type) {
	case *parse.ListNode:
		if n != nil {
			for _, c := range n.Nodes {
				f.walk(tr, c, dot, root, depth)
			}
		}
	case *parse.TextNode:
		f.spans = append(f.spans, cspSpan{f.b.Len(), tr.ParseName, int(n.Pos)})
		f.b.Write(n.Text)
	case *parse.ActionNode:
		if len(n.Pipe.Decl) > 0 {
			return // a declaration prints nothing
		}
		f.spans = append(f.spans, cspSpan{f.b.Len(), tr.ParseName, int(n.Pos)})
		f.b.WriteString(cspNonceMark(n.Pipe, dot, root))
	case *parse.IfNode:
		f.walk(tr, n.List, dot, root, depth)
		f.walk(tr, n.ElseList, dot, root, depth)
	case *parse.RangeNode:
		f.walk(tr, n.List, false, root, depth)
		f.walk(tr, n.ElseList, dot, root, depth)
	case *parse.WithNode:
		f.walk(tr, n.List, cspPipeIsPage(n.Pipe, dot, root), root, depth)
		f.walk(tr, n.ElseList, dot, root, depth)
	case *parse.TemplateNode:
		callee := f.set[n.Name]
		if callee == nil || depth > 20 {
			return
		}
		arg := n.Pipe != nil && cspPipeIsPage(n.Pipe, dot, root)
		f.walk(callee, callee.Root, arg, arg, depth+1)
	}
}

// cspPipeIsPage: whether the pipeline is the page's data, i.e. a bare "."
// or "$" that is.
func cspPipeIsPage(p *parse.PipeNode, dot, root bool) bool {
	if p == nil || len(p.Decl) > 0 || len(p.Cmds) != 1 || len(p.Cmds[0].Args) != 1 {
		return false
	}
	return cspArgIsPage(p.Cmds[0].Args[0], dot, root)
}

func cspArgIsPage(a parse.Node, dot, root bool) bool {
	switch a := a.(type) {
	case *parse.DotNode:
		return dot
	case *parse.VariableNode:
		return len(a.Ident) == 1 && a.Ident[0] == "$" && root
	}
	return false
}

// cspNonceMark is the marker for one printing action.
func cspNonceMark(p *parse.PipeNode, dot, root bool) string {
	if len(p.Cmds) == 1 && len(p.Cmds[0].Args) == 2 {
		if id, ok := p.Cmds[0].Args[0].(*parse.IdentifierNode); ok && id.Ident == "nonceAttr" {
			if cspArgIsPage(p.Cmds[0].Args[1], dot, root) {
				return cspMarkNonceOK
			}
			return cspMarkNonceBad
		}
	}
	return cspMarkAction
}

// where names the template line a flattened offset came from.
func (f *cspFlat) where(off int) string {
	i := sort.Search(len(f.spans), func(i int) bool { return f.spans[i].at > off }) - 1
	if i < 0 {
		return "?"
	}
	sp := f.spans[i]
	src := f.sources[sp.file]
	at := sp.off + (off - sp.at)
	if at > len(src) {
		at = len(src)
	}
	return fmt.Sprintf("%s:%d", sp.file, 1+strings.Count(src[:at], "\n"))
}

func cspIsSpace(c byte) bool {
	return c == ' ' || c == '\t' || c == '\n' || c == '\r' || c == '\f'
}

func cspIsAlpha(c byte) bool {
	return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')
}

var (
	cspHandlerAttrRE = regexp.MustCompile(`^on[a-z]+$`)
	cspURLAttrs      = map[string]bool{"href": true, "src": true, "action": true, "formaction": true, "xlink:href": true, "data": true, "poster": true}
)

// cspLexHTML walks markup the way the HTML tokenizer does -- comments, tags
// and their attributes, the raw text of script and style -- and reports what
// the policy refuses.  base is added to every reported offset.
func cspLexHTML(s string, base int, report func(off int, what string)) {
	i := 0
	for i < len(s) {
		j := strings.IndexByte(s[i:], '<')
		if j < 0 {
			return
		}
		i += j
		if strings.HasPrefix(s[i:], "<!--") {
			end := strings.Index(s[i+4:], "-->")
			if end < 0 {
				return
			}
			i += 4 + end + 3
			continue
		}
		if i+1 >= len(s) || !cspIsAlpha(s[i+1]) {
			i++
			continue
		}
		// A start tag: its name, then its attributes up to ">".
		tagAt := i
		p := i + 1
		for p < len(s) && (cspIsAlpha(s[p]) || (s[p] >= '0' && s[p] <= '9') || s[p] == '-' || s[p] == ':') {
			p++
		}
		tag := strings.ToLower(s[i+1 : p])
		attrs := map[string]string{}
		nonce := ""
		for p < len(s) && s[p] != '>' {
			if cspIsSpace(s[p]) || s[p] == '/' {
				p++
				continue
			}
			start := p
			for p < len(s) && !cspIsSpace(s[p]) && s[p] != '=' && s[p] != '>' && s[p] != '/' {
				p++
			}
			if p == start { // a stray "="
				p++
				continue
			}
			name := strings.ToLower(s[start:p])
			for p < len(s) && cspIsSpace(s[p]) {
				p++
			}
			val := ""
			if p < len(s) && s[p] == '=' {
				p++
				for p < len(s) && cspIsSpace(s[p]) {
					p++
				}
				if p < len(s) && (s[p] == '"' || s[p] == '\'') {
					q := s[p]
					p++
					end := strings.IndexByte(s[p:], q)
					if end < 0 {
						end = len(s) - p
					}
					val = s[p : p+end]
					p += end + 1
					if p > len(s) {
						p = len(s)
					}
				} else {
					vs := p
					for p < len(s) && !cspIsSpace(s[p]) && s[p] != '>' {
						p++
					}
					val = s[vs:p]
				}
			}
			switch {
			case strings.Contains(name, cspMarkNonceOK):
				nonce = cspMarkNonceOK
			case strings.Contains(name, cspMarkNonceBad):
				if nonce == "" {
					nonce = cspMarkNonceBad
				}
			case cspHandlerAttrRE.MatchString(name):
				report(base+start, fmt.Sprintf("inline handler %s= on <%s>: the policy runs no inline handler; wire it with addEventListener", name, tag))
			case cspURLAttrs[name] && strings.HasPrefix(strings.ToLower(strings.TrimSpace(val)), "javascript:"):
				report(base+start, fmt.Sprintf("javascript: URL in %s= on <%s>: the policy does not run it", name, tag))
			}
			attrs[name] = val
		}
		if p < len(s) {
			p++ // the ">"
		}
		i = p
		switch tag {
		case "script":
			switch nonce {
			case cspMarkNonceOK:
			case cspMarkNonceBad:
				report(base+tagAt, "<script> whose nonceAttr is not handed the page's data: inside a range or a with write {{ nonceAttr $ }}, and call the partial with the page's dot")
			default:
				report(base+tagAt, "<script> without {{ nonceAttr . }}: the policy does not run it")
			}
			end := cspIndexFold(s[i:], "</script")
			if end < 0 {
				end = len(s) - i
			}
			body := s[i : i+end]
			switch typ := strings.ToLower(strings.TrimSpace(attrs["type"])); {
			case typ == "" || typ == "module" || strings.HasSuffix(typ, "javascript") || strings.HasSuffix(typ, "ecmascript"):
				if _, src := attrs["src"]; !src {
					cspCheckJS(body, true, func(off int, what string) { report(base+i+off, what) })
				}
			case typ == "text/html":
				// A block of markup a script puts into the page.
				cspLexHTML(body, base+i, report)
			}
			i += end
		case "style", "textarea", "title":
			end := cspIndexFold(s[i:], "</"+tag)
			if end < 0 {
				return
			}
			i += end
		}
	}
}

// cspIndexFold is strings.Index for an ASCII needle, whatever its case in s.
func cspIndexFold(s, needle string) int {
	return strings.Index(strings.ToLower(s), needle)
}

var (
	// An on* attribute inside an HTML string: at the start of the literal or
	// after a space or a quote, and followed by its value's quote -- or by
	// the end of the literal, when the value is concatenated on.
	cspStringHandlerRE = regexp.MustCompile("(?i)(?:^|[\\s\"'`])(on[a-z]+)\\s*=\\s*(?:\\\\?[\"'`]|$)")
	cspStringJSURLRE   = regexp.MustCompile(`(?i)javascript:`)
	cspEvalRE          = regexp.MustCompile(`\beval\s*\(|\bnew\s+Function\b`)
	cspStringTimerRE   = regexp.MustCompile("\\bset(?:Timeout|Interval)\\s*\\(\\s*[\"'`]")
	cspSetAttrRE       = regexp.MustCompile("(?i)\\bsetAttribute\\s*\\(\\s*[\"'`]on[a-z]+[\"'`]")
	cspNewScriptRE     = regexp.MustCompile("\\bcreateElement\\s*\\(\\s*[\"'`]script[\"'`]\\s*\\)")
)

// cspCheckJS reports what the policy refuses in one script: handlers and
// javascript: links in the HTML it builds, and the calls that need
// 'unsafe-eval'.  admin says the script is one of the admin's, which may not
// add script elements of its own.
func cspCheckJS(src string, admin bool, report func(off int, what string)) {
	code, lits := cspLexJS(src)
	for _, l := range lits {
		if m := cspStringHandlerRE.FindStringSubmatchIndex(l.text); m != nil {
			report(l.off+m[2], fmt.Sprintf("inline handler %s= in an HTML string: the policy runs no inline handler; add a listener to the element instead", l.text[m[2]:m[3]]))
		}
		if m := cspStringJSURLRE.FindStringIndex(l.text); m != nil {
			report(l.off+m[0], "javascript: URL in a string: the policy does not run it")
		}
	}
	// The rest are calls: looked for in the source, and kept when they start
	// in code rather than in a string or a comment.
	inCode := func(off int) bool { return code[off] != ' ' && code[off] != '\n' }
	for _, c := range []struct {
		re    *regexp.Regexp
		what  string
		apply bool
	}{
		{cspEvalRE, "eval / new Function: the policy carries no 'unsafe-eval'", true},
		{cspStringTimerRE, "a timer given a string: the policy carries no 'unsafe-eval'; give it a function", true},
		{cspSetAttrRE, "setAttribute of an on* handler: the policy runs no inline handler", true},
		{cspNewScriptRE, "a script element built by script: it would need the response's nonce", admin},
	} {
		if !c.apply {
			continue
		}
		for _, m := range c.re.FindAllStringIndex(src, -1) {
			if inCode(m[0]) {
				report(m[0], c.what)
			}
		}
	}
}

// cspLit is one string literal of a script: its text between the quotes, as
// written, and where it starts.
type cspLit struct {
	off  int
	text string
}

// cspLexJS splits a script into its code and its string literals.  code is
// src with every comment, string and regular expression blanked out, byte
// for byte, so an offset in one is an offset in the other.
func cspLexJS(src string) (code []byte, lits []cspLit) {
	code = []byte(src)
	blank := func(from, to int) {
		for k := from; k < to && k < len(code); k++ {
			if code[k] != '\n' {
				code[k] = ' '
			}
		}
	}
	// What the last token was decides whether a "/" divides or opens a
	// regular expression: after a value it divides.
	afterValue := false
	i := 0
	var tmplDepth []int // brace depth of each ${...} being read
	for i < len(src) {
		c := src[i]
		switch {
		case cspIsSpace(c):
			i++
		case c == '/' && i+1 < len(src) && src[i+1] == '/':
			end := strings.IndexByte(src[i:], '\n')
			if end < 0 {
				end = len(src) - i
			}
			blank(i, i+end)
			i += end
		case c == '/' && i+1 < len(src) && src[i+1] == '*':
			end := strings.Index(src[i+2:], "*/")
			if end < 0 {
				end = len(src) - i - 2
			} else {
				end += 2
			}
			blank(i, i+2+end)
			i += 2 + end
		case c == '/' && !afterValue:
			// A regular expression: to the closing "/" outside a class.
			j, class := i+1, false
			for j < len(src) && src[j] != '\n' {
				if src[j] == '\\' {
					j += 2
					continue
				}
				if src[j] == '[' {
					class = true
				} else if src[j] == ']' {
					class = false
				} else if src[j] == '/' && !class {
					break
				}
				j++
			}
			if j >= len(src) || src[j] != '/' { // not one after all
				i++
				afterValue = false
				continue
			}
			j++
			for j < len(src) && cspIsAlpha(src[j]) {
				j++
			}
			blank(i, j)
			i = j
			afterValue = true
		case c == '"' || c == '\'':
			j := i + 1
			for j < len(src) && src[j] != c && src[j] != '\n' {
				if src[j] == '\\' {
					j++
				}
				j++
			}
			if j > len(src) {
				j = len(src)
			}
			lits = append(lits, cspLit{i + 1, src[i+1 : j]})
			blank(i, j+1)
			i = j + 1
			afterValue = true
		case c == '`' || (c == '}' && len(tmplDepth) > 0 && tmplDepth[len(tmplDepth)-1] == 0):
			// A template literal, or the rest of one after a ${...}.
			if c == '}' {
				tmplDepth = tmplDepth[:len(tmplDepth)-1]
			}
			j := i + 1
			open := false
			for j < len(src) && src[j] != '`' {
				if src[j] == '\\' {
					j++
				} else if src[j] == '$' && j+1 < len(src) && src[j+1] == '{' {
					open = true
					break
				}
				j++
			}
			if j > len(src) {
				j = len(src)
			}
			lits = append(lits, cspLit{i + 1, src[i+1 : j]})
			if open {
				blank(i, j+2)
				tmplDepth = append(tmplDepth, 0)
				i = j + 2
				afterValue = false
			} else {
				blank(i, j+1)
				i = j + 1
				afterValue = true
			}
		default:
			if len(tmplDepth) > 0 {
				switch c {
				case '{':
					tmplDepth[len(tmplDepth)-1]++
				case '}':
					tmplDepth[len(tmplDepth)-1]--
				}
			}
			if cspIsAlpha(c) || c == '_' || c == '$' || (c >= '0' && c <= '9') || c == cspMarkAction[0] {
				j := i
				for j < len(src) && (cspIsAlpha(src[j]) || src[j] == '_' || src[j] == '$' || (src[j] >= '0' && src[j] <= '9') || src[j] == cspMarkAction[0]) {
					j++
				}
				switch src[i:j] {
				case "return", "typeof", "instanceof", "in", "of", "new", "delete", "void", "throw", "case", "do", "else", "yield", "await":
					afterValue = false
				default:
					afterValue = true
				}
				i = j
				continue
			}
			afterValue = c == ')' || c == ']'
			i++
		}
	}
	return code, lits
}

// cspAssets reads the shipped templates and static scripts.
func cspAssets(t *testing.T) (templates, scripts map[string]string) {
	t.Helper()
	read := func(fsys fs.FS, pattern string) map[string]string {
		names, err := fs.Glob(fsys, pattern)
		if err != nil {
			t.Fatal(err)
		}
		out := map[string]string{}
		for _, name := range names {
			b, err := fs.ReadFile(fsys, name)
			if err != nil {
				t.Fatal(err)
			}
			out[name[strings.IndexByte(name, '/')+1:]] = string(b)
		}
		return out
	}
	templates, scripts = read(assets.Templates, "templates/*.html"), read(assets.Static, "static/*.js")
	if len(templates) < 40 || templates["settings.html"] == "" || scripts["popover-pin.js"] == "" {
		t.Fatalf("read %d templates and %d scripts; the assets moved", len(templates), len(scripts))
	}
	return templates, scripts
}

// The shipped templates and scripts hold nothing the policy refuses.
func TestAdminTemplatesRunUnderTheScriptPolicy(t *testing.T) {
	templates, scripts := cspAssets(t)
	found, err := cspScan(templates, scripts)
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range found {
		t.Error(f)
	}
}

// The scan itself: what it must catch, and what it must leave alone.
func TestCSPScanCatchesWhatThePolicyRefuses(t *testing.T) {
	const ok = `<script{{ nonceAttr . }}>var a = 1;</script>`
	cases := []struct {
		name string
		tpl  map[string]string
		js   map[string]string
		want []string // a substring of each finding, in order; none = clean
	}{
		{name: "marked script", tpl: map[string]string{"p.html": ok}},
		{name: "unmarked script", tpl: map[string]string{"p.html": "<p>x</p>\n<script>var a;</script>"},
			want: []string{"p.html:2: <script> without"}},
		{name: "unmarked data block and external script", tpl: map[string]string{"p.html": `<script type="application/json">{}</script><script src="/x.js"></script>`},
			want: []string{"p.html:1: <script> without"}},
		{name: "nonce after another attribute", tpl: map[string]string{"p.html": `<script type="text/html" id="h"{{ nonceAttr . }}><b>x</b></script>`}},
		{name: "dot inside range", tpl: map[string]string{"p.html": `{{ range .Rows }}<script{{ nonceAttr . }}>1</script>{{ end }}`},
			want: []string{"not handed the page's data"}},
		{name: "dot inside with", tpl: map[string]string{"p.html": `{{ with .Notice }}<script{{ nonceAttr . }}>1</script>{{ end }}`},
			want: []string{"not handed the page's data"}},
		{name: "dollar inside range and with", tpl: map[string]string{"p.html": `{{ range .Rows }}{{ with .X }}<script{{ nonceAttr $ }}>1</script>{{ end }}{{ end }}`}},
		{name: "partial called with the dot", tpl: map[string]string{
			"p.html":       `{{ template "part" . }}`,
			"partial.html": `{{ define "part" }}{{ with .Notice }}<script{{ nonceAttr $ }}>1</script>{{ end }}{{ end }}`}},
		{name: "partial called with a sub-value", tpl: map[string]string{
			"p.html":       `{{ template "part" .Sub }}`,
			"partial.html": `{{ define "part" }}<script{{ nonceAttr . }}>1</script>{{ end }}`},
			want: []string{"partial.html:1: <script> whose nonceAttr is not handed"}},
		{name: "partial called from a range with dollar", tpl: map[string]string{
			"p.html":       `{{ range .Rows }}{{ template "part" $ }}{{ end }}`,
			"partial.html": `{{ define "part" }}<script{{ nonceAttr . }}>1</script>{{ end }}`}},
		{name: "partial called from a range with its element", tpl: map[string]string{
			"p.html":       `{{ range .Rows }}{{ template "part" . }}{{ end }}`,
			"partial.html": `{{ define "part" }}<script{{ nonceAttr . }}>1</script>{{ end }}`},
			want: []string{"not handed the page's data"}},
		{name: "comments are not markup", tpl: map[string]string{"p.html": "{{/* a <script> block, onclick=\"x\" */}}\n<!-- <script>old()</script> <a onclick=\"x()\"> -->\n" +
			`<script{{ nonceAttr . }}>// html/template escapes inside <script>, and onclick="x" is gone` + "\n/* <button onclick=\"y()\"> */ var a;</script>"}},
		{name: "inline handler", tpl: map[string]string{"p.html": "<form>\n<select name=\"w\" onchange=\"this.form.submit()\"></select>\n<BUTTON OnClick='go()'>x</BUTTON></form>"},
			want: []string{"p.html:2: inline handler onchange= on <select>", "p.html:3: inline handler onclick= on <button>"}},
		{name: "handler after a template action", tpl: map[string]string{"p.html": `<input type="checkbox" {{ if .On }}checked{{ end }} onchange="f()">`},
			want: []string{"inline handler onchange= on <input>"}},
		{name: "not handlers", tpl: map[string]string{"p.html": `<a data-onclick="x" data-on="1" name="onward" title="set onclick=&quot;x&quot; here" href="/on=1">on = "x"</a>` +
			`<input name="only" value="once='x'"><p>turn it on="yes"</p>`}},
		{name: "javascript link", tpl: map[string]string{"p.html": `<a href=" JavaScript:void(0)">x</a><a href="/javascript:x">y</a>`},
			want: []string{"javascript: URL in href= on <a>"}},
		{name: "handler in a help block", tpl: map[string]string{"p.html": `<script{{ nonceAttr . }} type="text/html" id="h"><a onclick="x()">y</a></script>`},
			want: []string{"inline handler onclick= on <a>"}},
		{name: "handler in an HTML string", tpl: map[string]string{"p.html": "<script{{ nonceAttr . }}>\nvar esc = s => s.replace(/[<&>\"']/g, '');\nel.innerHTML = '<img src=\"' + u + '\" onerror=\"this.src=\\'' + f + '\\'\">';\n</script>"},
			want: []string{"p.html:3: inline handler onerror= in an HTML string"}},
		{name: "handler concatenated onto a string", tpl: map[string]string{"p.html": "<script{{ nonceAttr . }}>h = `<a ${cls} onclick=` + q + '>';</script>"},
			want: []string{"inline handler onclick= in an HTML string"}},
		{name: "not handlers in script", tpl: map[string]string{"p.html": `<script{{ nonceAttr . }}>
var one = '<span>' + a + '</span>', only = "x"; if (a < b && only == "x") { el.onclick = function(){}; b.onload=function(){}; }
es.onmessage = function(e){}; var w = 'onmessage=function(e){' + body + '}'; u = '?onload=cb&render=explicit'; q = 'input[name="only"]';
var d = a / b / c; var s = "it's on" + "=" + '"'; var tl = {title:{{ t .Lang "x" }}, n: {{ .N }} / 2};
</script>`}},
		{name: "partial spliced into a script is read as script", tpl: map[string]string{
			"p.html":       `<script{{ nonceAttr . }}>{{ template "part_js" . }}</script>`,
			"partial.html": `{{ define "part_js" }}for (var i = 0; i<n && on == "x"; i++) { el.onclick = function(){}; }{{ end }}`}},
		{name: "eval and friends", tpl: map[string]string{"p.html": "<script{{ nonceAttr . }}>\neval(x);\nvar f = new Function('a', 'return a');\nsetTimeout(\"go()\", 10);\nel.setAttribute('onclick', 'go()');\ndocument.createElement('script');\n" +
			"// eval(y) in a comment\nvar s = 'eval(z) and setTimeout(\"x\")'; setTimeout(function(){}, 10); medieval(1);\n</script>"},
			want: []string{"p.html:2: eval", "p.html:3: eval", "p.html:4: a timer given a string", "p.html:5: setAttribute of an on* handler", "p.html:6: a script element built by script"}},
		{name: "static scripts", js: map[string]string{
			"popover-pin.js": "var a = 1;\nel.innerHTML = '<a onclick=\"x()\">';\nvar s = document.createElement('script');\n",
			"challenge.js":   "var s = document.createElement('script'); s.nonce = n;\nvar w = 'onmessage=function(e){' + f + '}';\n"},
			want: []string{"popover-pin.js:2: inline handler onclick=", "popover-pin.js:3: a script element built by script"}},
	}
	for _, c := range cases {
		got, err := cspScan(c.tpl, c.js)
		if err != nil {
			t.Errorf("%s: %v", c.name, err)
			continue
		}
		if len(got) != len(c.want) {
			t.Errorf("%s: %d finding(s), want %d:\n  %s", c.name, len(got), len(c.want), strings.Join(got, "\n  "))
			continue
		}
		for i, w := range c.want {
			if !strings.Contains(got[i], w) {
				t.Errorf("%s: finding %d = %q, want it to contain %q", c.name, i, got[i], w)
			}
		}
	}
}
