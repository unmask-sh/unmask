package main

import (
	"fmt"
	"regexp"
	"strings"
)

// Numbered captures under protect.inc.
//
// nginx keeps one set of numbered captures ($1..$9) per request, and every
// regex that matches replaces it -- a regex key of a map included.  unmask's
// maps decide with regex keys, and protect.inc evaluates them in the
// location's rewrite phase (the challenge gate) and its preaccess phase (the
// rate-limit keys, which a server-scope include hands to every location of
// the server).  A regex location that reads $1 after that reads the map's
// captures, not its own: `location ~ ^/api/(.+)$ { include protect.inc;
// proxy_pass http://b/backend/$1; }` sent every request to /backend/, and
// `nginx -t` has nothing to say about it.  A named capture is copied into
// its variable when the location matches and keeps its value.
//
// capturesAtRisk reads an `nginx -T` dump and lists the regex locations that
// read a numbered capture after unmask's maps ran.  In a location that
// includes protect.inc, that is a rewrite-phase directive (return, set) after
// the include and any directive of a later phase (proxy_pass, try_files,
// alias...).  In a location nested in one, and in every location of a server
// that includes it at server scope (a location in a file with no server
// block, as a snippet is, counts when any server-scope include is in the
// dump), the gate runs elsewhere and only the later phases come after the
// rate-limit keys.  The $N of a rewrite and of an `if` with a regex
// condition read their own captures and are left out.

// confNode: one statement of an nginx configuration, with its block.
type confNode struct {
	words    []string
	line     int
	children []confNode
	block    bool
}

// confToken: a word or one of `{` `}` `;`, with the line it starts on.
type confToken struct {
	text  string
	punct bool
	line  int
}

// tokenizeConf splits nginx configuration text into tokens the way nginx
// reads it: `#` starts a comment outside quotes, quotes keep a word whole,
// and `${name}` inside a word does not open a block.
func tokenizeConf(src string) []confToken {
	var out []confToken
	line := 1
	i := 0
	for i < len(src) {
		c := src[i]
		switch c {
		case '\n':
			line++
			i++
		case ' ', '\t', '\r':
			i++
		case '#':
			for i < len(src) && src[i] != '\n' {
				i++
			}
		case '{', '}', ';':
			out = append(out, confToken{text: string(c), punct: true, line: line})
			i++
		case '"', '\'':
			start, q := line, c
			var b strings.Builder
			i++
			for i < len(src) && src[i] != q {
				if src[i] == '\\' && i+1 < len(src) {
					b.WriteByte(src[i])
					i++
				}
				if src[i] == '\n' {
					line++
				}
				b.WriteByte(src[i])
				i++
			}
			i++ // the closing quote
			out = append(out, confToken{text: b.String(), line: start})
		default:
			var b strings.Builder
			for i < len(src) {
				c := src[i]
				if c == ' ' || c == '\t' || c == '\r' || c == '\n' || c == ';' || c == '}' {
					break
				}
				if c == '{' {
					// `${name}` is part of the word; any other `{` opens a block.
					if i == 0 || src[i-1] != '$' {
						break
					}
					for i < len(src) && src[i] != '}' {
						b.WriteByte(src[i])
						i++
					}
				}
				if c == '\\' && i+1 < len(src) {
					b.WriteByte(c)
					i++
				}
				b.WriteByte(src[i])
				i++
			}
			out = append(out, confToken{text: b.String(), line: line})
		}
	}
	return out
}

// parseConf builds the statement tree of one file.  An unbalanced file
// (nginx would refuse it) yields what was read up to the imbalance.
func parseConf(toks []confToken) []confNode {
	pos := 0
	var parse func() []confNode
	parse = func() []confNode {
		var nodes []confNode
		var cur confNode
		for pos < len(toks) {
			t := toks[pos]
			pos++
			if !t.punct {
				if len(cur.words) == 0 {
					cur.line = t.line
				}
				cur.words = append(cur.words, t.text)
				continue
			}
			switch t.text {
			case ";":
				if len(cur.words) > 0 {
					nodes = append(nodes, cur)
				}
				cur = confNode{}
			case "{":
				if len(cur.words) == 0 {
					cur.line = t.line
				}
				cur.block = true
				cur.children = parse()
				nodes = append(nodes, cur)
				cur = confNode{}
			case "}":
				return nodes
			}
		}
		return nodes
	}
	return parse()
}

// dumpFiles splits an `nginx -T` dump into its files: each starts with a
// "# configuration file <path>:" line.
func dumpFiles(dump string) (names, bodies []string) {
	const head = "# configuration file "
	cur, name := []string(nil), ""
	flush := func() {
		if name != "" || len(cur) > 0 {
			names = append(names, name)
			bodies = append(bodies, strings.Join(cur, "\n"))
		}
	}
	for _, ln := range strings.Split(dump, "\n") {
		if strings.HasPrefix(ln, head) {
			flush()
			name = strings.TrimSuffix(strings.TrimSpace(strings.TrimPrefix(ln, head)), ":")
			cur = nil
			continue
		}
		cur = append(cur, ln)
	}
	flush()
	return names, bodies
}

func isProtectInclude(n confNode) bool {
	return !n.block && len(n.words) >= 2 && n.words[0] == "include" && strings.Contains(n.words[1], "protect.inc")
}

// includesProtect: n's block includes protect.inc, nested locations aside.
func includesProtect(children []confNode) bool {
	for _, c := range children {
		if isProtectInclude(c) {
			return true
		}
		if c.block && (len(c.words) == 0 || c.words[0] != "location") && includesProtect(c.children) {
			return true
		}
	}
	return false
}

// locationRegex: the regex of a `location ~ RE` / `~* RE` / `~RE` statement.
func locationRegex(words []string) (string, bool) {
	if len(words) < 2 || words[0] != "location" {
		return "", false
	}
	switch {
	case (words[1] == "~" || words[1] == "~*") && len(words) >= 3:
		return words[2], true
	case strings.HasPrefix(words[1], "~*") && len(words[1]) > 2:
		return words[1][2:], true
	case strings.HasPrefix(words[1], "~") && len(words[1]) > 1:
		return words[1][1:], true
	}
	return "", false
}

// numberedGroups: whether re has a capturing group nginx numbers -- an
// unescaped `(` outside a character class not followed by `?` (named and
// non-capturing groups start with `(?`).
func numberedGroups(re string) bool {
	inClass := false
	for i := 0; i < len(re); i++ {
		switch c := re[i]; {
		case c == '\\':
			i++
		case inClass:
			if c == ']' {
				inClass = false
			}
		case c == '[':
			inClass = true
			// `[]...]` and `[^]...]`: the first `]` is a literal.
			if i+1 < len(re) && re[i+1] == '^' {
				i++
			}
			if i+1 < len(re) && re[i+1] == ']' {
				i++
			}
		case c == '(':
			if i+1 >= len(re) || re[i+1] != '?' {
				return true
			}
		}
	}
	return false
}

var numberedCaptureRef = regexp.MustCompile(`\$\{?[1-9]`)

// rewritePhase: the directives the rewrite module runs, in order, in the
// location's rewrite phase.
var rewritePhase = map[string]bool{"return": true, "set": true, "break": true}

// readsNumbered: the first directive of a location's body that reads a
// numbered capture of the location after unmask's maps ran (see
// capturesAtRisk) -- not a rewrite's own, not one inside an `if` whose
// condition is a regex, not a nested location's.  gateHere: protect.inc is
// included in this location.
func readsNumbered(children []confNode, gateHere bool) (string, bool) {
	passed := false // the include of protect.inc, in the rewrite phase's order
	var scan func(nodes []confNode) (string, bool)
	scan = func(nodes []confNode) (string, bool) {
		for _, c := range nodes {
			if len(c.words) == 0 {
				continue
			}
			if isProtectInclude(c) {
				passed = true
				continue
			}
			switch c.words[0] {
			case "location", "rewrite":
				continue
			case "if":
				cond := strings.Join(c.words[1:], " ")
				if strings.Contains(cond, " ~") || strings.Contains(cond, "~ ") || strings.Contains(cond, "!~") {
					continue
				}
			}
			if c.block {
				if d, ok := scan(c.children); ok {
					return d, true
				}
				continue
			}
			if rewritePhase[c.words[0]] && !(gateHere && passed) {
				continue
			}
			for _, w := range c.words[1:] {
				if numberedCaptureRef.MatchString(w) {
					return c.words[0], true
				}
			}
		}
		return "", false
	}
	return scan(children)
}

// capturesAtRisk: see the comment at the top of the file.
func capturesAtRisk(dump string) []string {
	names, bodies := dumpFiles(dump)
	trees := make([][]confNode, len(bodies))
	serverScope := false
	var walkServers func(nodes []confNode)
	walkServers = func(nodes []confNode) {
		for _, n := range nodes {
			if n.block && len(n.words) > 0 && n.words[0] == "server" {
				for _, c := range n.children {
					if isProtectInclude(c) {
						serverScope = true
					}
				}
			}
			if n.block {
				walkServers(n.children)
			}
		}
	}
	for i, b := range bodies {
		trees[i] = parseConf(tokenizeConf(b))
		walkServers(trees[i])
	}
	var out []string
	var walk func(file string, nodes []confNode, protected, inServer bool)
	walk = func(file string, nodes []confNode, protected, inServer bool) {
		for _, n := range nodes {
			if !n.block || len(n.words) == 0 {
				continue
			}
			switch n.words[0] {
			case "server":
				p := false
				for _, c := range n.children {
					if isProtectInclude(c) {
						p = true
					}
				}
				walk(file, n.children, p, true)
			case "location":
				gateHere := includesProtect(n.children)
				p := protected || gateHere || (!inServer && serverScope)
				if re, ok := locationRegex(n.words); ok && p && numberedGroups(re) {
					if d, ok := readsNumbered(n.children, gateHere); ok {
						out = append(out, fmt.Sprintf("%s:%d `location %s` (%s reads $1..$9)", file, n.line, strings.Join(n.words[1:], " "), d))
					}
				}
				walk(file, n.children, p, inServer)
			default:
				walk(file, n.children, protected, inServer)
			}
		}
	}
	for i := range trees {
		walk(names[i], trees[i], false, false)
	}
	return out
}

// warnNumberedCaptures: the doctor's warning for capturesAtRisk.
func warnNumberedCaptures(dump string, addWarn func(t, m string)) {
	risks := capturesAtRisk(dump)
	if len(risks) == 0 {
		return
	}
	addWarn("nginx numbered captures", fmt.Sprintf("%d regex location(s) read a numbered capture where unmask's maps run first: %s.  "+
		"nginx resets $1..$9 each time a regex key of a map matches, and protect.inc evaluates unmask's maps in these locations, "+
		"so $1 can be empty there (a proxy_pass then goes to the wrong path) while `nginx -t` passes.  Use a named capture, which keeps its value: "+
		"`location ~ ^/api/(?<rest>.+)$ { ... proxy_pass http://backend/$rest; }`.",
		len(risks), strings.Join(risks, "; ")))
}
