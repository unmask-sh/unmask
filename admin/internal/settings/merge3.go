package settings

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"

	"gopkg.in/yaml.v3"
)

// Version names one saved form of the settings -- SavedYAML's text -- by
// the first 16 hex digits of its SHA-256.  A settings page carries the
// version it showed, so a save from it can tell whether the settings moved
// since the page was opened.
func Version(savedYAML string) string {
	sum := sha256.Sum256([]byte(savedYAML))
	return hex.EncodeToString(sum[:8])
}

// Merge3 merges two edits made from one saved form of the settings, all three
// as SavedYAML writes them: base, what a page showed; ours, base as that
// page's save leaves it; theirs, the settings as they are now.  Key by key,
// down the mappings: a value only one side changed takes that side's, one
// both changed alike takes it, one both changed differently is a conflict,
// and its dotted path is returned.  A list, and any other value that is not
// a mapping, is one value: two edits of one list conflict even when they
// touched different rows.  With a conflict, merged is "".
//
// ours may also be theirs with the page's form applied (what a save does,
// under the settings lock): a value the form does not carry is theirs on
// both sides, and so comes out theirs.
func Merge3(base, ours, theirs string) (merged string, conflicts []string, err error) {
	var b, o, t yaml.Node
	for _, in := range []struct {
		text string
		node *yaml.Node
	}{{base, &b}, {ours, &o}, {theirs, &t}} {
		if err := yaml.Unmarshal([]byte(in.text), in.node); err != nil {
			return "", nil, err
		}
	}
	m := mergeNodes("", docRoot(&b), docRoot(&o), docRoot(&t), &conflicts)
	if len(conflicts) > 0 {
		return "", conflicts, nil
	}
	if m == nil {
		return "", nil, nil
	}
	out, err := yaml.Marshal(m)
	if err != nil {
		return "", nil, err
	}
	return string(out), nil, nil
}

// docRoot: the top node of a parsed document; nil for an empty one.
func docRoot(n *yaml.Node) *yaml.Node {
	if n.Kind == yaml.DocumentNode {
		if len(n.Content) == 0 {
			return nil
		}
		return n.Content[0]
	}
	if n.Kind == 0 {
		return nil
	}
	return n
}

func mergeNodes(path string, b, o, t *yaml.Node, conflicts *[]string) *yaml.Node {
	switch {
	case nodesEqual(o, b):
		return t
	case nodesEqual(t, b):
		return o
	case nodesEqual(o, t):
		return o
	}
	// Both sides changed it, differently.  Two mappings (base one too, or
	// absent) are merged key by key; anything else is a conflict here.
	if isMapping(o) && isMapping(t) && (b == nil || isMapping(b)) {
		out := &yaml.Node{Kind: yaml.MappingNode, Tag: t.Tag, Style: t.Style}
		for _, k := range mergedKeys(t, o) {
			v := mergeNodes(joinPath(path, k), mapValue(b, k), mapValue(o, k), mapValue(t, k), conflicts)
			if v != nil {
				out.Content = append(out.Content, &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: k}, v)
			}
		}
		return out
	}
	if path == "" {
		path = "(the whole file)"
	}
	*conflicts = append(*conflicts, path)
	return t
}

func isMapping(n *yaml.Node) bool { return n != nil && n.Kind == yaml.MappingNode }

// mergedKeys: theirs' keys in theirs' order, then the keys only ours has, in
// ours' order -- the file keeps the layout it has now.
func mergedKeys(t, o *yaml.Node) []string {
	seen := map[string]bool{}
	var keys []string
	for _, m := range []*yaml.Node{t, o} {
		for i := 0; i+1 < len(m.Content); i += 2 {
			k := m.Content[i].Value
			if !seen[k] {
				seen[k] = true
				keys = append(keys, k)
			}
		}
	}
	return keys
}

// mapValue: the value under key k in mapping m, nil when m is nil or has no
// such key.
func mapValue(m *yaml.Node, k string) *yaml.Node {
	if m == nil {
		return nil
	}
	for i := 0; i+1 < len(m.Content); i += 2 {
		if m.Content[i].Value == k {
			return m.Content[i+1]
		}
	}
	return nil
}

func joinPath(path, k string) string {
	if path == "" {
		return k
	}
	return path + "." + k
}

// nodesEqual compares two values by what they say -- kind, tag, scalar text,
// children in order -- not by how they are written (quotes, layout,
// comments).  SavedYAML writes a mapping's keys in one order every time, so
// the order is part of the comparison.
func nodesEqual(x, y *yaml.Node) bool {
	if x == nil || y == nil {
		return x == nil && y == nil
	}
	if x.Kind == yaml.AliasNode && x.Alias != nil {
		x = x.Alias
	}
	if y.Kind == yaml.AliasNode && y.Alias != nil {
		y = y.Alias
	}
	if x.Kind != y.Kind {
		return false
	}
	switch x.Kind {
	case yaml.ScalarNode:
		return x.Value == y.Value && strings.EqualFold(x.ShortTag(), y.ShortTag())
	case yaml.MappingNode, yaml.SequenceNode, yaml.DocumentNode:
		if len(x.Content) != len(y.Content) {
			return false
		}
		for i := range x.Content {
			if !nodesEqual(x.Content[i], y.Content[i]) {
				return false
			}
		}
		return true
	}
	return false
}
