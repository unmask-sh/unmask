package settings

import "strings"

// A JA4 verdict's name is written as a quoted value of nginx's $ja4_verdict
// map, and nginx reads a `$` in a map value as a variable: a name ending in
// `$` -- what the hunt page made of a pattern anchored with `$` -- made
// nginx refuse the configuration ("invalid variable name"), and `$name`
// inside one would read another variable.  A quote or a backslash would end
// the value.

// ValidVerdictLabel: whether name can be a JA4 verdict's name -- not empty,
// none of `"` `\` `$` and no control character.
func ValidVerdictLabel(name string) bool {
	if name == "" || strings.ContainsAny(name, "\"\\$") {
		return false
	}
	for _, c := range name {
		if c < 0x20 || c == 0x7f {
			return false
		}
	}
	return true
}
