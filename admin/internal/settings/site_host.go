package settings

import (
	"regexp"
	"strings"
)

// A per-site rule's Site column becomes a key of nginx's host maps
// (`map $host ... { "<site>" ...; }`), and only a host name works there.
// Saved as typed, a value with a quote or a backslash broke the line -- a
// quoted name made the rule apply to every host, a trailing backslash made
// `nginx -t` fail -- and nginx reads a few words in a map's key position as
// its own: `default` became a second default ("duplicate default map
// parameter"), `include` opened a file.  The scope picker calls the default
// scope "default", so that one is easy to type.

// siteHostRe: a host name as $host carries it (no port), or an IP literal.
var siteHostRe = regexp.MustCompile(`^(?:[A-Za-z0-9_](?:[A-Za-z0-9_.-]*[A-Za-z0-9_])?|\[[0-9A-Fa-f:.]+\])$`)

// mapReservedWords: what nginx's map reads as a parameter in the key
// position, quoted or not.
var mapReservedWords = map[string]bool{"default": true, "include": true, "hostnames": true, "volatile": true}

// ValidSiteHost: whether site can key a host map -- a host name or an IP
// literal, at most 253 bytes, not one of the words map reserves.
func ValidSiteHost(site string) bool {
	if len(site) == 0 || len(site) > 253 || !siteHostRe.MatchString(site) {
		return false
	}
	return !mapReservedWords[strings.ToLower(site)]
}
