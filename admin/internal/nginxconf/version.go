// version.go: semantic-version comparison for admin / preset versions.
//
// Used to compare a preset group's AddedIn against settings.SeenVersion.  Plain
// lexicographic comparison gives "v0.10" < "v0.9", so we int-parse major.minor.
//
// Accepts "v0.1" / "v0.10" / "0.1.0".  Unparseable inputs map to 0,0 (= oldest).
package nginxconf

import (
	"strconv"
	"strings"
)

// VersionLess: true if a < b.  Format: "v?MAJOR.MINOR(.PATCH)?".  Patch is ignored.
func VersionLess(a, b string) bool {
	am, an := parseVer(a)
	bm, bn := parseVer(b)
	if am != bm {
		return am < bm
	}
	return an < bn
}

func parseVer(v string) (int, int) {
	v = strings.TrimSpace(v)
	v = strings.TrimPrefix(v, "v")
	if v == "" {
		return 0, 0
	}
	parts := strings.SplitN(v, ".", 3)
	maj, _ := strconv.Atoi(parts[0])
	var min int
	if len(parts) > 1 {
		min, _ = strconv.Atoi(parts[1])
	}
	return maj, min
}
