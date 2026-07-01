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
	am, an, _ := parseVer(a)
	bm, bn, _ := parseVer(b)
	if am != bm {
		return am < bm
	}
	return an < bn
}

// VersionParseable: does v parse as "v?MAJOR(.MINOR)?(.PATCH)?" with numeric
// MAJOR/MINOR?  Dev / source builds stamp a git hash ("6f94983") as the admin
// version; such a string must not be mistaken for a release number.
func VersionParseable(v string) bool {
	_, _, ok := parseVer(v)
	return ok
}

// PresetIsNew: should the preset added in addedIn be treated as
// not-yet-reviewed (= NEW badge, forced-OFF checkbox, skipped by renders) for
// an operator whose last settings save recorded seenVer?
//
// A seenVer that does not parse is NOT "very old": settings save stamps
// "v"+Version, so a dev / source build writes "v<git-hash>" here.  Mapping
// that to v0.0 would flag every preset as new and silently drop
// operator-enabled presets from the rendered conf (JA4 verdicts, honeypot,
// bypass paths).  Treat an unparseable seenVer as "runs tip" instead:
// nothing is new.
func PresetIsNew(seenVer, addedIn string) bool {
	if !VersionParseable(seenVer) {
		return false
	}
	return VersionLess(seenVer, addedIn)
}

func parseVer(v string) (maj, min int, ok bool) {
	v = strings.TrimSpace(v)
	v = strings.TrimPrefix(v, "v")
	if v == "" {
		return 0, 0, false
	}
	parts := strings.SplitN(v, ".", 3)
	maj, err := strconv.Atoi(parts[0])
	if err != nil {
		return 0, 0, false
	}
	if len(parts) > 1 {
		var minErr error
		if min, minErr = strconv.Atoi(parts[1]); minErr != nil {
			return maj, 0, false
		}
	}
	return maj, min, true
}
