// version.go: semantic-version comparison for admin / preset versions.
//
// Used to compare a preset group's AddedIn against settings.SeenVersion.  Plain
// lexicographic comparison gives "v0.10" < "v0.9", so we int-parse
// major.minor.patch.  Releases step by patch (0.0.1), so every segment counts;
// preset AddedIn values are written in full "v0.1.7" form.
//
// Accepts "v0.1" / "v0.10" / "0.1.0"; a present segment must be numeric.
// Unparseable inputs map to 0,0,0 (= oldest).
package nginxconf

import (
	"strconv"
	"strings"
)

// VersionLess: true if a < b.  Format: "v?MAJOR.MINOR(.PATCH)?".  A missing
// MINOR or PATCH counts as 0, so releases that step by patch ("v0.1.7") still
// order correctly against the previous tag ("v0.1.6").
func VersionLess(a, b string) bool {
	am, an, ap, _ := parseVer(a)
	bm, bn, bp, _ := parseVer(b)
	if am != bm {
		return am < bm
	}
	if an != bn {
		return an < bn
	}
	return ap < bp
}

// VersionParseable: does v parse as "v?MAJOR(.MINOR)?(.PATCH)?" with numeric
// MAJOR/MINOR?  Dev / source builds stamp a git hash ("6f94983") as the admin
// version; such a string must not be mistaken for a release number.
func VersionParseable(v string) bool {
	_, _, _, ok := parseVer(v)
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

func parseVer(v string) (maj, min, patch int, ok bool) {
	v = strings.TrimSpace(v)
	v = strings.TrimPrefix(v, "v")
	// Strip a SemVer pre-release / build suffix ("0.1.7-dev-3a819a7", "0.1.7+meta")
	// so a dev / release-candidate build whose Version carries a git hash still
	// orders by its MAJOR.MINOR.PATCH release number.  The remaining segments must
	// still each be strictly numeric — a bare git hash ("6f94983", no separator)
	// keeps failing, so it is never mistaken for a release.
	if i := strings.IndexAny(v, "-+"); i >= 0 {
		v = v[:i]
	}
	if v == "" {
		return 0, 0, 0, false
	}
	parts := strings.SplitN(v, ".", 3)
	maj, err := strconv.Atoi(parts[0])
	if err != nil {
		return 0, 0, 0, false
	}
	if len(parts) > 1 {
		var minErr error
		if min, minErr = strconv.Atoi(parts[1]); minErr != nil {
			return maj, 0, 0, false
		}
	}
	if len(parts) > 2 {
		var pErr error
		if patch, pErr = strconv.Atoi(parts[2]); pErr != nil {
			return maj, min, 0, false
		}
	}
	return maj, min, patch, true
}
