// Protected paths feature (= transparent PoW / CAPTCHA gate on chosen paths).
//
// Difference from honeypot:
//   - honeypot: "step on the trap → persistent BAN on that IP → affects all subsequent paths"
//   - protected paths: "a visitor reaching here is human-verified.  affects only that path"
//
// Meaning of each mode.  The mode IS the action: it maps 1:1 to a challenge
// chain, with no separate chMode / default-action / rate-limit-linkage layer on
// top (removed in the mode==action redesign).  A mode ending in a CAPTCHA is
// grade-enforced on both wires: a proof-of-work cookie does not satisfy it (see
// $unmask_needs_captcha_grade in http.conf.tmpl and requestNeedsCaptchaGrade).
//   - "pow"              : PoW only → issue _bv.  lightweight; only charges CPU cost
//   - "captcha"          : skip PoW → straight to CAPTCHA → issue _bv.  medium UX cost
//   - "pow_then_captcha" : PoW → CAPTCHA chain → _bv.  strongest; the default
package nginxconf

import (
	"sort"
	"strings"

	"github.com/unmask-sh/unmask/admin/internal/settings"
)

const (
	ProtectedModePoW            = "pow"
	ProtectedModeCaptcha        = "captcha"
	ProtectedModePoWThenCaptcha = "pow_then_captcha"

	// ProtectedModeDefault is the mode a protected path takes when none is
	// stored on the row / preset: the strongest chain (PoW → CAPTCHA).  A
	// protected path is an operator-chosen gate on a sensitive path, so the
	// default leans to maximum protection rather than the lightest option.
	ProtectedModeDefault = ProtectedModePoWThenCaptcha
)

// IsValidProtectedMode: validate a value coming from form / yml.
func IsValidProtectedMode(m string) bool {
	return m == ProtectedModePoW || m == ProtectedModeCaptcha || m == ProtectedModePoWThenCaptcha
}

// ModeEndsInCaptcha reports whether a protected mode terminates in a CAPTCHA
// (captcha / pow_then_captcha).  Such a mode is grade-enforced: only a
// CAPTCHA-grade _bv cookie satisfies it.  "pow" (and any unknown value) do not.
func ModeEndsInCaptcha(mode string) bool {
	return mode == ProtectedModeCaptcha || mode == ProtectedModePoWThenCaptcha
}

// ResolveProtectedMode fills in a blank mode from the operator's tab-level
// default, and the tab default from the shipped floor.  THE single place a
// blank becomes concrete: both wires (the nginx render via
// EffectiveProtectedPathRules, and the daemon via protectedModeForOrig) call
// it, so a path cannot resolve one way for the challenge it is served and
// another for the CAPTCHA grade its cookie must carry.
//
// An explicit mode always wins -- the default only fills a blank.  That is the
// difference from the default_action this replaces, which overrode the row.
func ResolveProtectedMode(mode string, s settings.ProtectedPathsConfig) string {
	if IsValidProtectedMode(mode) {
		return mode
	}
	if IsValidProtectedMode(s.DefaultMode) {
		return s.DefaultMode
	}
	return ProtectedModeDefault
}

// ChModeForProtectedMode maps a protected-path mode to the challenge chain the
// serve path runs for it.  Single source of truth now that mode == action.
func ChModeForProtectedMode(mode string) string {
	switch mode {
	case ProtectedModePoW:
		return settings.RateChallengePoWOnly
	case ProtectedModePoWThenCaptcha:
		return settings.RateChallengePoWThenCaptcha
	default: // captcha + any unexpected value -> a real CAPTCHA (safe floor)
		return settings.RateChallengeCaptchaOnly
	}
}

// ProtectedPathRule: render-time struct that maps to one row in the UI.
//
// Site is the per-row site override: empty = applies to every host (= preset
// rules always come through with Site=""), non-empty = only fires when the
// request's $host equals that value.  The render side splits the slice into
// a global path map + one per-host map and dispatches through $host (same
// pattern as BypassPath).
type ProtectedPathRule struct {
	Pattern string // nginx regex (= without ~^)
	Mode    string // "pow" | "captcha" | "pow_then_captcha"
	Site    string // empty = global; non-empty = exact $host match
}

// ProtectedPathPresetGroup: a preset group of protected paths.  Rules inside
// the group hold {Pattern, Mode} per entry (= captcha for login pages, pow
// for APIs, etc.).
type ProtectedPathPresetGroup struct {
	ID      string
	Label   string
	Rules   []ProtectedPathRule
	AddedIn string
}

// ProtectedPathPresetGroups: typical "you probably want to protect this" path sets.
//
// Default ON / OFF is set in settings.defaults(): "unmask" ships ON because
// it covers unmask's own admin login at the fixed `/unmask/admin/` path --
// no site-layout dependency, and the brand cost of an admin brute-force on
// an anti-bot product is too large to leave to opt-in.  "common-admin" stays
// OFF because it assumes `/wp-admin/` etc. exist on the protected site;
// enabling it without checking the layout would silently CAPTCHA legitimate
// users.
//
// Preset rules ship with a BLANK mode: they follow the tab's DefaultMode (and,
// when that is unset too, ProtectedModeDefault), so an operator who sets one
// default moves the presets with it instead of having to re-pick per preset.
// A preset can still be pinned via ProtectedPaths.PresetMode[id], which wins.
// The floor stays the strongest chain (pow_then_captcha): admin login forms
// expect a human, who clears it once, while a headless PoW-solver hits the
// CAPTCHA wall.
var ProtectedPathPresetGroups = []ProtectedPathPresetGroup{
	{
		ID:    "unmask",
		Label: "unmask itself (gate the /unmask/admin/ login page)",
		Rules: []ProtectedPathRule{
			{Pattern: `^/unmask/admin/`},
		},
	},
	{
		ID:    "common-admin",
		Label: "Common admin / CMS paths (/wp-admin/ /wp-login.php /phpmyadmin/ /admin/ /administrator/ /manager/html)",
		Rules: []ProtectedPathRule{
			{Pattern: `^/wp-admin/`},
			{Pattern: `^/wp-login\.php`},
			{Pattern: `^/phpmyadmin/`},
			{Pattern: `^/admin/`},
			{Pattern: `^/administrator/`},
			{Pattern: `^/manager/html`},
		},
	},
}

// EffectiveProtectedPathRules composes the protected-path rule set the render
// actually enforces: enabled presets plus non-disabled custom rows, deduped on
// (site, pattern) and sorted.  Extracted from the render so the settings UI
// can reason about the same set (the rate-limit tab warns when a deny zone
// overlaps a protected path) without keeping a second copy of the composition
// that would drift.
func EffectiveProtectedPathRules(s settings.Settings) []ProtectedPathRule {
	pp := []ProtectedPathRule{}
	// Dedup key is (site, pattern) so a path can carry different modes per
	// host without one row silently shadowing the other.  Preset rules are
	// always global (Site="").
	ppSeen := map[string]bool{}
	enabledPP := toSet(s.Nginx.ProtectedPaths.EnabledPresets)
	for _, g := range ProtectedPathPresetGroups {
		if !enabledPP[g.ID] {
			continue
		}
		// A preset-level mode override applies to every rule in the group
		// (the UI exposes one mode picker per preset, not per rule).
		override := ""
		if m, ok := s.Nginx.ProtectedPaths.PresetMode[g.ID]; ok && IsValidProtectedMode(m) {
			override = m
		}
		for _, r := range g.Rules {
			pat := trimSpaceAndQuotes(r.Pattern)
			if pat == "" {
				continue
			}
			key := "|" + pat
			if ppSeen[key] {
				continue
			}
			ppSeen[key] = true
			mode := r.Mode
			if override != "" {
				mode = override
			}
			// A preset with no override, or one whose shipped rule carries no
			// mode, falls to the operator's tab default (then the floor).
			mode = ResolveProtectedMode(mode, s.Nginx.ProtectedPaths)
			pp = append(pp, ProtectedPathRule{Pattern: pat, Mode: mode})
		}
	}
	// Custom rows carry a per-row Site (= empty = global, non-empty = only
	// for that $host).
	for _, r := range s.Nginx.ProtectedPaths.Paths {
		if r.Disabled {
			continue
		}
		p := trimSpaceAndQuotes(r.Path)
		site := trimSpaceAndQuotes(r.Site)
		key := site + "|" + p
		if p == "" || ppSeen[key] {
			continue
		}
		ppSeen[key] = true
		mode := ResolveProtectedMode(r.Mode, s.Nginx.ProtectedPaths)
		pp = append(pp, ProtectedPathRule{Pattern: p, Mode: mode, Site: site})
	}
	sort.Slice(pp, func(i, j int) bool {
		if pp[i].Site != pp[j].Site {
			return pp[i].Site < pp[j].Site
		}
		return pp[i].Pattern < pp[j].Pattern
	})
	return pp
}

// ProtectedPatternLiteralPrefix reduces a protected-path pattern (an nginx
// regex, "^/wp-admin/" style) to the literal path prefix it starts with, for
// best-effort overlap checks against the rate-limit zones' plain prefixes.
// The leading "^" is dropped, escaped literals ("\.") are unescaped, and the
// walk stops at the first real metacharacter.  "" means the pattern gives no
// usable literal head (e.g. it does not start at the path root).
func ProtectedPatternLiteralPrefix(pattern string) string {
	p := strings.TrimPrefix(strings.TrimSpace(pattern), "^")
	var b strings.Builder
	for i := 0; i < len(p); i++ {
		c := p[i]
		if c == '\\' && i+1 < len(p) {
			b.WriteByte(p[i+1])
			i++
			continue
		}
		switch c {
		case '.', '*', '+', '?', '(', ')', '[', ']', '{', '}', '|', '$':
			return b.String()
		}
		b.WriteByte(c)
	}
	return b.String()
}
