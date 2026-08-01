package nginxconf

import (
	"context"
	"fmt"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/unmask-sh/unmask/admin/internal/settings"
)

// dryRunSupported caches whether the host nginx can run the compose flow.  That
// needs BOTH the limit_req_dry_run directive (nginx >= 1.17.1) AND the
// r->main->limit_req_status field the module reads to route over-cap requests
// (nginx >= 1.17.6) -- so the effective gate is 1.17.6, matching the module's
// `#if (nginx_version >= 1017006)`.  Set once at process start via
// SetDryRunSupported (serve / the render + doctor CLIs); it defaults to false so
// a process that never probes -- a unit test, or an admin-only box with no local
// nginx -- resolves "auto" to the classic flow, which is valid on every nginx.
// Render never execs nginx itself (it runs on the hot settings-save path), so
// the probe is a startup-once fact fed in through this var.  Because it is cached
// for the process lifetime, an in-place nginx upgrade that crosses the 1.17.6
// boundary (e.g. 1.16 → 1.18) under a long-running daemon is not picked up until
// unmask restarts; restart unmask after upgrading nginx so the next Render
// re-resolves the compose flow.
var dryRunSupported atomic.Bool

// SetDryRunSupported records the startup nginx-capability probe.  Call it once
// before any Render; concurrent Render reads then see the resolved value.
func SetDryRunSupported(ok bool) { dryRunSupported.Store(ok) }

// DryRunSupported reports the cached probe result (false until SetDryRunSupported
// runs).
func DryRunSupported() bool { return dryRunSupported.Load() }

// The compose gate: the r->main->limit_req_status field the module reads landed
// in nginx 1.17.6 (the limit_req_dry_run DIRECTIVE is older, 1.17.1 -- which is
// why 1.17.1-1.17.5 passes `nginx -t` yet cannot enforce; see DiagnoseComposeMode).
// Keep composeMinNginxCode in step with the module's `#if (nginx_version >= 1017006)`.
const (
	composeMinNginxCode    = 1_017_006
	composeMinNginxVersion = "1.17.6"
	dryRunDirectiveCode    = 1_017_001 // limit_req_dry_run exists from here
)

// nginxVerRe pulls the X.Y.Z out of `nginx version: nginx/1.10.3` (written to
// stderr, so callers use CombinedOutput).
var nginxVerRe = regexp.MustCompile(`nginx/(\d+)\.(\d+)\.(\d+)`)

// nginxVersionCode parses "X.Y.Z" (as produced by parseNginxDryRun) back into
// the comparable code; ok=false when the string is not that shape.
func nginxVersionCode(ver string) (int, bool) {
	m := regexp.MustCompile(`^(\d+)\.(\d+)\.(\d+)$`).FindStringSubmatch(ver)
	if m == nil {
		return 0, false
	}
	maj, _ := strconv.Atoi(m[1])
	min, _ := strconv.Atoi(m[2])
	patch, _ := strconv.Atoi(m[3])
	return maj*1_000_000 + min*1_000 + patch, true
}

// DetectDryRunSupport probes the host nginx (`nginx -v`) and reports whether it
// is >= 1.17.6 -- the release whose r->main->limit_req_status field the compose
// module reads (the limit_req_dry_run directive itself is 1.17.1, but reading
// the field is what compose needs; see the module's `#if (nginx_version >=
// 1017006)`).  Returns (supported, version, detected).  detected is false when
// nginx is not on PATH (an admin-only box / central forward-auth) or its version
// is unparseable; the caller treats "not detected" as unknown → classic.
// Mirrors doctor's exec.LookPath("nginx") discovery.
func DetectDryRunSupport() (supported bool, version string, detected bool) {
	bin, err := exec.LookPath("nginx")
	if err != nil {
		return false, "", false
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, bin, "-v").CombinedOutput()
	if err != nil {
		return false, "", false
	}
	return parseNginxDryRun(string(out))
}

// parseNginxDryRun pulls the version out of an `nginx -v` line and reports
// whether it is >= 1.17.6 (the compose gate; see DetectDryRunSupport).  Split
// out so the version gate is unit-testable without a host nginx.  ok=false when
// no version matches.
func parseNginxDryRun(nginxVOutput string) (supported bool, version string, ok bool) {
	m := nginxVerRe.FindStringSubmatch(nginxVOutput)
	if m == nil {
		return false, "", false
	}
	maj, _ := strconv.Atoi(m[1])
	min, _ := strconv.Atoi(m[2])
	patch, _ := strconv.Atoi(m[3])
	code := maj*1_000_000 + min*1_000 + patch
	return code >= composeMinNginxCode, m[1] + "." + m[2] + "." + m[3], true
}

// normalizeComposeMode lower/trims nginx.rate_compose_mode to its canonical
// form and reports whether it was a recognized value.  "" maps to "auto".  An
// unrecognized value returns ("auto", false) so callers still resolve sensibly
// (auto) while a diagnostic can flag the typo -- see DiagnoseComposeMode.
func normalizeComposeMode(raw string) (mode string, known bool) {
	switch m := strings.ToLower(strings.TrimSpace(raw)); m {
	case "", "auto":
		return "auto", true
	case "always", "never":
		return m, true
	default:
		return "auto", false
	}
}

// ComposeCapable resolves whether the rendered config uses the compose flow
// (limit_req in dry-run + the plugin's ACCESS-phase composition) instead of the
// classic error_page-429 + REWRITE-phase-rewrite flow.  Nginx.RateComposeMode
// overrides; "" / "auto" (and any unrecognized value) falls back to the cached
// startup probe (DryRunSupported).  Compose requires nginx 1.17.6+ (the
// r->main->limit_req_status field the module reads); emitting it on older nginx
// fails `nginx -t`, so "auto" only turns it on when the probe confirmed support.
func ComposeCapable(s settings.Settings) bool {
	switch mode, _ := normalizeComposeMode(s.Nginx.RateComposeMode); mode {
	case "always":
		return true
	case "never":
		return false
	default: // "auto"
		return DryRunSupported()
	}
}

// HasDenyRateZone reports whether the default zone or any RENDERED named zone
// resolves to the "deny" action.  A deny zone fully composes (deny wins over a
// challenge) only in compose mode; in classic it hard-blocks un-challenged
// traffic but a challenged client is challenged, not denied -- so
// `HasDenyRateZone && !ComposeCapable` is the "deny zone can't fully enforce on
// this nginx" warning condition.  It must count only zones Render actually emits
// or the warning fires for a phantom zone: Render (render.go) skips a zone whose
// name is blank, so this does too.  Known limitation: render also dedupes zones
// whose RENDERED name collides (with each other or the default zone); a deny
// zone dropped by that dedupe still counts here, so a pathological name
// collision can produce a phantom deny report.  Replicating the rendered-name
// simulation would duplicate render.go's naming logic, so it is accepted.
func HasDenyRateZone(s settings.Settings) bool {
	for _, row := range s.RateLimit.DefaultAxisRows() {
		if !row.On {
			continue
		}
		mode := row.ChallengeMode
		if !settings.IsValidRateChallengeMode(mode) {
			// "" inherits: the primary resolves to the recommended chain, a
			// non-primary row to the primary's mode -- either way the deny
			// case is what matters here, so resolve through the primary.
			mode = s.RateLimit.Default.ResolvedChallengeMode()
		}
		if mode == settings.RateChallengeDeny {
			return true
		}
	}
	for _, z := range s.RateLimit.Zones {
		if z.Disabled || strings.TrimSpace(z.Name) == "" {
			continue // never rendered -> must not drive the warning
		}
		if z.ResolvedChallengeMode() == settings.RateChallengeDeny {
			return true
		}
	}
	return false
}

// ComposeDiagLevel ranks a compose-mode diagnosis so each caller maps it to its
// own sink (serve logs Warn/Error; doctor emits OK/Warn/Error checks).
type ComposeDiagLevel int

const (
	ComposeDiagOK ComposeDiagLevel = iota
	ComposeDiagWarn
	ComposeDiagError
)

// ComposeDiag is one resolved compose-mode diagnosis.  Level OK with an empty
// Message means "nothing to report".
type ComposeDiag struct {
	Level   ComposeDiagLevel
	Label   string // short check label (doctor)
	Message string // operator-facing detail
}

// DiagnoseComposeMode classifies the resolved rate-composition situation for
// operator reporting, so serve and doctor share one decision instead of
// duplicating the switch.  ngxVer/detected/dryOK come from DetectDryRunSupport
// (detected=false when no local nginx; ngxVer is "" then).  It attributes the
// classic-flow fallback to its ACTUAL cause -- operator choice (never), an
// absent nginx (admin-only host), or an old nginx -- rather than always blaming
// the nginx version.
func DiagnoseComposeMode(s settings.Settings, ngxVer string, detected, dryOK bool) ComposeDiag {
	mode, known := normalizeComposeMode(s.Nginx.RateComposeMode)

	// Resolve capability from the passed probe (not the global cache) so the
	// message can explain WHY; agrees with ComposeCapable at runtime.
	capable := mode == "always" || (mode == "auto" && detected && dryOK)
	deny := HasDenyRateZone(s)

	if !known {
		msg := fmt.Sprintf(
			"unrecognized nginx.rate_compose_mode %q — treating as \"auto\"; valid values are auto, always, never",
			s.Nginx.RateComposeMode)
		// The typo must not SUPPRESS the deny diagnosis the old code emitted:
		// with a deny zone stuck on the classic flow, say so in the same breath.
		if deny && !capable {
			msg += fmt.Sprintf("; note: a \"deny\" rate zone is set but the classic flow is active (%s) — deny hard-blocks un-challenged traffic but can't preempt a protected-path challenge",
				composeClassicReason(mode, ngxVer, detected))
		}
		return ComposeDiag{ComposeDiagWarn, "rate compose mode", msg}
	}

	switch {
	case mode == "always" && detected && !dryOK:
		// Two distinct failure shapes below the gate.  Before 1.17.1 the
		// limit_req_dry_run directive does not exist, so `nginx -t` rejects the
		// rendered config outright.  On 1.17.1-%s the directive parses and the
		// config LOADS — but the module's compose branch is compiled out
		// (needs the 1.17.6 limit_req_status field), so limit_req counts in
		// dry-run and never rejects: the rate limit / deny zone silently
		// enforces nothing.  Saying "nginx -t fails" there would send the
		// operator to a passing nginx -t and get the ERROR dismissed.
		if code, ok := nginxVersionCode(ngxVer); ok && code >= dryRunDirectiveCode {
			return ComposeDiag{ComposeDiagError, "rate compose", fmt.Sprintf(
				"nginx.rate_compose_mode=always but nginx %s is < %s — the config loads (`nginx -t` passes) yet the module cannot read limit_req_status there, so limit_req runs in dry-run and the rate limit / deny zone enforces NOTHING; set rate_compose_mode=auto/never or upgrade nginx",
				ngxVer, composeMinNginxVersion)}
		}
		return ComposeDiag{ComposeDiagError, "rate compose", fmt.Sprintf(
			"nginx.rate_compose_mode=always but nginx %s is < %s — the rendered limit_req_dry_run fails `nginx -t`, so nginx won't (re)load this config; set rate_compose_mode=auto/never or upgrade nginx",
			ngxVer, composeMinNginxVersion)}
	case !capable && deny:
		return ComposeDiag{ComposeDiagWarn, "rate deny zone", fmt.Sprintf(
			"a \"deny\" rate zone is set but the classic flow is active (%s) — deny hard-blocks un-challenged traffic but can't preempt a protected-path challenge; %s",
			composeClassicReason(mode, ngxVer, detected), composeClassicRemedy(mode))}
	case capable && deny:
		return ComposeDiag{ComposeDiagOK, "rate deny zone", "compose active (deny preempts a challenge)"}
	}
	return ComposeDiag{Level: ComposeDiagOK}
}

// composeClassicReason names why the classic flow is active (deny can't compose).
func composeClassicReason(mode, ngxVer string, detected bool) string {
	switch {
	case mode == "never":
		return "nginx.rate_compose_mode=never"
	case !detected:
		return "nginx not detected on PATH (admin-only host?)"
	default: // auto + detected + old
		return "nginx " + ngxVer + " is < " + composeMinNginxVersion
	}
}

// composeClassicRemedy suggests the fix matching composeClassicReason.
func composeClassicRemedy(mode string) string {
	if mode == "never" {
		return "set rate_compose_mode=auto/always for full deny composition"
	}
	return "upgrade nginx to " + composeMinNginxVersion + "+ (or set rate_compose_mode) for full deny composition"
}
