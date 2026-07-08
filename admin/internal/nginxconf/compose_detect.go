package nginxconf

import (
	"context"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/unmask-sh/unmask/admin/internal/settings"
)

// dryRunSupported caches whether the host nginx supports limit_req_dry_run
// (nginx >= 1.17.1), which the compose flow depends on.  Set once at process
// start via SetDryRunSupported (serve / the render + doctor CLIs); it defaults
// to false so a process that never probes -- a unit test, or an admin-only box
// with no local nginx -- resolves "auto" to the classic flow, which is valid on
// every nginx.  Render never execs nginx itself (it runs on the hot settings-
// save path), so the probe is a startup-once fact fed in through this var.
var dryRunSupported atomic.Bool

// SetDryRunSupported records the startup nginx-capability probe.  Call it once
// before any Render; concurrent Render reads then see the resolved value.
func SetDryRunSupported(ok bool) { dryRunSupported.Store(ok) }

// DryRunSupported reports the cached probe result (false until SetDryRunSupported
// runs).
func DryRunSupported() bool { return dryRunSupported.Load() }

// nginxVerRe pulls the X.Y.Z out of `nginx version: nginx/1.10.3` (written to
// stderr, so callers use CombinedOutput).
var nginxVerRe = regexp.MustCompile(`nginx/(\d+)\.(\d+)\.(\d+)`)

// DetectDryRunSupport probes the host nginx (`nginx -v`) and reports whether it
// is >= 1.17.1 -- the release that added limit_req_dry_run, which compose mode
// needs.  Returns (supported, version, detected).  detected is false when nginx
// is not on PATH (an admin-only box / central forward-auth) or its version is
// unparseable; the caller treats "not detected" as unknown → classic.  Mirrors
// doctor's exec.LookPath("nginx") discovery.
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
// whether it is >= 1.17.1.  Split out from DetectDryRunSupport so the version
// gate is unit-testable without a host nginx.  ok=false when no version matches.
func parseNginxDryRun(nginxVOutput string) (supported bool, version string, ok bool) {
	m := nginxVerRe.FindStringSubmatch(nginxVOutput)
	if m == nil {
		return false, "", false
	}
	maj, _ := strconv.Atoi(m[1])
	min, _ := strconv.Atoi(m[2])
	patch, _ := strconv.Atoi(m[3])
	code := maj*1_000_000 + min*1_000 + patch
	return code >= 1_017_001, m[1] + "." + m[2] + "." + m[3], true
}

// ComposeCapable resolves whether the rendered config uses the compose flow
// (limit_req in dry-run + the plugin's ACCESS-phase composition) instead of the
// classic error_page-429 + REWRITE-phase-rewrite flow.  Nginx.RateComposeMode
// overrides; "" / "auto" falls back to the cached startup probe (DryRunSupported).
// Compose requires nginx 1.17.1+ (limit_req_dry_run); emitting it on older nginx
// fails `nginx -t`, so "auto" only turns it on when the probe confirmed support.
func ComposeCapable(s settings.Settings) bool {
	switch strings.ToLower(strings.TrimSpace(s.Nginx.RateComposeMode)) {
	case "always":
		return true
	case "never":
		return false
	default: // "" / "auto"
		return DryRunSupported()
	}
}

// HasDenyRateZone reports whether the default zone or any named zone resolves to
// the "deny" action.  A deny zone fully composes (deny wins over a challenge)
// only in compose mode; in classic it hard-blocks un-challenged traffic but a
// challenged client is challenged, not denied -- so `HasDenyRateZone && !ComposeCapable`
// is the "deny zone can't fully enforce on this nginx" warning condition.
func HasDenyRateZone(s settings.Settings) bool {
	if s.RateLimit.Default.ResolvedChallengeMode() == settings.RateChallengeDeny {
		return true
	}
	for _, z := range s.RateLimit.Zones {
		if z.ResolvedChallengeMode() == settings.RateChallengeDeny {
			return true
		}
	}
	return false
}
