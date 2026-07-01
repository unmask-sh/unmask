package nginxconf

import (
	"os"
	"path/filepath"
	"strings"
)

// RenderedBVSecret reads <outDir>/http.inc and returns the bv_secret value
// baked into its `unmask_bv_secret "...";` directive, or "" when the file or
// the directive is absent (= forward-auth render, fresh install, or a
// plugin-less http.inc).
//
// Comparing it against the daemon's config secret detects a stale render whose
// secret no longer matches what the daemon signs _bv cookies with: the native
// plugin verifies against http.inc's secret, so a mismatch means every cookie
// is rejected and the visitor loops on the challenge — the 2026-06-08 incident
// root cause, which went unnoticed for hours because nothing surfaced it.
func RenderedBVSecret(outDir string) string {
	if outDir == "" {
		outDir = "/var/lib/unmask/nginx"
	}
	body, err := os.ReadFile(filepath.Join(outDir, "http.inc"))
	if err != nil {
		return ""
	}
	return extractBVSecretDirective(string(body))
}

// extractBVSecretDirective parses the value out of `unmask_bv_secret "...";`.
// String scan rather than a regexp: the directive format is fixed and this
// runs on a hot-ish startup path.
func extractBVSecretDirective(httpInc string) string {
	const key = "unmask_bv_secret"
	i := strings.Index(httpInc, key)
	if i < 0 {
		return ""
	}
	rest := httpInc[i+len(key):]
	q1 := strings.IndexByte(rest, '"')
	if q1 < 0 {
		return ""
	}
	rest = rest[q1+1:]
	q2 := strings.IndexByte(rest, '"')
	if q2 < 0 {
		return ""
	}
	return rest[:q2]
}

// BVSecretDesynced reports whether the rendered http.inc carries a bv_secret
// that disagrees with configSecret.  False when either secret is empty or the
// render is absent (nothing to compare) — only a concrete mismatch is a
// desync.  Shared by `unmask doctor` and the daemon's startup self-check.
func BVSecretDesynced(outDir, configSecret string) bool {
	if strings.TrimSpace(configSecret) == "" {
		return false
	}
	rendered := RenderedBVSecret(outDir)
	return rendered != "" && rendered != configSecret
}
