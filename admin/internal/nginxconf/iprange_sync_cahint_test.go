package nginxconf

import (
	"strings"
	"testing"
)

// annotateSyncError must turn a raw TLS-trust failure (common on EOL distros
// whose CA bundle predates the feed's Let's Encrypt root) into an operator-
// actionable message, while leaving every other error untouched.
func TestAnnotateSyncError(t *testing.T) {
	certErrs := []string{
		`http: Get "https://unmask.sh/dl/feed/iprange/bypass-iprange-all.json": tls: failed to verify certificate: x509: certificate signed by unknown authority`,
		`x509: certificate has expired or is not yet valid`,
		`Get "https://unmask.sh/...": tls: failed to verify certificate`,
	}
	for _, e := range certErrs {
		got := annotateSyncError(e)
		if !strings.HasPrefix(got, e) {
			t.Errorf("must keep the original error as prefix:\n  %s", got)
		}
		if !strings.Contains(got, "ca-certificates") || !strings.Contains(got, "ISRG") {
			t.Errorf("cert error not annotated with the CA hint:\n  in:  %s\n  out: %s", e, got)
		}
	}

	plainErrs := []string{
		`http: Get "https://unmask.sh/...": dial tcp: connection refused`,
		`unexpected status 503`,
		`schema validation failed: prefix count dropped 60%`,
	}
	for _, e := range plainErrs {
		if got := annotateSyncError(e); got != e {
			t.Errorf("non-cert error must pass through unchanged:\n  in:  %s\n  out: %s", e, got)
		}
	}
}
