package handlers

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/unmask-sh/unmask/admin/internal/settings"
)

// A JA4 pattern anchored with `$` from the hunt page made a verdict name
// ending in `$`, which nginx reads as a variable in the $ja4_verdict map:
// the configuration was refused.  The name now keeps the pattern's letters
// and digits only, and the rule reaches http.inc.
func TestHuntJA4VerdictNameHasNoDollar(t *testing.T) {
	h := ruleTestHandler(t)
	req := httptest.NewRequest(http.MethodPost, "/unmask/admin/hunt/action", nil)
	const pattern = "^t13d1516h2_8daaf6152771_b0da82dd1658$"
	if err := h.appendJA4Bot(req, pattern, "from the ranking", "admin", 1); err != nil {
		t.Fatalf("append: %v", err)
	}
	cur, err := settings.Load(h.ConfigPath)
	if err != nil {
		t.Fatal(err)
	}
	extra := cur.Nginx.JA4Verdicts.Extra
	if len(extra) != 1 {
		t.Fatalf("%d rows", len(extra))
	}
	if v := extra[0].Verdict; !settings.ValidVerdictLabel(v) || strings.ContainsAny(v, "$^") {
		t.Errorf("verdict name %q", v)
	}
	b, err := os.ReadFile(filepath.Join(h.cfg().Nginx.OutputDir, "http.inc"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(b), `"`+extra[0].Verdict+`";`) {
		t.Errorf("the rule %q is not in http.inc", extra[0].Verdict)
	}
}
