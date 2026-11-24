package nginxconf

import (
	"strings"
	"testing"
)

// The access log carries what the module nginx loaded says it verifies
// (mc=, its $unmask_module_caps), which the daemon reads before it issues a
// pass in a form an older module refuses.  A module from before 0.1.58 has
// no such variable, and a reload keeps the module nginx started with: the
// name is declared once, empty, ahead of the log format that reads it, so
// the configuration loads there too and its lines answer for nothing.  The
// same with no module at all (the fail-safe's render).
func TestLogFormatCarriesWhatTheModuleVerifies(t *testing.T) {
	for _, degraded := range []bool{false, true} {
		_, files := renderFiles(t, degraded, withLogAndBans)
		http := files["http.inc"]
		decl := strings.Index(http, "map \"\" $unmask_module_caps {\n    default \"\";\n}")
		logf := strings.Index(http, "\nlog_format unmask_minimal '")
		if decl < 0 || logf < 0 || decl > logf {
			t.Errorf("degraded=%v: $unmask_module_caps is not declared ahead of the log format (declaration at %d, log format at %d)", degraded, decl, logf)
		}
		if n := strings.Count(http, "$unmask_module_caps {"); n != 1 {
			t.Errorf("degraded=%v: $unmask_module_caps is declared %d times, want once (a second is a duplicate nginx refuses)", degraded, n)
		}
		if !strings.Contains(http, " mo=$unmask_module_id mc=$unmask_module_caps why=$unmask_why_log lp=$unmask_lp_log ua=$http_user_agent'") {
			t.Errorf("degraded=%v: the log format does not carry mc= after mo= and ahead of why=, lp= and ua=", degraded)
		}
	}
}
