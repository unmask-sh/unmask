package nginxconf

import (
	"strings"
	"testing"
)

// The access log names the pass a request rode on, for the daemon's count of
// the distinct passes behind each address: the cookie as carried, admitted
// only once the plugin verified it and only in the cookie's own alphabet, so a
// client-written value cannot write a field of its own into the line.  Ahead
// of ua=, which takes the rest of the line.
func TestLogFormatCarriesTheVerifiedPassCookie(t *testing.T) {
	httpInc, _, _ := renderIncs(t, nil)
	for _, want := range []string{
		`map "$unmask_bv_kind:$cookie__bv" $unmask_bv_log {`,
		`"~^[a-z]+:(?<bv_log_v>[0-9A-Za-z.~]{1,512})$"  $bv_log_v;`,
		` rh=$unmask_ref_host bv=$unmask_bv_log mo=$unmask_module_id ua=$http_user_agent'`,
	} {
		if !strings.Contains(httpInc, want) {
			t.Errorf("http.inc lacks %q", want)
		}
	}
}
