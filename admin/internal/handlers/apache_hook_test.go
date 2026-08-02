package handlers

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// The Apache hook is Lua, so nothing in the Go build ever executes it.  These
// tests do: they load the shipped snippet into a real interpreter with the
// mod_lua and luasocket surfaces stubbed, then count how many times it calls
// out to the daemon.  That count is the whole contract -- one visit, one
// judgement.

// luaHarness is the stub environment the snippet runs under.  http.request
// tallies calls into COUNT so a test can assert on it, and every mod_lua field
// the snippet touches is present so a missing stub fails loudly rather than
// silently taking a different branch.
const luaHarness = `
COUNT = 0
package.preload["socket.http"] = function()
  return { request = function(t) COUNT = COUNT + 1
                                 return 1, 200, {["x-unmask-action"] = "pass"} end }
end
package.preload["ltn12"] = function()
  return { sink = { null = function() return function() end end } }
end
apache2 = { DECLINED = -1, OK = 0, HTTP_MOVED_TEMPORARILY = 302 }

dofile(SNIPPET)

function request(initial, uri)
  return handle_request{
    uri = uri, unparsed_uri = uri,
    is_initial_req = initial,
    useragent_ip = "203.0.113.50",
    headers_in = {["User-Agent"] = "curl/8.0", Host = "shop.example.com"},
    headers_out = {}, err_headers_out = {}, subprocess_env = {},
    info = function() end, err = function() end, notice = function() end,
  }
end
`

// runLua executes body against the shipped snippet and returns its stdout.
func runLua(t *testing.T, body string) string {
	t.Helper()
	lua, err := exec.LookPath("luajit")
	if err != nil {
		if lua, err = exec.LookPath("lua"); err != nil {
			t.Skip("no lua interpreter — Apache hook behaviour not exercised")
		}
	}
	snippet := filepath.Join(repoSnippetsDir(t), "apache-unmask.lua")
	if _, err := os.Stat(snippet); err != nil {
		t.Skipf("snippet not found: %v", err)
	}

	script := filepath.Join(t.TempDir(), "harness.lua")
	full := "SNIPPET = " + quoteLua(snippet) + "\n" + luaHarness + body
	if err := os.WriteFile(script, []byte(full), 0o600); err != nil {
		t.Fatal(err)
	}
	out, err := exec.Command(lua, script).CombinedOutput()
	if err != nil {
		t.Fatalf("lua failed: %v\n%s", err, out)
	}
	return strings.TrimSpace(string(out))
}

func quoteLua(s string) string { return `"` + strings.ReplaceAll(s, `"`, `\"`) + `"` }

// TestApacheHookSkipsInternalRedirects: Apache re-runs the access checker on
// its own internal redirects -- ErrorDocument above all.  One client GET that
// 404s therefore reached the hook twice, the second time carrying the error
// document's URI, and unmask recorded both as visits.  On the install where
// this surfaced the error-page URI was the single most frequent "request" on
// the host, and every one of them had also cost a second round-trip to the
// daemon.  Reproduced there as: one curl to a missing page, two events.
func TestApacheHookSkipsInternalRedirects(t *testing.T) {
	if got := runLua(t, `request(false, "/common/errors/404error.html")
	                     print(COUNT)`); got != "0" {
		t.Errorf("daemon calls on an internal redirect = %s, want 0", got)
	}
}

// TestApacheHookJudgesRealVisits: the guard must not cost the ordinary case.
func TestApacheHookJudgesRealVisits(t *testing.T) {
	if got := runLua(t, `request(true, "/index.html")
	                     print(COUNT)`); got != "1" {
		t.Errorf("daemon calls on a real visit = %s, want 1", got)
	}
}

// TestApacheHookJudgesWhenFieldAbsent: a mod_lua that does not expose
// is_initial_req reads as nil.  Negating that would skip every request and
// disable unmask silently on the hosts least able to notice, so unknown has to
// mean "judge it".
func TestApacheHookJudgesWhenFieldAbsent(t *testing.T) {
	if got := runLua(t, `request(nil, "/index.html")
	                     print(COUNT)`); got != "1" {
		t.Errorf("daemon calls when is_initial_req is unavailable = %s, want 1", got)
	}
}

// TestApacheHookStillSkipsOwnPaths: /unmask/* must never be judged, or the
// challenge page challenges itself.  Pinned here because the new guard was
// inserted directly above that check.
func TestApacheHookStillSkipsOwnPaths(t *testing.T) {
	if got := runLua(t, `request(true, "/unmask/challenge/")
	                     print(COUNT)`); got != "0" {
		t.Errorf("daemon calls on unmask's own path = %s, want 0", got)
	}
}
