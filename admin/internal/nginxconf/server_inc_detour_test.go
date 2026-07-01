// Guards the 2026-06-28 hardening (#3): the Web Bot Auth and Privacy Pass verify
// detours in server.inc must feed the plugin-gated JA4 ($effective_ja4) and strip
// X-Unmask-Conn-Peer -- so a client reaching the daemon through the detour cannot
// spoof or suppress the JA4 (same handling as the main unmask_daemon_proxy).
// These detour blocks only render when the advanced WBA / PAT switches are on.
package nginxconf

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/unmask-sh/unmask/admin/internal/settings"
)

func TestVerifyDetoursGateJA4(t *testing.T) {
	dir := t.TempDir()
	conf := filepath.Join(dir, "nginx.conf")
	if err := os.WriteFile(conf, []byte("http {\n}\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	var s settings.Settings
	s.Nginx.OutputDir = dir
	s.Nginx.ConfPath = conf
	// WebBotAuthActive()/PrivacyPassActive() = AdvancedEnabled && <feature>.Enabled.
	s.Nginx.AdvancedEnabled = true
	s.Nginx.WebBotAuth.Enabled = true
	s.Nginx.PrivacyPass.Enabled = true
	if err := Render(s, dir, "test"); err != nil {
		t.Fatalf("Render: %v", err)
	}
	body, err := os.ReadFile(filepath.Join(dir, "server.inc"))
	if err != nil {
		t.Fatal(err)
	}
	got := string(body)

	// $effective_ja4 is the plugin-computed value (not a client header); the
	// conn-peer is blanked so a client can't smuggle a trusted-LB peer in.
	reJA4 := regexp.MustCompile(`X-Client-JA4\s+\$effective_ja4\s*;`)
	reConnPeer := regexp.MustCompile(`X-Unmask-Conn-Peer\s+""\s*;`)

	for _, loc := range []string{"/_unmask/_signed_verify", "/_unmask/_pat_verify"} {
		block := detourBlock(t, got, loc)
		if !reJA4.MatchString(block) {
			t.Errorf("%s: detour must forward X-Client-JA4 = $effective_ja4 (the plugin-gated JA4, not a client header) -- a spoofed JA4 would otherwise be honored through the verify detour", loc)
		}
		if !reConnPeer.MatchString(block) {
			t.Errorf(`%s: detour must strip X-Unmask-Conn-Peer (set it to "") so a client can't forge the trusted-LB peer through the verify detour`, loc)
		}
	}
}

// detourBlock returns the body of the `location = <loc> { ... }` block, or fails
// the test if it is absent (= the WBA/PAT detour did not render).
func detourBlock(t *testing.T, conf, loc string) string {
	t.Helper()
	marker := "location = " + loc + " {"
	start := strings.Index(conf, marker)
	if start < 0 {
		t.Fatalf("rendered server.inc has no %q block (WBA/PAT detour not rendered with the advanced switch on?)", marker)
	}
	rest := conf[start:]
	end := strings.Index(rest, "\n}")
	if end < 0 {
		t.Fatalf("%q block is not closed", marker)
	}
	return rest[:end]
}
