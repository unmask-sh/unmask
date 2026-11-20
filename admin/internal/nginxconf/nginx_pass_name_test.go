package nginxconf

import (
	"crypto/sha256"
	"math/bits"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/unmask-sh/unmask/admin/internal/cookies"
	"github.com/unmask-sh/unmask/admin/internal/settings"
)

// TestNginxNamesThePassItLetIn runs a real nginx with the module and asks it
// which pass it let a request in on.
//
// The module tries every _bv the Cookie header carries and takes one in
// quotes; nginx's $cookie__bv is the first, as written.  The access log's bv=
// is built from the latter, so a client that sent "_bv=x; _bv=<pass>", or its
// pass in quotes, got in on the pass and logged a value that verified for
// nobody -- and the daemon's pass budget, which counts the passes the log
// shows an address presenting, never heard of them.  The log carries the
// module's own name for the pass as well now ($unmask_bv_id, as bvid=), and
// it is the name the daemon gives the pass (cookies.MatchingEntryID).
//
// Skipped unless UNMASK_TEST_NGINX and UNMASK_TEST_NGINX_MODULE are set:
// `make test-nginx-accepts` sets both.
func TestNginxNamesThePassItLetIn(t *testing.T) {
	bin, mod := os.Getenv("UNMASK_TEST_NGINX"), os.Getenv("UNMASK_TEST_NGINX_MODULE")
	if bin == "" || mod == "" {
		t.Skip("UNMASK_TEST_NGINX / UNMASK_TEST_NGINX_MODULE are not set")
	}
	// startNginx's secret, its address and its Host.
	const secret, addr, host = "0123456789abcdef0123456789abcdef", "127.0.0.1", "test.local"
	ask := startNginx(t, bin, mod, "", "$unmask_bv_kind|$unmask_bv_id|$unmask_bv_log")
	pass := mintPowPass(t, secret, addr, host, time.Now().Unix())
	// The daemon asks for the difficulty this nginx was rendered with (the
	// default, as startNginx's config names none).  At a lower bar, the
	// nonce minted for the HMAC-SHA1 seed also clears the HMAC-SHA256 seed,
	// which both verifiers try first, in about one run in 256 -- and the
	// daemon then names the pass by that seed while nginx, which holds it to
	// the default, names it by the other.
	_, _, id, _, ok := cookies.MatchingEntryID(pass, secret, addr, host, 3600, 3600, settings.PowDifficultyDefault)
	if !ok || len(id) != cookies.PassIDLen {
		t.Fatalf("the daemon does not verify the minted pass %q (id %q)", pass, id)
	}
	for _, c := range []struct{ what, cookie, logged string }{
		{"the pass alone", "_bv=" + pass, pass},
		{"a junk _bv ahead of it", "_bv=x; _bv=" + pass, "x"},
		{"the pass in quotes", `_bv="` + pass + `"`, ""},
	} {
		if got, want := ask(false, map[string]string{"Cookie": c.cookie}), "pow|"+id+"|"+c.logged; got != want {
			t.Errorf("%s: kind|bvid|bv = %q, want %q", c.what, got, want)
		}
	}
}

// TestNginxBindsAPassToAnIPv6HostInBrackets runs a real nginx with the module
// and asks it for $host when the client reached the site by its IPv6
// address, and whether a pass signed for that name verifies.  $host keeps
// the literal's brackets and drops the port ("[2001:db8::1]" for a Host of
// "[2001:DB8::1]:8443"), and that string is what the module signs for --
// which is why the daemon's own name for the host (handlers.requestHost)
// has to keep the brackets too.  A pass signed for the bare address, as the
// daemon signed it until 0.1.58, does not verify.
//
// Skipped unless UNMASK_TEST_NGINX and UNMASK_TEST_NGINX_MODULE are set:
// `make test-nginx-accepts` sets both.
func TestNginxBindsAPassToAnIPv6HostInBrackets(t *testing.T) {
	bin, mod := os.Getenv("UNMASK_TEST_NGINX"), os.Getenv("UNMASK_TEST_NGINX_MODULE")
	if bin == "" || mod == "" {
		t.Skip("UNMASK_TEST_NGINX / UNMASK_TEST_NGINX_MODULE are not set")
	}
	// startNginx's secret and its address.
	const secret, addr = "0123456789abcdef0123456789abcdef", "127.0.0.1"
	ask := startNginx(t, bin, mod, "", "$host|$unmask_bv_kind")
	now := time.Now().Unix()
	for _, c := range []struct{ sent, host string }{
		{"[2001:DB8::1]:8443", "[2001:db8::1]"},
		{"[2001:db8::1]", "[2001:db8::1]"},
		{"[::1]:80", "[::1]"},
	} {
		for _, p := range []struct{ kind, value string }{
			{"captcha", cookies.IssueValueAt(secret, addr, c.host, "captcha", now)},
			{"pow", mintPowPass(t, secret, addr, c.host, now)},
		} {
			if got, want := ask(false, map[string]string{"Host": c.sent, "Cookie": "_bv=" + p.value}), c.host+"|"+p.kind; got != want {
				t.Errorf("Host %q, a %s pass signed for %q: nginx says $host|kind = %q, want %q", c.sent, p.kind, c.host, got, want)
			}
		}
		bare := strings.Trim(c.host, "[]")
		if got, want := ask(false, map[string]string{"Host": c.sent, "Cookie": "_bv=" + cookies.IssueValueAt(secret, addr, bare, "captcha", now)}), c.host+"|"; got != want {
			t.Errorf("Host %q, a pass signed for %q (no brackets): nginx says %q, want %q", c.sent, bare, got, want)
		}
	}
}

// mintPowPass solves the proof-of-work for addr and host at issued the way
// challenge.js does, past any difficulty the settings allow by default (20
// leading zero bits), so the test does not depend on the one configured.
func mintPowPass(t *testing.T, secret, addr, host string, issued int64) string {
	t.Helper()
	seed := cookies.PowSeed(secret, addr, host, issued)
	for nonce := int64(0); nonce < 1<<28; nonce++ {
		sum := sha256.Sum256([]byte(seed + ":" + strconv.FormatInt(nonce, 10)))
		n := 0
		for _, b := range sum {
			if b != 0 {
				n += bits.LeadingZeros8(b)
				break
			}
			n += 8
		}
		if n >= 20 {
			return strconv.FormatInt(issued, 10) + ".pow2." + strconv.FormatInt(nonce, 36) + ".0"
		}
	}
	t.Fatal("no nonce clears the difficulty")
	return ""
}
