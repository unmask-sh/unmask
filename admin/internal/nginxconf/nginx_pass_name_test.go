package nginxconf

import (
	"crypto/sha256"
	"math/bits"
	"os"
	"strconv"
	"testing"
	"time"

	"github.com/unmask-sh/unmask/admin/internal/cookies"
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
	_, _, id, _, ok := cookies.MatchingEntryID(pass, secret, addr, host, 3600, 3600, 8)
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
