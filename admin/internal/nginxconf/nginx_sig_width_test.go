package nginxconf

import (
	"crypto/hmac"
	"crypto/sha1"
	"encoding/hex"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/unmask-sh/unmask/admin/internal/cookies"
)

// TestNginxVerifiesBothSignatureWidths runs a real nginx with the module and
// presents it passes signed in every form the daemon issues: HMAC-SHA1 and
// HMAC-SHA256 with a 16-digit signature, which is what every release before
// 0.1.58 issued, and HMAC-SHA256 with a 32-digit one.  nginx has to say of
// each what the daemon says -- the kind, and the same name for the pass
// ($unmask_bv_id is what the per-pass reuse cap counts by, and the daemon
// reports by cookies.MatchingEntryID) -- and of each thing that is not a
// pass, nothing: a 32-digit signature with one digit changed in either half,
// one spelt from HMAC-SHA1, one of a width between the two, one of a kind
// the daemon does not issue.
//
// The module also says what it verifies ($unmask_module_caps), for a daemon
// to read off the access log before it issues the wide form; a
// configuration that logs it has to declare the name first, for the module
// from before 0.1.58 that a reload keeps, and the module takes that
// placeholder over without a word.
//
// Skipped unless UNMASK_TEST_NGINX and UNMASK_TEST_NGINX_MODULE are set:
// `make test-nginx-accepts` sets both.
func TestNginxVerifiesBothSignatureWidths(t *testing.T) {
	bin, mod := os.Getenv("UNMASK_TEST_NGINX"), os.Getenv("UNMASK_TEST_NGINX_MODULE")
	if bin == "" || mod == "" {
		t.Skip("UNMASK_TEST_NGINX / UNMASK_TEST_NGINX_MODULE are not set")
	}
	// startNginx's secret, its address and its Host.
	const secret, addr, host = "0123456789abcdef0123456789abcdef", "127.0.0.1", "test.local"
	ask, dir := startNginxWith(t, bin, mod, "", "$unmask_bv_kind|$unmask_bv_id|$unmask_module_caps",
		"    map \"\" $unmask_module_caps { default \"\"; }\n")
	issued := time.Now().Unix() - 30
	issuedS := strconv.FormatInt(issued, 10)
	sigOf := func(entry string) string { return strings.Split(entry, ".")[1] }
	entry := func(sig, kind string) string { return issuedS + "." + sig + "." + kind }
	flip := func(sig string, i int) string {
		c := byte('0')
		if sig[i] == '0' {
			c = '1'
		}
		return sig[:i] + string(c) + sig[i+1:]
	}

	narrow1 := cookies.IssueValueAtH(cookies.SigSHA1, secret, addr, host, "captcha", issued)
	narrow := cookies.IssueValueAtH(cookies.SigSHA256, secret, addr, host, "captcha", issued)
	wide := cookies.IssueValueAtH(cookies.SigSHA256Wide, secret, addr, host, "captcha", issued)
	if len(sigOf(narrow1)) != cookies.SigHexLen || len(sigOf(narrow)) != cookies.SigHexLen || len(sigOf(wide)) != cookies.SigHexLenWide {
		t.Fatalf("signature widths: %q %q %q", narrow1, narrow, wide)
	}
	if !strings.HasPrefix(sigOf(wide), sigOf(narrow)) {
		t.Fatalf("the 16-digit HMAC-SHA256 signature %q is not the head of the 32-digit one %q", sigOf(narrow), sigOf(wide))
	}
	// A 32-digit signature that is HMAC-SHA1's: the wide form is
	// HMAC-SHA256's alone, in the module and in the daemon.
	m := hmac.New(sha1.New, []byte(secret))
	m.Write([]byte(issuedS + ":" + addr + ":" + host + ":captcha"))
	sha1Wide := hex.EncodeToString(m.Sum(nil))[:cookies.SigHexLenWide]
	// The proof-of-work seed is the same MAC over a message of the same
	// shape with "pow_seed" where the kind goes, and every visitor is handed
	// it: its head must not pass for a signature of either width.
	seed := cookies.PowSeedH(cookies.SigSHA256Wide, secret, addr, host, issued)

	cases := []struct{ what, value string }{
		{"HMAC-SHA1, 16 digits", narrow1},
		{"HMAC-SHA256, 16 digits", narrow},
		{"HMAC-SHA256, 32 digits", wide},
		{"32 digits, kind rebind", cookies.IssueValueAtH(cookies.SigSHA256Wide, secret, addr, host, "rebind", issued)},
		{"32 digits, kind passthrough", cookies.IssueValueAtH(cookies.SigSHA256Wide, secret, addr, host, "passthrough", issued)},
		{"32 digits, kind pow", cookies.IssueValueAtH(cookies.SigSHA256Wide, secret, addr, host, "pow", issued)},
		{"32 digits behind a junk entry", "x~" + entry(flip(sigOf(wide), 3), "captcha") + "~" + wide},
		{"32 digits, the first digit changed", entry(flip(sigOf(wide), 0), "captcha")},
		{"32 digits, the 17th digit changed", entry(flip(sigOf(wide), 16), "captcha")},
		{"32 digits, the last digit changed", entry(flip(sigOf(wide), 31), "captcha")},
		{"32 digits of HMAC-SHA1", entry(sha1Wide, "captcha")},
		{"24 digits", entry(sigOf(wide)[:24], "captcha")},
		{"31 digits", entry(sigOf(wide)[:31], "captcha")},
		{"33 digits", entry(sigOf(wide)+"0", "captcha")},
		{"16 digits and 16 zeros", entry(sigOf(narrow)+"0000000000000000", "captcha")},
		{"32 digits signed for another host", cookies.IssueValueAtH(cookies.SigSHA256Wide, secret, addr, "other.test.local", "captcha", issued)},
		{"32 digits signed for another address", cookies.IssueValueAtH(cookies.SigSHA256Wide, secret, "127.0.0.2", host, "captcha", issued)},
		{"32 digits, a kind the daemon does not issue", cookies.IssueValueAtH(cookies.SigSHA256Wide, secret, addr, host, "other", issued)},
		{"the seed's first 32 digits as a signature", entry(seed[:cookies.SigHexLenWide], "pow_seed")},
		{"the seed's first 16 digits as a signature", entry(seed[:cookies.SigHexLen], "pow_seed")},
	}
	verified := 0
	for _, c := range cases {
		_, kind, id, _, ok := cookies.MatchingEntryID(c.value, secret, addr, host, 3600, 3600, 8)
		want := "||sig128"
		if ok {
			verified++
			want = kind + "|" + id + "|sig128"
			if len(id) != cookies.PassIDLen {
				t.Errorf("%s: the daemon names the pass %q, want %d digits", c.what, id, cookies.PassIDLen)
			}
		}
		if got := ask(false, map[string]string{"Cookie": "_bv=" + c.value}); got != want {
			t.Errorf("%s: nginx says kind|bvid|caps = %q, the daemon %q (entry %q)", c.what, got, want, c.value)
		}
	}
	if verified != 7 {
		t.Errorf("the daemon verified %d of the entries, want the first 7 alone", verified)
	}
	// One pass, one name: the 16-digit HMAC-SHA256 entry and the 32-digit
	// one are the same signature at two widths, and count as one pass.
	one := ask(false, map[string]string{"Cookie": "_bv=" + narrow})
	two := ask(false, map[string]string{"Cookie": "_bv=" + wide})
	if one != two || one != "captcha|"+sigOf(narrow)+"|sig128" {
		t.Errorf("the same pass at two widths: nginx names it %q and %q, want captcha|%s|sig128 for both", one, two, sigOf(narrow))
	}

	// The placeholder was taken over in silence.  A notice at every nginx -t
	// and reload reads as a misconfiguration to the operators who log at
	// that level; the startup log (<prefix>/logs/error.log) is where a
	// postconfiguration line goes before error_log takes effect.
	for _, f := range []string{filepath.Join(dir, "error.log"), filepath.Join(dir, "logs", "error.log")} {
		b, err := os.ReadFile(f)
		if err != nil {
			continue
		}
		for _, line := range strings.Split(string(b), "\n") {
			if strings.Contains(line, "unmask_module_caps") {
				t.Errorf("%s: %s", f, line)
			}
		}
	}
}
