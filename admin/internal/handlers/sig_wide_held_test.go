package handlers

import (
	"bytes"
	"log"
	"strings"
	"testing"
	"time"

	"github.com/unmask-sh/unmask/admin/internal/cookies"
	"github.com/unmask-sh/unmask/admin/internal/renderwatch"
)

// The 128-bit signature is issued only where the module in front of the
// daemon verifies it.  The package replaces the daemon at once and nginx
// runs the module it loaded until it is restarted: a pass in a form that
// module does not know is refused, its holder is challenged again and handed
// another of the same form -- every visitor, on every page.  So while
// nginx's own lines say the module does not verify the form, the daemon
// signs the way an install that names no form does, and says so once; the
// setting takes effect by itself when the lines answer for it.
func TestWideSignatureIsHeldBackUntilTheModuleVerifiesIt(t *testing.T) {
	const secret, ip, host = "0123456789abcdef0123456789abcdef", "203.0.113.5", "example.com"
	h := newTestHandler(t)
	set := func(word string) {
		s := *h.cfg()
		s.Secret.BVSecret = secret
		s.Secret.SigHash = word
		h.SetSettings(s)
	}
	width := func() int {
		t.Helper()
		e := cookies.IssueValueH(h.sigHash(), secret, ip, host, "captcha")
		if !cookies.Verify(e, secret, ip, host, 3600, 3600, 8) {
			t.Fatalf("the entry issued does not verify: %q", e)
		}
		return len(strings.Split(e, ".")[1])
	}
	var logged bytes.Buffer
	prev := log.Writer()
	log.SetOutput(&logged)
	t.Cleanup(func() { log.SetOutput(prev) })
	said := func(what string) int { return strings.Count(logged.String(), what) }
	now := time.Now()

	// No watch (a daemon that hears no access log), and a watch that has
	// heard no line: nothing says the module lacks the form, the setting
	// stands.
	set("sha256-128")
	if h.sigHash() != cookies.SigSHA256Wide || width() != cookies.SigHexLenWide {
		t.Fatalf("no watch: form %v, width %d", h.sigHash(), width())
	}
	dir := t.TempDir()
	h.RenderWatch = renderwatch.New(func() string { return dir })
	if h.sigHash() != cookies.SigSHA256Wide {
		t.Fatalf("a watch with no line: form %v", h.sigHash())
	}
	if logged.Len() != 0 {
		t.Errorf("nothing held back, yet the log says: %s", logged.String())
	}

	// nginx logs from a module that does not say it verifies the form.
	h.RenderWatch.SawModule("0123456789abcdef", "", now.Add(-2*time.Minute))
	if h.sigHash() != cookies.DefaultSigHash || width() != cookies.SigHexLen {
		t.Errorf("an older module in front: form %v, width %d -- want the default form, 16 digits", h.sigHash(), width())
	}
	// The seed follows the same choice, so the proof-of-work the page hands
	// out is one that module verifies as well.
	if got, want := cookies.PowSeedH(h.sigHash(), secret, ip, host, now.Unix()), cookies.PowSeedH(cookies.DefaultSigHash, secret, ip, host, now.Unix()); got != want {
		t.Errorf("the seed while held back is %q, want the default form's %q", got, want)
	}
	for i := 0; i < 5; i++ {
		_ = h.sigHash()
	}
	if n := said("does not say it verifies 128-bit signatures"); n != 1 {
		t.Errorf("held back: said %d times, want once:\n%s", n, logged.String())
	}

	// nginx restarted onto the module that verifies it.
	h.RenderWatch.SawModule("fedcba9876543210", "sig128", now)
	if h.sigHash() != cookies.SigSHA256Wide || width() != cookies.SigHexLenWide {
		t.Errorf("the module answers for the form: form %v, width %d", h.sigHash(), width())
	}
	if n := said("signing with sha256-128 as secret.sig_hash says"); n != 1 {
		t.Errorf("released: said %d times, want once:\n%s", n, logged.String())
	}

	// A line without the word again (an old worker, a second nginx): held
	// back at once, and said again.
	h.RenderWatch.SawModule("0123456789abcdef", "", now.Add(2*time.Second))
	if h.sigHash() != cookies.DefaultSigHash {
		t.Errorf("a line without the word since: form %v", h.sigHash())
	}
	if n := said("does not say it verifies 128-bit signatures"); n != 2 {
		t.Errorf("held back again: said %d times, want twice", n)
	}

	// The other forms are the operator's word on what every module in front
	// verifies, as they were before the watch knew anything: not touched.
	for word, want := range map[string]cookies.SigHash{"": cookies.SigSHA1, "sha1": cookies.SigSHA1, "sha256": cookies.SigSHA256} {
		set(word)
		if got := h.sigHash(); got != want {
			t.Errorf("sig_hash %q with an older module in front: form %v, want %v", word, got, want)
		}
	}
	// A word the daemon does not know: the default, as Load warned.
	set("sha512")
	if got := h.sigHash(); got != cookies.DefaultSigHash {
		t.Errorf("sig_hash sha512: form %v", got)
	}
}
