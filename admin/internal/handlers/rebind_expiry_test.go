package handlers

import (
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/unmask-sh/unmask/admin/internal/cookies"
	"github.com/unmask-sh/unmask/admin/internal/settings"
)

// A pass lives as long as the solve behind it, roams included.  The _bvj
// that lets a visitor keep their pass across a network change used to be
// valid for the larger of the two solve windows whatever it recorded, and
// each re-bound _bv lived a fresh CAPTCHA window from the roam: on the
// default settings a proof-of-work solve -- seven days -- kept a browser
// through for up to four weeks.

const (
	expirySecret = "test-secret"
	expiryHost   = "example.com"
	expiryAddr   = "203.0.113.5"
	expiryUA     = "Mozilla/5.0 (X11; Linux x86_64; rv:153.0) Gecko/20100101 Firefox/153.0"
	expiryJA4    = "t13d1717h2_5b57614c22b0_3cbfd9057e0d"
	day          = int64(24 * 60 * 60)
)

func expiryHandler(t *testing.T, ch settings.ChallengeValues) *Handler {
	t.Helper()
	h := newRebindTestHandler(t)
	h.SetSettings(settings.Settings{
		Secret:    settings.Secret{BVSecret: expirySecret},
		Challenge: settings.ChallengeConfig{Default: ch},
	})
	return h
}

func expiryBVJ(issued int64, grade, ua string) string {
	return cookies.IssueJValueAt(expirySecret, cookies.FingerprintHash(expiryJA4), cookies.FingerprintHash(ua),
		"linexpiry000000000000000", 0, expiryHost, grade, issued)
}

// issuedOf reads the issue time an entry or a _bvj carries (its first field).
func issuedOf(t *testing.T, v string) int64 {
	t.Helper()
	n, err := strconv.ParseInt(strings.SplitN(v, ".", 2)[0], 10, 64)
	if err != nil {
		t.Fatalf("no issue time in %q", v)
	}
	return n
}

func setCookie(rr *httptest.ResponseRecorder, name string) string {
	for _, c := range rr.Result().Cookies() {
		if c.Name == name {
			return c.Value
		}
	}
	return ""
}

func TestBVJWindowFollowsTheGrade(t *testing.T) {
	h := expiryHandler(t, settings.ChallengeValues{}) // PoW 7 days, CAPTCHA 14 days
	now := time.Now().Unix()
	for _, c := range []struct {
		name  string
		age   int64
		grade string
		want  bool
	}{
		{"proof-of-work, past its seven days", 8 * day, "pow", false},
		{"proof-of-work, inside its seven days", 6 * day, "pow", true},
		{"CAPTCHA, inside its fourteen days", 8 * day, "captcha", true},
		{"CAPTCHA, past its fourteen days", 15 * day, "captcha", false},
	} {
		req := httptest.NewRequest(http.MethodGet, "https://example.com/unmask/challenge/", nil)
		req.AddCookie(&http.Cookie{Name: "_bvj", Value: expiryBVJ(now-c.age, c.grade, expiryUA)})
		if _, ok := h.validBVJ(req, expiryHost, "default"); ok != c.want {
			t.Errorf("%s: valid=%v, want %v", c.name, ok, c.want)
		}
	}
}

func TestRebindEntryEndsWithTheSolve(t *testing.T) {
	const pow, captcha = 7 * day, 14 * day
	rebind := func(t *testing.T, h *Handler, bvj string) string {
		t.Helper()
		req := httptest.NewRequest(http.MethodGet, "https://example.com/unmask/challenge/", nil)
		req.Host = expiryHost
		req.Header.Set("X-Real-IP", expiryAddr)
		req.Header.Set("User-Agent", expiryUA)
		req.Header.Set("X-Client-JA4", expiryJA4)
		req.AddCookie(&http.Cookie{Name: "_bvj", Value: bvj})
		rr := httptest.NewRecorder()
		if !h.tryRebind(rr, req, "default", "bt-test") {
			t.Fatal("the roam should rebind")
		}
		bv := setCookie(rr, "_bv")
		if !cookies.Verify(bv, expirySecret, expiryAddr, expiryHost, int(pow), int(captcha), 18) {
			t.Fatalf("the re-bound entry %q does not verify now", bv)
		}
		return bv
	}
	now := time.Now().Unix()

	t.Run("proof-of-work", func(t *testing.T) {
		solved := now - 6*day
		bv := rebind(t, expiryHandler(t, settings.ChallengeValues{}), expiryBVJ(solved, "pow", expiryUA))
		if got, want := issuedOf(t, bv)+captcha, solved+pow; got != want {
			t.Errorf("the re-bound entry ends at %d, want the solve's end %d (%+d s)", got, want, got-want)
		}
	})
	t.Run("CAPTCHA", func(t *testing.T) {
		solved := now - day
		bv := rebind(t, expiryHandler(t, settings.ChallengeValues{}), expiryBVJ(solved, "captcha", expiryUA))
		if got, want := issuedOf(t, bv)+captcha, solved+captcha; got != want {
			t.Errorf("the re-bound entry ends at %d, want the solve's end %d (%+d s)", got, want, got-want)
		}
	})
	t.Run("a proof-of-work window longer than the CAPTCHA one", func(t *testing.T) {
		// The entry is honoured for the CAPTCHA window from the time it carries,
		// and that time cannot be in the future: it lives that window from now.
		h := expiryHandler(t, settings.ChallengeValues{PowCookieValidSeconds: 30 * 24 * 60 * 60})
		before := time.Now().Unix()
		bv := rebind(t, h, expiryBVJ(before-day, "pow", expiryUA))
		if got := issuedOf(t, bv); got < before || got > time.Now().Unix() {
			t.Errorf("the re-bound entry carries %d, want now (%d)", got, before)
		}
	})
}

func TestIssueBVJDatesTheCredentialFromTheSolve(t *testing.T) {
	h := expiryHandler(t, settings.ChallengeValues{PowDifficulty: bvjTestDifficulty})
	post := func(bv, bvj, ua string) string {
		req := httptest.NewRequest(http.MethodPost, "https://example.com/unmask/api/bvj", nil)
		req.Host = expiryHost
		req.Header.Set("X-Real-IP", expiryAddr)
		req.Header.Set("User-Agent", ua)
		req.Header.Set("X-Client-JA4", expiryJA4)
		req.AddCookie(&http.Cookie{Name: "_bv", Value: bv})
		if bvj != "" {
			req.AddCookie(&http.Cookie{Name: "_bvj", Value: bvj})
		}
		rr := httptest.NewRecorder()
		h.IssueBVJ(rr, req)
		return setCookie(rr, "_bvj")
	}
	now := time.Now().Unix()
	const otherUA = "Mozilla/5.0 (X11; Linux x86_64; rv:154.0) Gecko/20100101 Firefox/154.0"

	solved := now - 2*day
	if got := post(powPassAt(t, expirySecret, expiryAddr, expiryHost, solved), "", expiryUA); got == "" || issuedOf(t, got) != solved {
		t.Errorf("a first _bvj for a pass solved at %d carries %q, want that time", solved, got)
	}
	// A re-issue keeps the newest solve it knows of: the newer pass ...
	newer := now - day
	if got := post(powPassAt(t, expirySecret, expiryAddr, expiryHost, newer), expiryBVJ(now-3*day, "pow", otherUA), expiryUA); got == "" || issuedOf(t, got) != newer {
		t.Errorf("re-issued off a newer pass, the _bvj carries %q, want %d", got, newer)
	}
	// ... or its own, when the pass it is shown is the older one.  Dated now,
	// re-posting an old pass under a changed User-Agent restarted the window.
	own := now - 3*day
	if got := post(powPassAt(t, expirySecret, expiryAddr, expiryHost, now-5*day), expiryBVJ(own, "pow", otherUA), expiryUA); got == "" || issuedOf(t, got) != own {
		t.Errorf("re-issued off an older pass, the _bvj carries %q, want its own %d", got, own)
	}
}
