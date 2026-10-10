package nginxlog

import (
	"testing"
	"time"

	"github.com/unmask-sh/unmask/admin/internal/live"
)

// The live strip reads each access-log line under the same precedence the
// minute buckets use, and the ban list decides what counts as denied.
func TestLiveHitPerLine(t *testing.T) {
	r := Start("", nil) // no database: the minute buckets are off, the live tap is not
	c := live.New()
	r.SetLive(c)
	r.SetDeniedCheck(func(ip, ja4 string) bool { return ip == "198.51.100.9" })
	r.SetCrawlerClassifier(func(ua string) string {
		if ua == "Mozilla/5.0 (compatible; Googlebot/2.1)" {
			return "search-engine"
		}
		return ""
	})
	line := func(kind, fc, hp, ip, bp, ua string) string {
		return "1751400000.1 site=shop.example kind=" + kind + " fc=" + fc + " hp=" + hp +
			" ip=" + ip + " ja4=t13d1516h2_8daaf6152771_02713d6af862 hpuri=/x bp=" + bp + " scheme=https ua=" + ua
	}
	r.onLine(line("pow", "0", "0", "203.0.113.1", "0", "Mozilla/5.0 Chrome"))                   // a pass cookie
	r.onLine(line("", "1", "0", "203.0.113.2", "0", "Mozilla/5.0 Chrome"))                      // a challenge served
	r.onLine(line("", "0", "0", "203.0.113.3", "1", "curl/8"))                                  // bypassed
	r.onLine(line("", "0", "0", "66.249.66.1", "0", "Mozilla/5.0 (compatible; Googlebot/2.1)")) // a listed crawler
	r.onLine(line("", "0", "1", "203.0.113.4", "0", "python-requests/2"))                       // a honeypot trip
	r.onLine(line("pow", "0", "0", "198.51.100.9", "0", "Mozilla/5.0 Chrome"))                  // banned with deny: not a pass
	r.onLine(line("", "0", "0", "203.0.113.5", "0", "Mozilla/5.0 Chrome"))                      // nothing special: a request only

	sn := c.Snapshot(time.Now())
	want := map[live.Kind]uint32{live.Requests: 7, live.Pass: 1, live.Serve: 1, live.Bypass: 2, live.Deny: 2, live.Solve: 0, live.RateLimit: 0}
	for k, n := range want {
		if sn.Last[k] != n {
			t.Errorf("%s = %d, want %d", live.Names[k], sn.Last[k], n)
		}
	}
	if sn.LastLine == 0 {
		t.Error("the feed did not register as alive")
	}
}

// Forward-auth has no access-log line: the exported Bump entry points feed
// the strip with what each one knows, and a line never counts twice.
func TestLiveBumpForwardAuth(t *testing.T) {
	r := Start("", nil)
	c := live.New()
	r.SetLive(c)
	// Bump returns before counting when there is no database (the minute
	// buckets need one), so forward-auth's strip needs the database too; the
	// exported kinds-only paths do not.
	r.BumpBypass("default")
	r.BumpCrawlerPass("default")
	sn := c.Snapshot(time.Now())
	if sn.Last[live.Bypass] != 2 || sn.Last[live.Requests] != 0 {
		t.Errorf("bypass=%d requests=%d, want 2/0", sn.Last[live.Bypass], sn.Last[live.Requests])
	}
}

func TestLiveUnsetIsFree(t *testing.T) {
	r := Start("", nil)
	// No counter attached: a line must not panic or allocate a strip.
	r.onLine("1751400000.1 site=a kind= fc=0 hp=0 ip=203.0.113.1 ja4=- hpuri= bp=0 scheme=https ua=x")
	r.BumpBypass("a")
}
