package nginxlog

import (
	"fmt"
	"path/filepath"
	"strings"
	"testing"

	"github.com/unmask-sh/unmask/admin/internal/classify"
	"github.com/unmask-sh/unmask/admin/internal/db"
	"github.com/unmask-sh/unmask/admin/internal/settings"
)

// What a line costs the log's one reader does not grow with its User-Agent.
//
// The User-Agent is the client's to write and nginx logs it whole, up to its
// header buffers.  Every classifier read all of it -- the crawler category
// twice a line, the honeypot's veto with four scans a trip -- and each costs
// in proportion: a line with eight kilobytes of User-Agent held the reader
// for tens of milliseconds, a honeypot trip for most of a second.  The
// reader is one goroutine behind a queue; lines it cannot keep up with are
// dropped, the trips among them, so a few such requests a second stopped the
// counters and the automatic bans of the whole install.  The classifiers
// read the head of the User-Agent now (classUA), once each.

const (
	testBrowserUA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36"
	testGoogleUA  = "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)"
)

func uaLine(hp int, sfs, ua string) string {
	return fmt.Sprintf("1700000000.000 site=a.example kind= fc=0 hp=%d ip=198.51.100.7 ja4=t13d1516h2_8daaf6152771_02713d6af862 hpuri=/.env bp=0 scheme=https cr=- pv=0 sb=0 sfs=%s sfd= rh= bv= bvid= mo= mc= ua=%s", hp, sfs, ua)
}

// uaProbe is a Reader whose every User-Agent hook records what it was handed.
type uaProbe struct {
	r                                         *Reader
	search, category, namer, ranges, observer []string
	trips                                     int
}

func newUAProbe(t *testing.T) *uaProbe {
	t.Helper()
	d, err := db.Open(settings.DB{Driver: "sqlite", SQLitePath: filepath.Join(t.TempDir(), "t.db")})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { d.Close() })
	if err := db.Migrate(d); err != nil {
		t.Fatal(err)
	}
	p := &uaProbe{r: Start("", d)}
	t.Cleanup(func() { p.r.Close() })
	p.r.SetSearchBotCheck(func(ua string) bool { p.search = append(p.search, ua); return classify.IsSearchAI(ua) })
	p.r.SetRangeVerifiedCheck(func(ua string) bool { p.ranges = append(p.ranges, ua); return false })
	p.r.SetCrawlerClassifier(func(ua string) string { p.category = append(p.category, ua); return classify.LookupTag(ua) })
	p.r.SetCrawlerNamer(func(ua, tag string) string { p.namer = append(p.namer, ua); return classify.LookupCrawlerIn(ua, tag) })
	p.r.SetCrawlerObserver(func(ip, ua string) { p.observer = append(p.observer, ua) })
	p.r.SetHoneypotCallback(func(ip, ja4, uri, site, scheme string) { p.trips++ })
	return p
}

func TestClassifiersReadTheHeadOfAUserAgent(t *testing.T) {
	long := testBrowserUA + " " + strings.Repeat("abcdefgh ", 900)   // eight kilobytes
	escaped := "Mozilla/5.0 " + strings.Repeat(`\xE3\x81\x82`, 2660) // as nginx logs 8 KB of bytes above 0x7e
	for _, ua := range []string{long, escaped} {
		for _, hp := range []int{0, 1} {
			p := newUAProbe(t)
			p.r.onLine(uaLine(hp, "", ua))
			for name, got := range map[string][]string{"the honeypot's veto": p.search, "the crawler category": p.category, "the crawler's name": p.namer, "the vendor-range check": p.ranges} {
				for _, g := range got {
					if len(g) > classifyUAMax {
						t.Errorf("hp=%d, a User-Agent of %d bytes: %s was handed %d of them, more than %d", hp, len(ua), name, len(g), classifyUAMax)
					}
					if !strings.HasPrefix(ua, g) {
						t.Errorf("hp=%d: %s was handed something that is not the User-Agent's head", hp, name)
					}
				}
			}
			if len(p.category) != 1 {
				t.Errorf("hp=%d: the crawler category was asked for %d times for one line, want once", hp, len(p.category))
			}
			if want := hp; len(p.search) != want || p.trips != want {
				t.Errorf("hp=%d: the veto was asked %d time(s) and %d trip(s) reached the callback; want %d of each", hp, len(p.search), p.trips, want)
			}
			// The field itself is the line's, whole: what the rDNS check
			// looks for a crawler's name in, and what the tables cut to
			// their own width.
			if len(p.observer) != 1 || p.observer[0] != ua {
				t.Errorf("hp=%d: the observer was not handed the User-Agent as logged (%d call(s))", hp, len(p.observer))
			}
		}
	}
}

// The line's other fields are read as they are whatever the User-Agent's
// length, and whatever it holds -- " ua=" itself included.
func TestParseKeepsALongUserAgentWholeAndTheFieldsBeforeIt(t *testing.T) {
	r := &Reader{}
	short, ok := r.parse(uaLine(1, "none", testBrowserUA))
	if !ok {
		t.Fatal("the line does not parse")
	}
	for _, ua := range []string{
		testBrowserUA + " " + strings.Repeat("x", 9000),
		strings.Repeat("y", 600) + " ua=Googlebot site=evil.example hp=0 ip=203.0.113.9",
		"curl/8 ua=second",
		strings.Repeat("z", classifyUAMax),
		strings.Repeat("z", classifyUAMax+1),
	} {
		p, ok := r.parse(uaLine(1, "none", ua))
		if !ok {
			t.Errorf("a line with a User-Agent of %d bytes does not parse", len(ua))
			continue
		}
		if p.ua != ua {
			t.Errorf("a User-Agent of %d bytes was read as one of %d", len(ua), len(p.ua))
		}
		if p.uaClass != classUA(ua) {
			t.Errorf("a User-Agent of %d bytes: the classifiers' head is %d bytes, want %d", len(ua), len(p.uaClass), len(classUA(ua)))
		}
		got := p
		got.ua, got.uaClass = short.ua, short.uaClass
		if got != short {
			t.Errorf("a User-Agent of %d bytes changed how the fields before it are read:\n got %+v\nwant %+v", len(ua), got, short)
		}
	}
}

// A crawler is known by the head of its User-Agent, as before; what a client
// appends does not make it one, nor un-make it.
func TestACrawlerIsKnownByTheHeadOfItsUserAgent(t *testing.T) {
	pad := " " + strings.Repeat("abcdefgh ", 900)
	p := newUAProbe(t)
	p.r.onLine(uaLine(1, "", testGoogleUA+pad)) // a trip by something that names Googlebot
	if p.trips != 0 {
		t.Error("a search crawler's User-Agent with eight kilobytes behind it was banned by the trap")
	}
	p.r.mu.Lock()
	n := len(p.r.crawlerBuckets)
	p.r.mu.Unlock()
	if n != 1 {
		t.Errorf("the crawler with the long User-Agent was counted in %d category bucket(s), want 1", n)
	}

	q := newUAProbe(t)
	q.r.onLine(uaLine(1, "", strings.Repeat("abcdefgh ", 100)+testGoogleUA)) // the name past the head
	if q.trips != 1 {
		t.Error("a User-Agent that names a crawler only past its first 512 bytes was spared by the trap")
	}
}

// The veto that reads the User-Agent comes last: a trip that bans nobody
// (a page of another site could have caused it) is not classified at all.
func TestHoneypotVetoReadsTheUserAgentLast(t *testing.T) {
	p := newUAProbe(t)
	p.r.onLine(uaLine(1, "cross-site", testBrowserUA))
	if len(p.search) != 0 || p.trips != 0 {
		t.Errorf("a cross-site trip: the search-crawler veto was asked %d time(s), %d trip(s) banned; want none of either", len(p.search), p.trips)
	}
	p.r.onLine(uaLine(1, "", testBrowserUA))
	if len(p.search) != 1 || p.trips != 1 {
		t.Errorf("a scanner's trip: the veto was asked %d time(s), %d trip(s) banned; want one of each", len(p.search), p.trips)
	}
}
