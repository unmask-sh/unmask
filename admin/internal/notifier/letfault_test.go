package notifier

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// TestLetThroughFaultTellsTheListAlone: what the access log's flush reports
// of the reason "none" reaches the admin's list -- the hour, the requests,
// the sites by count, as a warning -- and neither the webhook nor the mail,
// whatever the switches say.
func TestLetThroughFaultTellsTheListAlone(t *testing.T) {
	hooked := make(chan string, 4)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { hooked <- r.URL.Path }))
	defer srv.Close()
	ib := &chanInbox{got: make(chan map[string]any, 8)}
	m := &chanMailer{sent: make(chan string, 8)}
	n := New(Config{URL: srv.URL, Format: FormatGeneric, Sites: "blog", BanEvents: true, ChallengeBurst: true}).
		WithMail(m, func() []Recipient { return []Recipient{{Email: "ops@example.com"}} }, nil).
		WithInbox(ib)
	c := &fakeClock{t: time.Date(2026, 11, 25, 3, 10, 0, 0, time.UTC)}
	n.now = c.now
	hour := c.t.Unix() / 3600

	n.LetThroughFault(hour, 7, map[string]int{"a.example": 5, "b.example": 2})
	f := ib.next(t, "the flush's report")
	if f["_event"] != EventLetThroughFault || f["count"] != int64(7) || f["hour"] != hour*3600 || f["site"] != "blog" ||
		f["ts"] != c.t.Unix() || f["severity"] != SeverityWarn || f["more"] != int64(0) {
		t.Errorf("fields: %v", f)
	}
	sites, _ := f["sites"].(map[string]any)
	if len(sites) != 2 || sites["a.example"] != int64(5) || sites["b.example"] != int64(2) {
		t.Errorf("sites: %v", f["sites"])
	}
	select {
	case p := <-hooked:
		t.Errorf("the webhook was sent it (%s)", p)
	case s := <-m.sent:
		t.Errorf("mail was sent (%s)", s)
	case <-time.After(200 * time.Millisecond):
	}

	// Nothing to say is not said.
	n.LetThroughFault(hour, 0, nil)
	ib.none(t, "a flush with none of them")
	var none *Notifier
	none.LetThroughFault(hour, 3, map[string]int{"a.example": 3}) // nil-safe
}

// TestLetThroughFaultBoundsTheSites: a Host is the client's to write on a
// catch-all server, so a call names the busiest LetFaultSitesKept sites and
// counts the rest, and a name is bounded like any field a visitor wrote.
func TestLetThroughFaultBoundsTheSites(t *testing.T) {
	ib := &chanInbox{got: make(chan map[string]any, 2)}
	n := New(Config{}).WithInbox(ib)
	sites := map[string]int{}
	total := 0
	for i := 0; i < LetFaultSitesKept+4; i++ {
		sites[fmt.Sprintf("h%02d.example", i)] = 100 - i // h00 is the busiest
		total += 100 - i
	}
	long := strings.Repeat("x", 300) + "\nforged line"
	sites[long] = 1000
	total += 1000
	n.LetThroughFault(1, total, sites)
	f := ib.next(t, "the report")
	named, _ := f["sites"].(map[string]any)
	if len(named) != LetFaultSitesKept {
		t.Fatalf("%d sites named, want %d: %v", len(named), LetFaultSitesKept, named)
	}
	sum := int64(0)
	for name, v := range named {
		if len([]rune(name)) > fieldMax || strings.ContainsAny(name, "\n\r") {
			t.Errorf("a site's name is not bounded: %q", name)
		}
		sum += v.(int64)
	}
	if named["h00.example"] != int64(100) || named["h07.example"] != nil {
		t.Errorf("not the busiest sites: %v", named)
	}
	if more, _ := f["more"].(int64); more+sum != int64(total) || more <= 0 {
		t.Errorf("named %d + more %v != %d", sum, f["more"], total)
	}
}
