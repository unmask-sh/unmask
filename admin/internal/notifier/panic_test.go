package notifier

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// A loop's recovered panic is a row in the admin's list once (a warning);
// the loop stuck on one -- three in a row -- is critical, on the critical
// hook and in the mail; in between, nothing, and again at every hundredth.
func TestLoopPanicIsAWarningOnceAndCriticalWhenStuck(t *testing.T) {
	posts := make(chan string, 8)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		posts <- r.URL.Path
	}))
	defer srv.Close()
	inbox := make(chan map[string]any, 8)
	m := &chanMailer{sent: make(chan string, 8)}
	n := New(Config{URL: srv.URL + "/all", CriticalURL: srv.URL + "/crit", Format: FormatSlack}).
		WithMail(m, func() []Recipient { return []Recipient{{Email: "ops@example.com"}} }, nil).
		WithInbox(inboxFunc(func(event string, fields map[string]any) { inbox <- fields }))

	n.LoopPanic("ban-loop", 1, "runtime error: index out of range\nmore")
	select {
	case f := <-inbox:
		if f["event"] != EventLoopPanic || f["loop"] != "ban-loop" || f["severity"] != SeverityWarn || f["consecutive"] != 1 || strings.Contains(f["value"].(string), "\n") {
			t.Errorf("first panic's row: %v", f)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("the first panic wrote no row")
	}
	select {
	case p := <-posts:
		t.Errorf("the first panic posted to %s", p)
	case s := <-m.sent:
		t.Errorf("the first panic mailed %q", s)
	case <-time.After(200 * time.Millisecond):
	}

	n.LoopPanic("ban-loop", 2, "again")
	select {
	case f := <-inbox:
		t.Errorf("the second panic wrote a row: %v", f)
	case <-time.After(200 * time.Millisecond):
	}

	n.LoopPanic("ban-loop", 3, "again")
	select {
	case f := <-inbox:
		if f["severity"] != SeverityCrit || f["consecutive"] != 3 {
			t.Errorf("the third panic's row: %v", f)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("the third panic wrote no row")
	}
	select {
	case p := <-posts:
		if p != "/crit" {
			t.Errorf("the third panic posted to %s, want the critical hook", p)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("the third panic posted nothing")
	}
	select {
	case s := <-m.sent:
		if !strings.Contains(s, "ban-loop loop stuck") {
			t.Errorf("mail subject %q", s)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("the third panic mailed nothing")
	}

	n.LoopPanic("ban-loop", 100, "again")
	select {
	case <-posts:
	case <-time.After(3 * time.Second):
		t.Fatal("the hundredth panic posted nothing")
	}
	<-m.sent
	<-inbox
	n.LoopPanic("ban-loop", 101, "again")
	select {
	case p := <-posts:
		t.Errorf("the 101st panic posted to %s", p)
	case <-time.After(200 * time.Millisecond):
	}
}
