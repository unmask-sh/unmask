package nginxlog

import (
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// lineWith is an access-log line as nginx sends it, with the given site and
// the custom-rule id the test reads back (cr=).
func lineWith(site, cr string) string {
	return fmt.Sprintf("<190>Oct  1 00:00:00 h nginx: 1759276800.000 site=%s kind= fc=0 hp=0 ip=192.0.2.7 ja4=- hpuri=- bp=0 scheme=https cr=%s ua=Mozilla/5.0\n", site, cr)
}

func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// The receive goroutine reads the socket and queues; a worker handles the
// lines, in the order they arrived.  A stop handles what was queued before
// the final flush.
func TestLinesAreHandledInOrderOffTheReceiveGoroutine(t *testing.T) {
	path := sockPath(t, "log.sock")
	r := Start(path, handoverDB(t))
	var mu sync.Mutex
	var got []string
	r.SetRuleHit(func(id string) {
		mu.Lock()
		got = append(got, id)
		mu.Unlock()
	})
	r.Receive()
	nginx, err := net.DialUnix("unixgram", nil, &net.UnixAddr{Name: path, Net: "unixgram"})
	if err != nil {
		t.Fatal(err)
	}
	defer nginx.Close()
	const n = 200
	for i := 0; i < n; i++ {
		if _, err := nginx.Write([]byte(lineWith("s", fmt.Sprintf("r%d", i)))); err != nil {
			t.Fatal(err)
		}
	}
	waitFor(t, "every line to be handled", func() bool {
		mu.Lock()
		defer mu.Unlock()
		return len(got) == n
	})
	r.Close()
	for i, id := range got {
		if want := fmt.Sprintf("r%d", i); id != want {
			t.Fatalf("line %d handled as %q, want %q: the order was not kept", i, id, want)
		}
	}
	if d := r.DroppedLines(); d != 0 {
		t.Errorf("%d line(s) dropped with the queue never full", d)
	}
}

// A worker that is behind by a full queue costs lines at the receiver, not
// at nginx: they are dropped and counted, the socket is read on, and the
// lines that were queued are still handled.
func TestAFullQueueDropsLinesAndCountsThem(t *testing.T) {
	prev := recvQueueSize
	recvQueueSize = 4
	t.Cleanup(func() { recvQueueSize = prev })
	path := sockPath(t, "log.sock")
	r := Start(path, handoverDB(t))
	hold := make(chan struct{})
	var handled atomic.Int32
	r.SetRuleHit(func(id string) {
		handled.Add(1)
		<-hold // the worker is stuck on its first line until the test lets go
	})
	r.Receive()
	nginx, err := net.DialUnix("unixgram", nil, &net.UnixAddr{Name: path, Net: "unixgram"})
	if err != nil {
		t.Fatal(err)
	}
	defer nginx.Close()
	const n = 40
	for i := 0; i < n; i++ {
		if _, err := nginx.Write([]byte(lineWith("s", fmt.Sprintf("r%d", i)))); err != nil {
			t.Fatal(err)
		}
	}
	// Four lines in the queue and the rest dropped -- and one more in the
	// worker, or one more dropped, by whether the worker had taken its
	// first line before the queue filled.
	const kept = 4
	waitFor(t, "the receiver to have read every datagram", func() bool { return r.DroppedLines() >= n-kept-1 })
	close(hold)
	waitFor(t, "the queued lines to be handled", func() bool { return handled.Load()+int32(r.DroppedLines()) == n })
	r.Close()
	d, h := r.DroppedLines(), handled.Load()
	if d != n-kept-1 && d != n-kept {
		t.Errorf("dropped %d, want %d or %d", d, n-kept-1, n-kept)
	}
	if int(h)+int(d) != n || h < kept {
		t.Errorf("handled %d with %d dropped: the %d queued lines must be handled and every line accounted for", h, d, kept)
	}
}

func distinctSites(r *Reader) map[string]int {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := map[string]int{}
	for k, b := range r.buckets {
		out[k.site] += b.total
	}
	return out
}

// Past siteCapPerMinute distinct hosts in a minute, the rest of the minute's
// hosts count under OtherSite: a client varying the Host header cannot make
// the daemon hold a set of sketches, and the tables a row, per value.
func TestSitesPastTheCapAreFiledUnderOther(t *testing.T) {
	r := Start("", handoverDB(t))
	defer r.Close()
	const n = siteCapPerMinute + 44
	for i := 0; i < n; i++ {
		r.onLine(lineWith(fmt.Sprintf("h%d.example", i), ""))
	}
	sites := distinctSites(r)
	if len(sites) != siteCapPerMinute+1 {
		t.Fatalf("%d distinct sites in the buckets, want the cap (%d) and %s", len(sites), siteCapPerMinute, OtherSite)
	}
	if sites[OtherSite] != 44 {
		t.Errorf("%s counted %d requests, want 44", OtherSite, sites[OtherSite])
	}
	if sites["h0.example"] != 1 || sites[fmt.Sprintf("h%d.example", siteCapPerMinute-1)] != 1 {
		t.Error("a host within the cap must keep its own bucket")
	}
	// A host already counted this minute keeps its bucket past the cap.
	r.onLine(lineWith("h0.example", ""))
	if distinctSites(r)["h0.example"] != 2 {
		t.Error("a host counted before the cap was reached must go on counting under its own name")
	}
	// "default" (a line with no Host) is never folded.
	r.onLine(lineWith("", ""))
	if distinctSites(r)["default"] != 1 {
		t.Error("the default site must keep its own bucket past the cap")
	}
}

// With the site list in "defined" mode a Host that is not on it is filed
// under OtherSite at once -- while the honeypot callback still hears the
// Host as logged, since the trap's per-site rule is resolved by it.
func TestAHostOffTheDefinedListIsFiledUnderOther(t *testing.T) {
	r := Start("", handoverDB(t))
	defer r.Close()
	r.SetSiteCheck(func(site string) bool { return site == "a.example" })
	var trapSite string
	r.SetHoneypotCallback(func(ip, ja4, uri, site, scheme string) { trapSite = site })
	r.onLine(lineWith("a.example", ""))
	r.onLine(lineWith("b.example", ""))
	r.onLine("<190>Oct  1 00:00:00 h nginx: 1759276800.000 site=b.example kind= fc=1 hp=1 ip=192.0.2.9 ja4=- hpuri=/wp-login.php ua=curl/8\n")
	sites := distinctSites(r)
	if sites["a.example"] != 1 || sites[OtherSite] != 2 || sites["b.example"] != 0 {
		t.Errorf("buckets %v, want a.example=1 and %s=2 with no b.example", sites, OtherSite)
	}
	if trapSite != "b.example" {
		t.Errorf("the honeypot callback heard site %q, want the Host as logged", trapSite)
	}
}
