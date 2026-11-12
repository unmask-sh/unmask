package events

import (
	"bytes"
	"log"
	"strings"
	"sync"
	"testing"
	"time"
)

// syncBuffer collects log output from the flusher's goroutine.
type syncBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *syncBuffer) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}

// TestFlusherBacksOffAfterAFailedWrite: a write that fails keeps its events
// for a retry one interval later.  The buffer it leaves is past the batch
// size, and the batch-size trigger used to fire on that for every event that
// arrived meanwhile: one attempt and one log line per event, hundreds a
// second against a database that answers at once with an error.  Nothing is
// lost by waiting for the tick: when the database is back, everything kept is
// written.
func TestFlusherBacksOffAfterAFailedWrite(t *testing.T) {
	d := pruneTestDB(t)
	var logs syncBuffer
	old := log.Writer()
	log.SetOutput(&logs)
	defer log.SetOutput(old)

	const interval = 500 * time.Millisecond
	f := NewFlusher(d, 20, int(interval/time.Millisecond)) // a batch of 20
	defer f.Stop()
	if _, err := d.Exec(`ALTER TABLE unmask_event RENAME TO unmask_event_away`); err != nil {
		t.Fatal(err)
	}
	const sent = 300
	start := time.Now()
	for i := 0; i < sent; i++ {
		f.Submit(&Event{Site: "s", Host: "h", IPPacked: []byte{10, 0, 0, 1}, Phase: "serve"})
		time.Sleep(time.Millisecond)
	}
	elapsed := time.Since(start)
	failures := strings.Count(logs.String(), "events batch flush:")
	if failures == 0 {
		t.Fatal("no write was tried, so nothing was tested")
	}
	// One try per interval of the time the events took to arrive (a
	// millisecond's sleep is several on some machines), and one at each end.
	if most := int(elapsed/interval) + 2; failures > most {
		t.Errorf("%d failed writes logged in %v while %d events arrived: more than the %d an interval of %v allows", failures, elapsed.Round(time.Millisecond), sent, most, interval)
	}

	if _, err := d.Exec(`ALTER TABLE unmask_event_away RENAME TO unmask_event`); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(10 * time.Second)
	var stored int
	for time.Now().Before(deadline) {
		if err := d.QueryRow(`SELECT COUNT(*) FROM unmask_event`).Scan(&stored); err == nil && stored == sent {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if stored != sent {
		t.Errorf("%d of %d events were written once the database took writes again", stored, sent)
	}
}
