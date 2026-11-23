package dashboard

import (
	"testing"
	"time"
)

// A pass folds up to the MAX(id) seen at least the settling time before it:
// nothing while no sighting is that old, then the last one that is.  With no
// settling time it is the sighting of the pass itself.
func TestSeenIDsGiveTheIDSettledLongEnoughAgo(t *testing.T) {
	var s seenIDs
	t0 := time.Date(2026, 11, 24, 4, 0, 0, 0, time.UTC)
	if _, ok := s.note(t0, 100, 30*time.Second); ok {
		t.Fatal("a fence from the first sighting, with nothing seen 30s before")
	}
	if _, ok := s.note(t0.Add(10*time.Second), 120, 30*time.Second); ok {
		t.Fatal("a fence from sightings 10s old")
	}
	if f, ok := s.note(t0.Add(60*time.Second), 180, 30*time.Second); !ok || f != 120 {
		t.Fatalf("fence %d (ok %v) a minute on; want 120, the last sighting at least 30s old", f, ok)
	}
	if len(s.seen) != 2 {
		t.Errorf("%d sightings kept; the ones before the settled one are of no more use", len(s.seen))
	}
	if f, ok := s.note(t0.Add(70*time.Second), 190, 0); !ok || f != 190 {
		t.Fatalf("fence %d (ok %v) with no settling time; want the sighting itself", f, ok)
	}
}
