package notifier

import (
	"testing"
	"time"
)

// TestPreviewChallengedTellsTheHourOnce: the hour's fifth challenged fetch
// tells the list, with the fetchers by count; the rest of the hour, and the
// next hours inside the cooldown, add nothing.
func TestPreviewChallengedTellsTheHourOnce(t *testing.T) {
	ib := &chanInbox{got: make(chan map[string]any, 8)}
	n := New(Config{}).WithInbox(ib)
	c := &fakeClock{t: time.Date(2026, 10, 22, 2, 10, 0, 0, time.UTC)}
	n.now = c.now
	for i := 0; i < 3; i++ {
		n.PreviewChallenged("Twitterbot", "geo")
	}
	n.PreviewChallenged("Slackbot", "geo")
	ib.none(t, "four fetches")
	n.PreviewChallenged("Twitterbot", "geo")
	f := ib.next(t, "the fifth fetch")
	if f["count"] != int64(5) || f["crawlers"] != "Twitterbot 4 / Slackbot 1" || f["axis"] != "geo" {
		t.Errorf("preview fields: %v", f)
	}
	for i := 0; i < 20; i++ {
		n.PreviewChallenged("Twitterbot", "geo")
	}
	ib.none(t, "the same hour again")
	c.add(3600)
	for i := 0; i < 10; i++ {
		n.PreviewChallenged("Twitterbot", "asn")
	}
	ib.none(t, "the next hour, inside the cooldown")
	c.add(6 * 3600)
	for i := 0; i < 5; i++ {
		n.PreviewChallenged("Discordbot", "asn")
	}
	f = ib.next(t, "a later hour, after the cooldown")
	if f["count"] != int64(5) || f["crawlers"] != "Discordbot 5" || f["axis"] != "asn" {
		t.Errorf("preview fields after the cooldown: %v", f)
	}
}

// TestPreviewChallengedHourResets: an hour with fewer than the floor tells
// nothing, and does not carry into the next.
func TestPreviewChallengedHourResets(t *testing.T) {
	ib := &chanInbox{got: make(chan map[string]any, 8)}
	n := New(Config{}).WithInbox(ib)
	c := &fakeClock{t: time.Date(2026, 10, 22, 2, 50, 0, 0, time.UTC)}
	n.now = c.now
	for i := 0; i < 4; i++ {
		n.PreviewChallenged("Twitterbot", "geo")
	}
	c.add(1200)
	for i := 0; i < 4; i++ {
		n.PreviewChallenged("Twitterbot", "geo")
	}
	ib.none(t, "four and four across the hour's edge")
	n.PreviewChallenged("Twitterbot", "geo")
	if f := ib.next(t, "the new hour's fifth"); f["count"] != int64(5) {
		t.Errorf("count = %v, want 5", f["count"])
	}
}
