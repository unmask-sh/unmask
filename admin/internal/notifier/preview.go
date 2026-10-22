package notifier

import (
	"fmt"
	"sort"
	"strings"
	"time"
)

// A link-preview fetcher that the country or ASN axis sent to the challenge
// is a card that did not render: the fetcher solves nothing, the post goes
// out without its image, and nothing on the page says so -- the operator
// hears from the people whose posts went bare, hours later.  So the hour's
// first few such fetches tell the admin's list.
//
// The count is per clock hour and the floor is small: a site shares links a
// few times an hour, not hundreds, and every one of them is a preview that
// did not render.  One notice, then quiet for previewCooldown: the rule
// stays where it is until the operator moves it, and the list does not need
// to say so every hour.
const (
	EventPreviewChallenged = "preview_challenged"

	previewFloor    = 5             // challenged fetches in one hour before the list is told
	previewCooldown = 6 * time.Hour // the quiet after a notice
)

// previewState counts the hour's challenged fetches, by crawler name.
type previewState struct {
	hour  int64 // the clock hour the counts are of (unix seconds / 3600)
	count map[string]int64
	total int64
	told  bool      // this hour has given its notice
	last  time.Time // the last notice
}

// PreviewChallenged: call when the challenge page is served to a link-preview
// fetcher that a country or ASN rule stopped (axis is "geo" or "asn").  The
// hour's previewFloor-th such fetch tells the admin's list -- whatever the
// switches say -- and, with the burst switch on, the webhook and the mail;
// then nothing for previewCooldown.
func (n *Notifier) PreviewChallenged(crawler, axis string) {
	if n == nil || crawler == "" {
		return
	}
	cfg := n.currentCfg()
	now := n.clock()
	n.mu.Lock()
	s := &n.preview
	if h := now.Unix() / 3600; h != s.hour {
		s.hour, s.count, s.total, s.told = h, map[string]int64{}, 0, false
	}
	s.count[crawler]++
	s.total++
	fire := !s.told && s.total >= previewFloor && now.Sub(s.last) >= previewCooldown
	if fire {
		s.told, s.last = true, now
	}
	total := s.total
	names := make([]string, 0, len(s.count))
	for name := range s.count {
		names = append(names, name)
	}
	sort.Slice(names, func(i, j int) bool {
		if s.count[names[i]] != s.count[names[j]] {
			return s.count[names[i]] > s.count[names[j]]
		}
		return names[i] < names[j]
	})
	parts := make([]string, 0, len(names))
	for _, name := range names {
		parts = append(parts, fmt.Sprintf("%s %d", name, s.count[name]))
	}
	n.mu.Unlock()
	if !fire {
		return
	}
	crawlers := strings.Join(parts, " / ")
	fields := map[string]any{
		"event":    EventPreviewChallenged,
		"count":    total,
		"crawlers": crawlers,
		"axis":     axis,
		"site":     cfg.Sites,
		"ts":       now.Unix(),
	}
	n.toInbox(EventPreviewChallenged, fields)
	if cfg.Disabled || !cfg.ChallengeBurst {
		return
	}
	rule := "country"
	if axis == "asn" {
		rule = "network"
	}
	text := fmt.Sprintf("[WARN] %d link-preview fetches this hour met a %s rule's challenge (%s); those previews did not render%s", total, rule, crawlers, siteSuffix(cfg.Sites))
	if cfg.URL != "" && !cfg.WebhookDisabled {
		go n.send(cfg, EventPreviewChallenged, fields, text)
	}
	subject := fmt.Sprintf("[unmask] link previews challenged: %d this hour", total)
	if cfg.Sites != "" {
		subject = fmt.Sprintf("[unmask:%s] link previews challenged: %d this hour", cfg.Sites, total)
	}
	go n.sendMail(subject, text)
}
