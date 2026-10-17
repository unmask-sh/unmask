package notifier

import (
	"fmt"
	"math"
	"time"
)

// A challenge burst is five minutes in which challenges come burstTimes as
// often as in an average five minutes of the hour before, and at least
// Config.BurstThresholdPer5m of them.
//
// A count alone cannot tell a burst.  What one site serves in a quiet five
// minutes another sees only under attack, so a fixed number is either
// passed all day on the busy sites or never reached on the quiet ones.
// Measured against the site's own last hour, a burst means the same thing on
// both; the operator's number stays as the floor under it, so a quiet site
// is not told when two challenges become twenty.
const (
	burstBucket   = 300       // seconds in one count; buckets start on the clock's five minutes
	burstHistory  = 12        // whole buckets the average is over: the hour before
	burstTimes    = 10        // how many times that average a bucket has to reach
	burstCooldown = time.Hour // the quiet after a notice: one surge, one notice
)

// burstState counts the challenges per bucket.  hist is a ring of the last
// burstHistory whole buckets and filled says how many it holds: the bucket
// counting began in (at the daemon's first challenge) is partial and is not
// one of them, so the comparison waits for a whole hour after that.
type burstState struct {
	bucket  int64 // the current bucket (unix seconds / burstBucket); 0 before the first challenge
	partial bool  // counting began inside the current bucket
	count   int64 // challenges in the current bucket so far
	told    bool  // the current bucket has given its notice
	hist    [burstHistory]int64
	pos     int
	filled  int
	last    time.Time // the last notice
}

// roll moves the count on to bucket b.  The bucket that ends joins the
// history, unless it was partial, and so does every bucket in between that
// had no challenge at all.
func (s *burstState) roll(b int64) {
	switch {
	case s.bucket == 0:
		s.bucket, s.partial = b, true
		return
	case b <= s.bucket: // the same bucket, or the clock stepped back
		return
	}
	if !s.partial {
		s.push(s.count)
	}
	for i := int64(1); i < b-s.bucket && i <= burstHistory; i++ {
		s.push(0)
	}
	s.bucket, s.partial, s.count, s.told = b, false, 0, false
}

func (s *burstState) push(v int64) {
	s.hist[s.pos] = v
	s.pos = (s.pos + 1) % burstHistory
	if s.filled < burstHistory {
		s.filled++
	}
}

// average is the challenges in an average bucket of the history, and false
// while the history is short of an hour.
func (s *burstState) average() (float64, bool) {
	if s.filled < burstHistory {
		return 0, false
	}
	var sum int64
	for _, v := range s.hist {
		sum += v
	}
	return float64(sum) / burstHistory, true
}

func (n *Notifier) clock() time.Time {
	if n.now != nil {
		return n.now()
	}
	return time.Now()
}

// ChallengeServed: call every time the challenge page is served.  It counts
// the challenge, and the moment its five minutes become a burst (above) it
// tells the admin's list -- whatever the switches say -- and, with the burst
// switch on, the webhook and the mail.  Nothing more for burstCooldown after
// a notice, nothing in the first hour of counting, which has no hour before
// it yet, and nothing while the floor is 0; the count runs then too, so the
// hour before is the real one when a floor is set again.
func (n *Notifier) ChallengeServed() {
	if n == nil {
		return
	}
	cfg := n.currentCfg()
	now := n.clock()
	n.mu.Lock()
	s := &n.burst
	s.roll(now.Unix() / burstBucket)
	s.count++
	avg, whole := s.average()
	floor := int64(cfg.BurstThresholdPer5m)
	threshold := max(floor, int64(math.Ceil(burstTimes*avg)))
	fire := floor > 0 && whole && !s.told && s.count >= threshold && now.Sub(s.last) >= burstCooldown
	if fire {
		s.told, s.last = true, now
	}
	count := s.count
	n.mu.Unlock()
	if !fire {
		return
	}
	baseline := int64(math.Round(avg))
	fields := map[string]any{
		"event":           EventChallengeBurst,
		"count_per_5m":    count,
		"threshold":       threshold,
		"baseline_per_5m": baseline,
		"site":            cfg.Sites,
		"ts":              now.Unix(),
	}
	n.toInbox(EventChallengeBurst, fields)
	if cfg.Disabled || !cfg.ChallengeBurst {
		return
	}
	text := fmt.Sprintf("[WARN] %d challenges within 5 minutes; the hour before averaged %d per 5 minutes%s", count, baseline, siteSuffix(cfg.Sites))
	if cfg.URL != "" && !cfg.WebhookDisabled {
		go n.send(cfg, EventChallengeBurst, fields, text)
	}
	subject := fmt.Sprintf("[unmask] challenge burst: %d/5min", count)
	if cfg.Sites != "" {
		subject = fmt.Sprintf("[unmask:%s] challenge burst: %d/5min", cfg.Sites, count)
	}
	go n.sendMail(subject, text)
}
