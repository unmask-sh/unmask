// notifier_advisor.go — the advisor's scheduled digest, carried by the same
// webhook / mail channels as every other alert.
//
// Kept in its own file so the advisor feature adds nothing to notifier.go.
// The event rides the existing send / sendMail paths, so the operator's pause
// switches, recipient list and payload format apply to it unchanged.
package notifier

import (
	"fmt"
	"time"
)

// AdvisorDigest reports ban candidates the scheduled advisor pass found since
// the previous digest.  Advisory only -- nothing has been blocked -- so it is
// gated on BanEvents (an operator who does not want ban-shaped notifications
// does not want these either) rather than introducing a separate switch.
func (n *Notifier) AdvisorDigest(newCount, total int, body string) {
	if n == nil || newCount <= 0 {
		return
	}
	cfg := n.currentCfg()
	fields := map[string]any{
		"event":            EventAdvisorDigest,
		"new_candidates":   newCount,
		"total_candidates": total,
		"site":             cfg.Sites,
		"ts":               time.Now().Unix(),
	}
	fields["severity"] = Severity(EventAdvisorDigest, fields)
	n.toInbox(EventAdvisorDigest, fields)
	if cfg.Disabled || !cfg.BanEvents {
		return
	}
	subject := fmt.Sprintf("[unmask] %d new ban candidate(s)", newCount)
	if cfg.Sites != "" {
		subject = fmt.Sprintf("[unmask %s] %d new ban candidate(s)", cfg.Sites, newCount)
	}
	if u := cfg.hookFor(EventAdvisorDigest, fields); u != "" {
		n.send(u, cfg.Format, EventAdvisorDigest, fields, body)
	}
	n.sendMail(subject, body)
}
