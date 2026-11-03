package notifier

import (
	"fmt"
	"time"
)

// EventLoopPanic: an iteration of one of the daemon's loops -- the events
// flusher, the ban loop, the access-log flush -- panicked and was recovered
// (safe.Guard), and the loop goes on after a wait.  Once is a warning in the
// admin's list, with the loop's name and the panic's words: a bug to report,
// nothing lost but one iteration's work.  panicAlertAt in a row is the loop
// stuck on something that comes back every time -- the file, the table or
// the counters it keeps are not being written -- and that is critical, on
// the webhook and in the mail; then every hundredth, so a loop stuck for
// days is heard of again without flooding.
const (
	EventLoopPanic = "loop_panic"
	panicAlertAt   = 3
)

// LoopPanic: the hook the guards call (safe.SetOnPanic) with the loop's
// name, the count of consecutive panics and the panic's value.
func (n *Notifier) LoopPanic(loop string, consecutive int, value string) {
	if n == nil || consecutive < 1 {
		return
	}
	if consecutive != 1 && consecutive != panicAlertAt && consecutive%100 != 0 {
		return
	}
	cfg := n.currentCfg()
	fields := map[string]any{
		"event":       EventLoopPanic,
		"loop":        loop,
		"consecutive": consecutive,
		"value":       untrusted(value, fieldMax),
		"site":        cfg.Sites,
		"ts":          time.Now().Unix(),
	}
	fields["severity"] = Severity(EventLoopPanic, fields)
	n.toInbox(EventLoopPanic, fields)
	if cfg.Disabled || consecutive < panicAlertAt {
		return
	}
	text := fmt.Sprintf("[CRITICAL] unmask: the %s loop has panicked %d times in a row (%s) and is retrying with a wait between tries; what it writes -- events, the ban list, the traffic counters -- waits with it. The daemon log has the stack; restart unmask if it does not clear, and report the log line%s",
		loop, consecutive, untrusted(value, fieldMax), siteSuffix(cfg.Sites))
	if u, f := cfg.hookFor(EventLoopPanic, fields); u != "" {
		go n.send(u, f, EventLoopPanic, fields, text)
	}
	subject := fmt.Sprintf("[unmask] %s loop stuck: %d panics in a row", loop, consecutive)
	if cfg.Sites != "" {
		subject = fmt.Sprintf("[unmask:%s] %s loop stuck: %d panics in a row", cfg.Sites, loop, consecutive)
	}
	go n.sendMail(subject, text+"\n")
}
