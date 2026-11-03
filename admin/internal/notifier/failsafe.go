package notifier

import (
	"fmt"
	"strings"
	"time"
)

// EventNativeFailsafe: the plugin's fail-safe stripped the nginx module
// (place-module.sh found no bundled module for the host's nginx, or
// `nginx -t` failed on unmask's configuration) and the configuration is
// rendered without it -- nginx runs, the admin answers, and nothing is
// challenged, banned or rate-limited.  The daemon sees the marker it leaves
// (handlers.RunNativeFailsafeWatch) and this is the alert: the one every
// operator wants, so it is gated on nothing but the notifications section
// being on, and it is critical while the module is out.  The clearing, when
// the module is wired again, is information on the same channels.
const EventNativeFailsafe = "native_failsafe"

// FailsafeReport is what the watch saw change.
type FailsafeReport struct {
	Active bool      // the module is out now (false: it is back)
	Reason string    // what place-module wrote as the cause ("" when it wrote none)
	Since  time.Time // when the marker was written (zero when unknown)
}

// NativeFailsafe sends the fail-safe alert by webhook and by mail.  The
// admin's list is not written here: the watch writes its own row, before
// this, in the same transaction of thought as reading the list's last row
// (so a restart in either state repeats nothing), and the row's fields are
// the ones the generic payload carries.
func (n *Notifier) NativeFailsafe(r FailsafeReport) {
	if n == nil {
		return
	}
	cfg := n.currentCfg()
	fields := map[string]any{
		"event":  EventNativeFailsafe,
		"active": r.Active,
		"reason": r.Reason,
		"site":   cfg.Sites,
		"ts":     time.Now().Unix(),
	}
	if !r.Since.IsZero() {
		fields["since"] = r.Since.Unix()
	}
	fields["severity"] = Severity(EventNativeFailsafe, fields)
	if cfg.Disabled {
		return
	}
	text := failsafeLine(r, cfg.Sites)
	if u, f := cfg.hookFor(EventNativeFailsafe, fields); u != "" {
		go n.send(u, f, EventNativeFailsafe, fields, text)
	}
	go n.sendMail(failsafeSubject(r, cfg.Sites), failsafeMail(r, text))
}

// failsafeLine is the webhook's text.
func failsafeLine(r FailsafeReport, site string) string {
	if !r.Active {
		return "[OK] unmask: the nginx module is back; protection resumes once nginx reloads (restarts, when the module file changed)" + siteSuffix(site)
	}
	var b strings.Builder
	b.WriteString("[CRITICAL] unmask: the nginx module is not loaded; protection is OFF")
	b.WriteString(siteSuffix(site))
	b.WriteString("\nThe plugin's fail-safe stripped the module and rendered the configuration without it: nginx runs and the admin answers, but nothing is challenged, banned or rate-limited.")
	if r.Reason != "" {
		b.WriteString("\n• cause: ")
		b.WriteString(untrusted(r.Reason, reasonMax))
	}
	if !r.Since.IsZero() {
		b.WriteString("\n• since: ")
		b.WriteString(r.Since.UTC().Format("2006-01-02 15:04:05 UTC"))
	}
	b.WriteString("\n• run `unmask doctor` for the cause; once `nginx -t` passes with the module wired, the full configuration is rendered again")
	return b.String()
}

func failsafeSubject(r FailsafeReport, site string) string {
	what := "nginx module OFF: protection is off"
	if !r.Active {
		what = "nginx module back: protection resumes"
	}
	if site == "" {
		return "[unmask] " + what
	}
	return "[unmask:" + site + "] " + what
}

// failsafeMail is the mail's body: the webhook's text with what to do.
func failsafeMail(r FailsafeReport, text string) string {
	if !r.Active {
		return text + "\n"
	}
	return fmt.Sprintf("%s\n\nWhat to do:\n  - `unmask doctor` names the cause: an nginx the plugin has no module for (install a plugin build that has one, or build the module for it), or a configuration error (fix it).\n  - Then run `sh /usr/share/unmask/plugin/place-module.sh` or restart nginx (systemd runs it before each start); once `nginx -t` passes with the module wired, the marker clears and the full configuration is rendered.\n", text)
}
