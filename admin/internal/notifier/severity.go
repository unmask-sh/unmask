package notifier

// How an alert is marked: in the admin's notification list, in the generic
// webhook payload (its "severity" field), and for the choice between the two
// hooks when the operator keeps one channel for the alerts that need a person
// now and one for the record.
const (
	SeverityInfo = "info"
	SeverityWarn = "warn"
	SeverityCrit = "crit"
)

// Severity is the mark of an event with its fields: the one table the list
// (internal/notice) and the hooks read, so what the bell shows as critical is
// what the critical hook gets.  A ban and the advisor's digest are
// information; a challenge burst and link previews stopped are warnings; the
// over-block breaker tripping is critical, and its clearing information.  An
// event this package does not send (the fail-safe row the daemon writes
// itself) is information here; its writer sets the mark.
func Severity(event string, fields map[string]any) string {
	switch event {
	case EventChallengeBurst, EventPreviewChallenged:
		return SeverityWarn
	case EventOverBlock:
		if tripped, _ := fields["tripped"].(bool); tripped {
			return SeverityCrit
		}
	}
	return SeverityInfo
}

// hookFor is the webhook URL an alert goes to, or "" when the channel is
// paused or has no hook for it.  With no critical hook every alert goes to
// URL.  With one, an alert whose severity reaches CriticalMinSeverity goes
// there and the rest to URL -- which may be empty, for an operator who wants
// to hear of the critical alerts alone.  The over-block breaker's clearing
// follows its trip: the channel that saw the alarm sees it end.
func (c Config) hookFor(event string, fields map[string]any) string {
	if c.WebhookDisabled {
		return ""
	}
	if c.CriticalURL == "" {
		return c.URL
	}
	sev := Severity(event, fields)
	critical := event == EventOverBlock || sev == SeverityCrit ||
		(sev == SeverityWarn && c.CriticalMinSeverity == SeverityWarn)
	if critical {
		return c.CriticalURL
	}
	return c.URL
}
