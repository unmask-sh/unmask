package handlers

import (
	"strconv"

	"github.com/unmask-sh/unmask/admin/internal/classify"
	"github.com/unmask-sh/unmask/admin/internal/i18n"
	"github.com/unmask-sh/unmask/admin/internal/settings"
)

// The old-browser mark on a UA cell (the hunt log, its rankings and live
// tail, the stats page).
//
// The cell shows "Windows 10+ · Chrome 109", and whether 109 is last month's
// release or one from three years ago is something the reader has to know.
// The mark says it: a browser at least uaOldLag releases behind its current
// stable carries how far behind it is, and one that no longer ships carries
// "EOL".  A client that pins one old build -- a scraper with a hard-coded UA
// -- then stands out among visitors whose browsers update themselves.
//
// It is a reading aid and decides nothing.  A person on an old machine wears
// the same mark, and the stale-browser challenge has its own settings; this
// follows neither its switch nor its threshold.
//
// uaOldLag: Chrome and Firefox both ship a major every four weeks, so ten is
// roughly ten months.  Browsers that update themselves sit within a few
// releases of current, and the slow channels (extended stable, ChromeOS LTS)
// within about eight; past ten is a browser nobody is updating.
const uaOldLag = 10

// uaOldRead is classify.UABrowserLag against the automatic baselines: the
// newer of what the hub publishes and what this binary shipped with.  Not the
// operator's current_chrome_major, which tunes the challenge: the mark states
// how old a version is, and that does not depend on a setting.
func uaOldRead(summary string) (lag int, ended bool) {
	if summary == "" {
		return 0, false
	}
	curChrome, _ := settings.AutoChromeBaseline()
	curFirefox, _ := settings.AutoFirefoxBaseline()
	return classify.UABrowserLag(summary, curChrome, curFirefox, settings.GlobalConfig{}.FirefoxESRMajors())
}

// uaOldBadge is the mark for a UA summary: "−41" (a minus sign and the
// releases behind), "EOL", or "" when the browser is not old.
func uaOldBadge(summary string) string {
	lag, ended := uaOldRead(summary)
	switch {
	case ended:
		return "EOL"
	case lag >= uaOldLag:
		return "\u2212" + strconv.Itoa(lag)
	}
	return ""
}

// uaOldNote is the sentence behind the mark, for the popover of the cell that
// shows it; "" when there is no mark.  Takes the raw UA, as the cell does.
func uaOldNote(lang i18n.Lang, ua string) string {
	summary := classify.UASummary(ua)
	lag, ended := uaOldRead(summary)
	switch {
	case ended:
		return i18n.T(lang, "hunt.ua.old_ended")
	case lag >= uaOldLag:
		cur, _ := settings.AutoChromeBaseline()
		if _, b := classify.UASummaryParts(summary); len(b) >= 7 && b[:7] == "Firefox" {
			cur, _ = settings.AutoFirefoxBaseline()
		}
		return i18n.Tf(lang, "hunt.ua.old_behind", lag, cur)
	}
	return ""
}
