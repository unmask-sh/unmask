package main

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/unmask-sh/unmask/admin/internal/nginxconf"
	"github.com/unmask-sh/unmask/admin/internal/settings"
)

// crawlerRangesStaleAfter: how old the crawler range data may be before
// doctor says so.
const crawlerRangesStaleAfter = 30 * 24 * time.Hour

// checkCrawlerRanges: crawler IP-range freshness.  Range-verified crawler
// UAs (uarange.go) are rescued by their vendor's published IP ranges instead
// of the UA string, so range data that stops refreshing eventually
// challenges genuine crawlers arriving from newly added vendor IPs.
//
// Two dates say whether it refreshes.  The files in dir are written by every
// pull that takes a document, so their dates say that the pull runs.  The
// document's own generatedAt, which the pull records beside them, says that
// what the pull is handed is current -- and the first does not imply the
// second: a hub, a mirror or something on the way that keeps answering with
// the same document passes the pull every day (an equal date is no
// rollback) and the files are a day old for as long as that lasts.
//
// dir is the directory the pulls write to, the one nginxconf.SetOverrideDir
// was given; now is the moment the ages are measured from.
func checkCrawlerRanges(s settings.Settings, dir string, now time.Time, addOK, addWarn func(t, m string)) {
	inverted := nginxconf.RangeVerifiedUA(s.Nginx)
	if len(inverted) == 0 {
		return
	}
	const staleAfter = crawlerRangesStaleAfter
	days := func(t time.Time) int { return int(now.Sub(t).Hours() / 24) }
	hub := strings.TrimSpace(s.Nginx.SyncHubURL)
	if hub == "" {
		hub = nginxconf.SyncDefaultHubURL
	}
	need := map[string]bool{}
	for pat := range inverted {
		for _, id := range nginxconf.UARangePresets[pat] {
			need[id] = true
		}
	}
	var missing []string
	var oldestID string
	var oldest time.Time
	for i := range nginxconf.BypassIPGroups {
		g := &nginxconf.BypassIPGroups[i]
		if !need[g.ID] {
			continue
		}
		fi, err := os.Stat(filepath.Join(dir, filepath.Base(g.File)))
		if err != nil {
			missing = append(missing, g.ID)
			continue
		}
		if oldest.IsZero() || fi.ModTime().Before(oldest) {
			oldest, oldestID = fi.ModTime(), g.ID
		}
	}
	sort.Strings(missing)
	switch {
	case s.Nginx.SyncDisabled:
		// Switched off on purpose, so nothing is failing and "check the
		// sync" is not the advice: judge the data in use, which a newer
		// release's snapshot refreshes (the loader takes the newer copy).
		if at := nginxconf.SnapshotDataAt(); !at.IsZero() && now.Sub(at) <= staleAfter {
			addOK("crawler IP ranges", fmt.Sprintf(
				"scheduled pulls are off (sync_disabled); the range data in use was assembled %d days ago",
				days(at)))
		} else {
			addWarn("crawler IP ranges", fmt.Sprintf(
				"scheduled pulls are off (sync_disabled) and the range data in use is more than %d days old — %d crawler UA pattern(s) rely on it. Import a copy with `unmask update-iprange -file`, upgrade to a newer release, or switch the pulls back on (About tab).",
				int(staleAfter.Hours()/24), len(inverted)))
		}
	case len(missing) > 0:
		addWarn("crawler IP ranges", fmt.Sprintf(
			"%d crawler UA pattern(s) rely on vendor IP ranges, but these presets have never been synced (serving the compiled-in snapshot): %s. Check the daemon log for 'iprange sync' errors; a stale snapshot can eventually challenge genuine crawlers from new vendor IPs.",
			len(inverted), strings.Join(missing, ", ")))
	case now.Sub(oldest) > staleAfter:
		addWarn("crawler IP ranges", fmt.Sprintf(
			"synced range files are stale (oldest: %s, %d days) — %d crawler UA pattern(s) rely on them. Check the daemon's iprange sync against %s.",
			oldestID, days(oldest), len(inverted), hub))
	default:
		// The files were written lately.  What they were written from may
		// still be old (see above).  The data in use is the synced copy or
		// the release's built-in one, whichever is the newer, so both have
		// to be past the limit for there to be something to say.
		docAt, dataAt := nginxconf.SyncedDocumentAt(), nginxconf.SnapshotDataAt()
		if !docAt.IsZero() && now.Sub(docAt) > staleAfter && now.Sub(dataAt) > staleAfter {
			addWarn("crawler IP ranges", fmt.Sprintf(
				"the range files were written %d day(s) ago, but from a document generated %d days ago — the pull keeps being handed an old copy, and %d crawler UA pattern(s) rely on it. Check what answers at %s (a mirror or a cache in between), or import a current copy with `unmask update-iprange -file`.",
				days(oldest), days(docAt), len(inverted), hub))
			return
		}
		addOK("crawler IP ranges", fmt.Sprintf(
			"%d preset(s) back %d range-verified crawler UA pattern(s); oldest sync %dd ago",
			len(need), len(inverted), days(oldest)))
	}
}
