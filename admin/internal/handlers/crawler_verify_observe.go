package handlers

import (
	"context"

	"github.com/unmask-sh/unmask/admin/internal/ban"
	"github.com/unmask-sh/unmask/admin/internal/crawlerverify"
)

// ObserveCrawlerForBan is the native-mode rDNS post-pass, wired to the nginxlog
// per-line observer.  Native has no daemon in the request path, so a forged
// crawler is caught here: for a crawler-claiming access-log line, verify the
// visitor (async, cached, load-capped -- via crawlerverify) and, if the claim is
// a forgery, write a ban so the plugin's ban-read enforces the operator's forged
// action on every subsequent request.
//
// No-op unless rDNS is enabled.  The verification never blocks (VerifyAsync);
// the ban lands from the second observation of that IP -- fine for a persistent
// per-IP verdict.  Idempotent: re-banning the same IP is an upsert.
func (h *Handler) ObserveCrawlerForBan(ip, ua string) {
	if h == nil || h.CrawlerVerify == nil || h.BanMgr == nil {
		return
	}
	snap := h.cfg()
	cv := snap.Nginx.CrawlerVerify
	if !cv.Enabled {
		return
	}
	// Respect the per-crawler enable state (skip a crawler the operator turned off).
	if claimed := crawlerverify.ClaimedCrawler(ua); claimed == "" || !cv.CrawlerActive(claimed) {
		return
	}
	// Skip a crawler-claim already covered by a bypass IP range: the range is
	// authoritative (same gate as forward-auth), so rDNS would be a redundant
	// lookup and a genuine in-range crawler is Verified anyway (never banned).
	// bypassMatchers is memoized on the settings pointer, so this is cheap.
	if h.bypassMatchers(snap, "").ipBypass.Match(ip) {
		return
	}
	action := cv.ResolvedForgedAction()
	banForged := func(crawler string) {
		h.BanMgr.AddWithSourceAction(context.Background(), ip, "", ban.SourceCrawlerForged, "forged "+crawler+" (rDNS)", "", action)
	}
	if r, ok := h.CrawlerVerify.Cached(ip, ua); ok {
		if r.Status == crawlerverify.Forged {
			banForged(r.Crawler)
		}
		return
	}
	h.CrawlerVerify.VerifyAsyncNotify(ip, ua, func(r crawlerverify.Result) {
		if r.Status == crawlerverify.Forged {
			banForged(r.Crawler)
		}
	})
}
