package communitybans

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"path/filepath"
	"strings"
	"time"

	"github.com/unmask-sh/unmask/admin/internal/settings"
)

// Pull: fetches the feed JSON and regenerates the map file.  Skipped when
// subscribe_mode is off (= returns nil, nil).  On success, updates
// settings.CommunityBans.LastPulledAt / Entries.
//
// A pull that does not reach the hub leaves the map files as the last one
// wrote them -- the install goes on enforcing what it knew -- except for the
// entries whose own expiry has passed since (dropExpired).
func (c *Client) Pull(ctx context.Context) (FeedDocument, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	doc, err := c.pull(ctx)
	if err != nil {
		c.dropExpired(c.SettingsGetter(), c.clock())
	}
	return doc, err
}

// clock: the time, which a test may set (Client.now).
func (c *Client) clock() time.Time {
	if c.now != nil {
		return c.now()
	}
	return time.Now()
}

// dropExpired takes out of the map files the entries that have passed their
// expiry since the pull that wrote them, and returns how many.  Under mu.
//
// An entry's expiry was looked at only when the files were written, and they
// are written by a pull that reached the hub.  While the hub could not be
// reached -- an outage there, a firewall here, for a day or for a month --
// every entry of the last good pull stayed in force, the ones the hub had
// meant to hold for another hour among them: a shared ban is on an address
// or a fingerprint that somebody else reported, and an address changes
// hands.  The guard's state keeps each applied entry's expiry beside the
// files, so the expiry holds without the hub.
//
// It only ever takes keys out.  The state may be older than the files (a
// daemon from before 0.1.58 wrote them, the mode was switched meanwhile);
// what it does not name stays as it is, and nothing is put back from it.
func (c *Client) dropExpired(cur settings.Settings, now time.Time) int {
	if !cur.CommunityBans.ApplyActive() {
		return 0
	}
	st := c.guardStateFor(cur)
	if len(st.Enforced) == 0 {
		return 0
	}
	drop := map[string]map[string]bool{}
	kept := make([]enforcedEntry, 0, len(st.Enforced))
	expired := 0
	for _, e := range st.Enforced {
		if e.ExpiresAt <= 0 || e.ExpiresAt >= now.Unix() {
			kept = append(kept, e)
			continue
		}
		expired++
		fe := FeedEntry{Match: e.Match, IP: e.IP, JA4: e.JA4}
		if file, key := mapFileKey(fe); file != "" && key != "" {
			if drop[file] == nil {
				drop[file] = map[string]bool{}
			}
			drop[file][key] = true
		}
		delete(st.Applied, MuteKey(fe))
	}
	if expired == 0 {
		return 0
	}
	st.Enforced = kept
	mapDir := c.resolveMapDir(cur)
	removed := 0
	for file, keys := range drop {
		n, err := removeMapKeys(filepath.Join(mapDir, file), keys)
		if err != nil {
			c.logf("communitybans: taking expired entries out of %s: %v", file, err)
		}
		removed += n
	}
	c.reloadMatcher(mapDir)
	c.saveGuardState(cur)
	c.logf("communitybans: the hub was not reached; %d entr(ies) past their expiry taken out of the map files (nginx applies it at its next reload)", removed)
	return removed
}

// pull is Pull's work, under mu.
func (c *Client) pull(ctx context.Context) (FeedDocument, error) {
	cur := c.SettingsGetter()
	mode := cur.CommunityBans.ResolvedSubscribeMode()

	// Resolve the output dir up front -- needed for both the off (= clear)
	// and active (= write) paths.  c.MapDir wins; else settings fall-backs.
	// Default = Nginx.OutputDir (= /var/lib/unmask/nginx/), which is already
	// the nginx-specific dir; no further sub-directory is needed.
	mapDir := c.resolveMapDir(cur)

	// off: stop pulling AND clear the map + in-memory doc cache so stale
	// entries don't keep enforcing / showing.  Empty map files keep nginx's
	// include valid.
	if mode == settings.SubscribeOff {
		empty := FeedDocument{GeneratedAt: time.Now().Unix(), Version: 2}
		_ = WriteMapFiles(empty, mapDir)
		c.reloadMatcher(mapDir)
		c.setCachedDoc(empty)
		if st := c.guardStateFor(cur); len(st.Enforced) > 0 {
			st.Enforced = nil // nothing is in the files to expire
			c.saveGuardState(cur)
		}
		return FeedDocument{}, nil
	}

	url := cur.CommunityBans.ResolvedFeedURL()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return FeedDocument{}, fmt.Errorf("new request: %w", err)
	}
	req.Header.Set("User-Agent", c.UserAgent)
	// Identify the install to the hub, so it can count deployments that are
	// actually running.  The feed itself stays public -- the hub serves the
	// same document with or without this header; all it does is move this
	// token's last_seen_at.  Without it the hub has no liveness signal at all:
	// last_seen_at is written at register and then only by a submit, so a
	// subscriber of many months reads identically to a registration that was
	// thrown away immediately.
	//
	// Off by operator choice (publish_liveness), and absent before a token
	// exists, in which case the pull is anonymous exactly as it was.
	if tok := strings.TrimSpace(cur.CommunityBans.Token); tok != "" && cur.CommunityBans.PublishLiveness {
		req.Header.Set("Authorization", "Bearer "+tok)
	}

	resp, err := c.httpClient().Do(req)
	if err != nil {
		return FeedDocument{}, fmt.Errorf("get feed: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		raw, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		return FeedDocument{}, fmt.Errorf("feed: status %d: %s", resp.StatusCode, string(raw))
	}

	var doc FeedDocument
	// Cap the body so a compromised / mis-configured hub can't drive admin
	// into an OOM by streaming a giant JSON (pull runs every hour on cron).
	if err := json.NewDecoder(io.LimitReader(resp.Body, 16<<20)).Decode(&doc); err != nil {
		return FeedDocument{}, fmt.Errorf("decode feed: %w", err)
	}
	capFeedText(doc.Entries)

	// Always cache the browse doc in memory (= both fetch and fetch_apply
	// show the list).  Replaces the legacy /etc/unmask/community-bans-doc.json
	// file -- nginx never read it, and admin restart is uncommon enough that
	// memory-only caching is fine (= a stale UI for one Pull cycle on cold
	// start is acceptable; the hub is back within the hour anyway).
	c.setCachedDoc(doc)

	// The clocks of guard.go run from the first sight of a promoted entry,
	// whether or not this install enforces yet: an entry promoted a day ago
	// is applied the moment enforcement is switched on.
	now := time.Now()
	st := c.guardStateFor(cur)
	observePromoted(doc.Entries, st, now)

	// Enforcement is fetch_apply-only.  In "fetch" mode the maps are written
	// empty so nginx sees the entries for browsing (via the doc) but never
	// challenges traffic, and a previous fetch_apply's maps are cleared.
	//
	// Community entries are intentionally NOT copied into the local
	// unmask_ban table -- the nginx maps are the sole enforcement surface
	// for community feeds.  "BAN 管理" stays a list of *this install's own*
	// decisions (= manual / honeypot / 5-axes).  The "共有 BAN" tab is the
	// single UI for browsing what arrived from the hub.
	if cur.CommunityBans.ApplyActive() {
		// Whitelisted-crawler guard: never enforce a feed entry whose IP
		// falls in a bypass preset / bypass-IP range (= Googlebot, Bingbot,
		// GPTBot official ranges, internal LBs).  The challenge path already
		// exempts $is_bypass_ip, but writing such an IP into the map would
		// still lock search-engine traffic to CAPTCHA on the native plugin
		// path -- strip those entries before the map files; the browse doc
		// above keeps them for visibility.
		enforce := doc
		if kept, skipped := excludeBypassedEntries(doc.Entries, NewBypassMatcher(cur)); skipped > 0 {
			enforce.Entries = kept
			c.logf("communitybans: excluded %d whitelisted-crawler entr(ies) from enforcement (search-engine accident guard)", skipped)
		}
		// Local mutes: install-specific opt-outs from the "共有 BAN" tab.
		// Bypassed entries are dropped first (= secure default for crawler
		// IPs) so the mute count below reflects only operator-initiated
		// silences.
		if kept, skipped := excludeMutedEntries(enforce.Entries, cur.CommunityBans.LocalMutes); skipped > 0 {
			enforce.Entries = kept
			c.logf("communitybans: muted %d entr(ies) per LocalMutes", skipped)
		}
		// Last, the limits on what one pull may switch on (guard.go): a
		// current browser's fingerprint never, a new ja4_only entry after a
		// day, and at most ApplyCap entries new to this install per pull.
		kept, held, pend := guardEntries(enforce.Entries, st, now)
		enforce.Entries = kept
		c.setPending(pend, held)
		st.Enforced = enforcedOf(kept, now.Unix())
		c.saveGuardState(cur)
		if pend.Total() > 0 {
			c.logf("communitybans: %d promoted entr(ies) held back: %d on a current browser's JA4, %d in the %s grace for a new ja4_only entry, %d over the cap of %d new entries per pull, %d on an address no visitor comes from (loopback, private, link-local, carrier NAT)",
				pend.Total(), pend.Majors, pend.Grace, GraceJA4, pend.Capped, ApplyCap, pend.Local)
		}
		keyMax := 0
		if c.MapKeyMax != nil {
			keyMax = c.MapKeyMax(cur)
		}
		if err := WriteMapFilesLimited(enforce, mapDir, keyMax); err != nil {
			return doc, fmt.Errorf("write map files: %w", err)
		}
		c.reloadMatcher(mapDir)
	} else {
		// Nothing is applied: the next switch to fetch_apply starts from
		// nothing, under the cap.
		st.Applied = map[string]int64{}
		st.Enforced = nil
		c.setPending(Pending{}, nil)
		c.saveGuardState(cur)
		empty := FeedDocument{GeneratedAt: time.Now().Unix(), Version: doc.Version}
		if err := WriteMapFiles(empty, mapDir); err != nil {
			return doc, fmt.Errorf("clear map files: %w", err)
		}
		c.reloadMatcher(mapDir)
	}

	cnt := len(doc.Entries)
	if err := c.SettingsUpdate(func(s *settings.Settings) {
		s.CommunityBans.LastPulledAt = now.Unix()
		s.CommunityBans.Entries = cnt
	}); err != nil {
		c.logf("communitybans: persist pull state: %v", err)
	}
	c.logf("communitybans: pulled %d entries from %s", cnt, redactURL(url))
	return doc, nil
}

// capFeedText bounds each free-text field of a feed entry (Reason / Reasoning /
// per-Comment text) so a hostile or buggy hub entry with a multi-KB string can't
// make the community-bans page's html/template render slow per entry (L-4).  The
// whole body is already capped to 16 MiB at decode; this caps each field.  Byte
// cap backed off to a UTF-8 boundary so the trim never leaves a half rune.
func capFeedText(entries []FeedEntry) {
	const max = 2000
	clip := func(s string) string {
		if len(s) <= max {
			return s
		}
		n := max
		for n > 0 && s[n]&0xC0 == 0x80 { // back off mid-rune continuation bytes
			n--
		}
		return s[:n]
	}
	for i := range entries {
		entries[i].Reason = clip(entries[i].Reason)
		entries[i].Reasoning = clip(entries[i].Reasoning)
		for j := range entries[i].Comments {
			entries[i].Comments[j].Text = clip(entries[i].Comments[j].Text)
		}
	}
}

// redactURL: strips secret-bearing parts before logging a feed URL -- the query
// string and any userinfo (scheme://user:token@host).  The path is kept for
// debuggability; if a future feed URL carries a token in the path, mask it here
// too (L-3).
func redactURL(u string) string {
	if i := strings.IndexByte(u, '?'); i > 0 {
		u = u[:i]
	}
	if at := strings.IndexByte(u, '@'); at > 0 {
		if p := strings.Index(u, "://"); p >= 0 && p+3 < at {
			u = u[:p+3] + u[at+1:]
		}
	}
	return u
}
