// Package ban: manage the persistent BAN list (= DB backed + file flush for nginx).
//
// How it works:
//   - source of truth: the DB (= unmask_ban table).  Carries metadata
//     (= source / reason / banned_by).  Used for admin UI listing, manual
//     unban, and statistics.
//   - nginx integration: write out a ban file
//     (= "<ip>|<ja4>|<source>|<action>" per line).  The unmask module
//     watches mtime, reloads, and exposes $unmask_banned (= 0/1) plus
//     $unmask_ban_action (= the chain mode for the ban source so the
//     server-block render can return 403 / redirect to challenge).
//
// Positioned as the shared substrate used by multiple features:
//   - source="honeypot" : tripped a honeypot path (= nginxlog hp=1 -> Add)
//   - source="manual"   : added manually from the admin UI / CLI
//   - source="protected_failed" / "rate_limit_abuse" / "ja4_loop" : v0.2+
//
// Design:
//   - IPs in the whitelist (= bypass_ips) are never banned.
//   - expires_at = 0 means permanent.  > 0 is a unix-sec deadline.
//   - prune deletes expired rows + file flush every 60s in a goroutine.
//   - Restored from DB across admin restart (= file is regenerated automatically).
package ban

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"syscall"
	"time"

	"gorm.io/gorm"
	"gorm.io/gorm/clause"

	"github.com/unmask-sh/unmask/admin/internal/db"
	"github.com/unmask-sh/unmask/admin/internal/safe"
)

const (
	SourceHoneypot        = "honeypot"
	SourceCrawlerForged   = "crawler_forged" // rDNS proved a UA's crawler claim false
	SourceManual          = "manual"
	SourceProtectedFailed = "protected_failed" // v0.2+
	SourceRateLimitAbuse  = "rate_limit_abuse" // v0.2+
	SourceJA4Loop         = "ja4_loop"         // v0.2+
	// SourceJA4Ranking: hunt → "上位 JA4" ranking から operator が選んで報告した
	// (= 特定 IP ではなく JA4 fingerprint 自体への評価).  hub はこれを受け取ると
	// 該当 entry を ja4_only として強く分類する (= judge.applySourceLean).
	SourceJA4Ranking = "ja4_ranking"
)

// ScopeIPJA4 / ScopeJA4Only / ScopeIPOnly drive which fields the C plugin
// matches against at request time.  The (ip, ja4) data columns hold full
// operator-entered info regardless of scope, so flipping the scope in the
// BAN modal does not lose the context.
const (
	ScopeIPJA4   = "ip_ja4"
	ScopeJA4Only = "ja4_only"
	ScopeIPOnly  = "ip_only"
)

// ValidateScope normalises operator input.  Empty / unknown values fall
// back to ScopeIPJA4 so the file flush never emits a malformed marker.
func ValidateScope(s string) string {
	switch s {
	case ScopeIPJA4, ScopeJA4Only, ScopeIPOnly:
		return s
	default:
		return ScopeIPJA4
	}
}

// DeriveScope: pick a scope from (ip, ja4) emptiness when the caller has
// not specified one explicitly.  Mirrors the legacy semantics: an empty
// IP with a JA4 fingerprint becomes ja4_only; the opposite becomes
// ip_only; everything else stays ip_ja4 (= exact tuple match).
func DeriveScope(ip, ja4 string) string {
	switch {
	case ip == "" && ja4 != "":
		return ScopeJA4Only
	case ja4 == "" && ip != "":
		return ScopeIPOnly
	default:
		return ScopeIPJA4
	}
}

// Entry: one ban record.
type Entry struct {
	ID        int64
	IP        string
	JA4       string
	Source    string
	Reason    string
	BannedAt  time.Time
	ExpiresAt time.Time // zero = permanent
	BannedBy  string    // username (= for manual) or empty (= automatic)
	Action    string    // per-row override; empty = source default at flush time
	Scope     string    // ip_ja4 / ja4_only / ip_only (= ScopeIPJA4 etc.)
	// Held: not a row yet.  Placed while a schema update held the database's
	// writes: in force from the file and the checks, written when the lock
	// is free.  No ID, so the page lifts it by its key (DropHeld).
	Held bool
}

// ActionResolver maps a ban source (= "honeypot" / "manual" /
// "community_bans") to the chain mode written into the ban file
// (= "deny" / "pow_only" / "pow_then_captcha" / "captcha_only").
// The admin wires this to settings.BansConfig.ResolveAction so the
// ban package keeps its zero-deps-on-settings boundary.  Nil = the
// action column flushes as "deny" for every row (= the safe default
// the nginx module treats as hard ban).
type ActionResolver func(source string) string

// Manager: ban management with the DB as the source of truth.  When
// filePath is empty, file flushing is skipped (= used in tests where
// nginx integration is unnecessary).
type Manager struct {
	DB       *db.DB
	filePath string
	flushed  bool          // the list has been written since start (see Flushed)
	duration time.Duration // default TTL for honeypot/auto bans.  0 = permanent
	// whitelistFn reports whether an IP is on the bypass allowlist (= preset
	// crawler ranges + operator bypass_ips, CIDR-aware).  Injected by the admin
	// via SetWhitelist over the live settings' IPBypassMatcher, so toggling a
	// preset / adding a bypass IP takes effect without a manager restart; nil =
	// nothing whitelisted.  wlMu guards it because honeypot auto-bans (the flush
	// goroutine via AddWithSource) read it while AdminSettingsSave swaps it.
	whitelistFn func(ip string) bool
	wlMu        sync.RWMutex
	// egressFn names the CDN an address is the origin-facing egress of
	// (cdn package: CloudFront, Cloudflare, Fastly, the operator's own), or
	// "" and false.  Such an address is shared by every customer of the
	// CDN, so no automatic ban is placed on it (AddWithSourceAction, AddAuto,
	// escalateIP), and one that is there -- from before, or placed by hand
	// elsewhere -- is left out of the file and the checks unless an
	// operator put it there (banned_by).  Injected by the admin like
	// whitelistFn, reading the live settings; nil = no address is one.
	egressFn func(ip string) (string, bool)
	// egressSkipped: the active rows the last flush left out of the file
	// for sitting on a CDN egress (EgressSkipped, for the pages).
	egressSkipped int
	mu            sync.Mutex
	dirty         bool
	stopCh        chan struct{}
	doneCh        chan struct{}

	// actionResolver: per-source action picker injected by the admin.
	// Read on every flush() so a settings change reflects on the next
	// 60s tick without a manager restart.
	actionResolver ActionResolver

	// OnCreated: callback invoked when a ban is successfully added (= so
	// notifier can stay decoupled).  Nil is fine.  Assigned by the caller
	// (= so the ban package does not depend on notifier).
	OnCreated func(ip, ja4, source, reason, bannedBy string)

	// held: the bans that arrived while the database's writes were held by a
	// schema update -- automatic ones from the access log, an operator's --
	// written once the lock is free.  heldFull: the list reached heldBansMax
	// and that has been logged.  lifted: the rows an operator unbanned
	// meanwhile, out of the file, the checks and the list from then on,
	// deleted once the lock is free.  All under mu.
	held     []heldBan
	heldFull bool
	lifted   map[int64]bool

	// flushMu makes one flush at a time.  A flush follows every addition,
	// and runs on the loop's tick too: an addition from the access log's
	// receive loop and a tick at the same moment would both write the one
	// temporary file, and the list nginx loads could be a mix of the two.
	flushMu sync.Mutex
	// writeHeldMu makes one writeHeld at a time: the loop's tick and the
	// daemon's shutdown (FlushHeld) can meet, and the kept bans stay listed
	// until they are written -- two at once would write and announce each
	// of them twice.
	writeHeldMu sync.Mutex
	// wake asks the loop to write the kept bans and the file now rather
	// than at its next tick: an automatic ban the receive loop could not
	// write at once.  Buffered by one; a wake while one waits is the same.
	wake chan struct{}
	// keptLoggedAt: when a ban kept for the loop was last logged (one line
	// a minute, not one a hit).  Under mu.
	keptLoggedAt   time.Time
	egressLoggedAt time.Time

	// mirror: the table's live bans in memory, what the checks read (see
	// mirror.go).  mirrorMu guards it; loadMu makes one load at a time.
	mirror   *mirror
	mirrorMu sync.RWMutex
	loadMu   sync.Mutex
	// flushTimer: a write of the file due at the end of the debounce window
	// (requestFlush).  lastFlushAt: when the file was last written; flushes:
	// how many times (the tests).  repeatTrips: automatic bans asked for on
	// a client already banned the same way (RepeatedTrips).  All under mu.
	flushTimer  *time.Timer
	lastFlushAt time.Time
	flushes     int
	repeatTrips uint64
}

// flushDebounce is the window within which requests to write the file are
// made one write: a burst of bans from the access log -- a scanner walking
// a subnet, a backlog after a hold -- wrote the whole file, with an fsync,
// once per ban.  The first request of a quiet period writes at once, so a
// lone ban reaches nginx without the wait; the rest of the window is one
// write at its end.  The checks do not wait for it: a ban is in the mirror
// (or kept) the moment it is placed.
const flushDebounce = 200 * time.Millisecond

// autoBanWriteWithin bounds the write of an automatic ban on the access log's
// receive loop.  Against another writer's transaction -- a backlog being
// written after a hold, the hourly aggregate -- the write would otherwise
// wait out the busy timeout, five seconds a hit, and the socket behind the
// loop drops what it cannot hold meanwhile (2026-10-17).
const autoBanWriteWithin = 300 * time.Millisecond

// SetActionResolver installs the per-source action picker.  Safe to call
// after Start (= reads happen on the flush goroutine).
func (m *Manager) SetActionResolver(r ActionResolver) {
	m.mu.Lock()
	m.actionResolver = r
	m.mu.Unlock()
}

// EffectiveAction reports how a ban record is enforced, using the SAME
// precedence flush() writes into the ban file: the per-row action if set, else
// the source's default via the resolver, else "deny" (the safe hard-ban
// fallback).  Used by the hunt UI to show an operator how a ban acts.
func (m *Manager) EffectiveAction(action, source string) string {
	if a := strings.TrimSpace(action); a != "" {
		return a
	}
	m.mu.Lock()
	resolver := m.actionResolver
	m.mu.Unlock()
	if resolver != nil {
		if a := strings.TrimSpace(resolver(source)); a != "" {
			return a
		}
	}
	return "deny"
}

// SetWhitelist installs the bypass-allowlist test.  Safe to call after Start
// (= reads happen on the flush goroutine + admin handlers).  The admin injects
// a closure over the live settings' IPBypassMatcher so a bypass change applies
// without a restart, and so honeypot auto-bans respect preset crawler CIDRs
// (Googlebot / Bingbot / GPTBot).  The previous literal-IP map could do neither
// -- the M-3 / DB-4 bug: a crawler that landed on a honeypot URI got banned,
// and a freshly added bypass IP was ignored until the next restart.
func (m *Manager) SetWhitelist(fn func(ip string) bool) {
	m.wlMu.Lock()
	m.whitelistFn = fn
	m.wlMu.Unlock()
}

// SetEgress installs the CDN-egress lookup (see egressFn).  Swapped on a
// settings save like the whitelist; nil clears it.
func (m *Manager) SetEgress(fn func(ip string) (string, bool)) {
	if m == nil {
		return
	}
	m.wlMu.Lock()
	m.egressFn = fn
	m.wlMu.Unlock()
}

// isEgress: the CDN ip is the egress of, if any.
func (m *Manager) isEgress(ip string) (string, bool) {
	if m == nil || ip == "" {
		return "", false
	}
	m.wlMu.RLock()
	fn := m.egressFn
	m.wlMu.RUnlock()
	if fn == nil {
		return "", false
	}
	return fn(ip)
}

// EgressSkipped: how many active bans the last flush left out of the file
// for sitting on a CDN's egress.
func (m *Manager) EgressSkipped() int {
	if m == nil {
		return 0
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.egressSkipped
}

// egressLog says once a minute that an automatic ban was withheld.
func (m *Manager) egressLog(ip, vendor, what string) {
	m.mu.Lock()
	say := time.Since(m.egressLoggedAt) > time.Minute
	if say {
		m.egressLoggedAt = time.Now()
	}
	m.mu.Unlock()
	if say {
		log.Printf("ban: %s is %s's origin-facing address, shared by every site behind that CDN: %s not placed (settings > Network: CDN egress)", ip, vendor, what)
	}
}

// isWhitelisted reports whether ip is on the bypass allowlist.  An empty ip or
// a nil fn (= not yet wired / test stub) means "not whitelisted".
func (m *Manager) isWhitelisted(ip string) bool {
	if ip == "" {
		return false
	}
	m.wlMu.RLock()
	fn := m.whitelistFn
	m.wlMu.RUnlock()
	return fn != nil && fn(ip)
}

// New: initialize the ban manager.  filePath="" disables file flush
// (= test stub).
func New(d *db.DB, filePath string, duration time.Duration) *Manager {
	return &Manager{
		DB:       d,
		filePath: filePath,
		duration: duration,
		stopCh:   make(chan struct{}),
		doneCh:   make(chan struct{}),
		wake:     make(chan struct{}, 1),
	}
}

// wakeLoop asks the loop to write what is kept, now.  Never waits.
func (m *Manager) wakeLoop() {
	select {
	case m.wake <- struct{}{}:
	default:
	}
}

// Start: launch the prune + flush goroutine.  Initial flush of the ban file.
func (m *Manager) Start() {
	if m == nil {
		return
	}
	// Migration (2026-05-31): community feed entries no longer copy into
	// unmask_ban.  Cleanup leftover rows from older installs once at startup
	// so the BAN management UI immediately reflects the new policy (= local
	// list shows only this install's own decisions).  nginx maps remain the
	// enforcement surface for community entries.  Best-effort: ignore errors.
	if res := m.DB.Gorm.Exec(`DELETE FROM unmask_ban WHERE source = ?`, "community_bans"); res.Error == nil && res.RowsAffected > 0 {
		log.Printf("ban: cleaned up %d legacy community_bans rows (= now map-only)", res.RowsAffected)
	}
	m.normalizeStoredIPs()
	if m.filePath != "" {
		if err := m.flush(); err != nil {
			log.Printf("ban: initial flush: %v", err)
		}
	} else {
		m.ensureMirror()
	}
	go m.loop()
}

// normalizeStoredIPs rewrites, once at start, the rows whose address is not
// in the spelling the request carries (normalizeIP): typed into a ban as
// "2001:DB8::1" or "2001:0db8::1" before the door fixed it, such a row
// matched nothing in nginx and nothing here.  A row whose fixed spelling
// another row already has is dropped for that row.  Few rows, so one at a
// time, on either database.
func (m *Manager) normalizeStoredIPs() {
	if m.DB == nil || m.DB.WritesHeld() {
		return
	}
	type row struct {
		id             int64
		ip, ja4, scope string
	}
	var fix []row
	rows, err := m.DB.QueryContext(context.Background(), `SELECT id, ip, ja4, scope FROM unmask_ban WHERE ip <> ''`)
	if err != nil {
		log.Printf("ban: reading the list to fix address spellings: %v", err)
		return
	}
	for rows.Next() {
		var r row
		if err := rows.Scan(&r.id, &r.ip, &r.ja4, &r.scope); err != nil {
			rows.Close()
			log.Printf("ban: reading the list to fix address spellings: %v", err)
			return
		}
		if normalizeIP(r.ip) != r.ip {
			fix = append(fix, r)
		}
	}
	rows.Close()
	fixed, dropped := 0, 0
	for _, r := range fix {
		want := normalizeIP(r.ip)
		var dup int64
		if err := m.DB.Gorm.Model(&db.Ban{}).Where("ip = ? AND ja4 = ? AND scope = ? AND id <> ?", want, r.ja4, r.scope, r.id).Count(&dup).Error; err != nil {
			log.Printf("ban: fixing the spelling of %q: %v", r.ip, err)
			continue
		}
		if dup > 0 {
			if err := m.DB.Gorm.Where("id = ?", r.id).Delete(&db.Ban{}).Error; err != nil {
				log.Printf("ban: dropping the duplicate row for %q: %v", r.ip, err)
				continue
			}
			dropped++
			continue
		}
		if err := m.DB.Gorm.Model(&db.Ban{}).Where("id = ?", r.id).Update("ip", want).Error; err != nil {
			log.Printf("ban: fixing the spelling of %q: %v", r.ip, err)
			continue
		}
		fixed++
	}
	if fixed > 0 || dropped > 0 {
		log.Printf("ban: %d address(es) rewritten in the spelling requests carry, %d duplicate row(s) dropped", fixed, dropped)
		m.markDirty()
	}
}

// Close: stop the goroutine + final flush.
func (m *Manager) Close() {
	if m == nil {
		return
	}
	select {
	case <-m.stopCh:
		return
	default:
		close(m.stopCh)
	}
	<-m.doneCh
	m.mu.Lock()
	if m.flushTimer != nil {
		m.flushTimer.Stop()
		m.flushTimer = nil
	}
	m.mu.Unlock()
	if m.filePath != "" {
		_ = m.flush()
	}
}

// Add: add a ban originating from a honeypot (= automatic).  Ignores
// whitelisted IPs.  An existing entry has its expires_at refreshed
// (= re-trip extends TTL, source is kept).
func (m *Manager) Add(ip, ja4 string) {
	m.AddWithSource(context.Background(), ip, ja4, SourceHoneypot, "", "")
}

// AddWithSource: add a ban with explicit source / reason / banned_by.
//
//	source="manual"    + bannedBy="admin"   - manual via admin UI / CLI
//	source="honeypot"  + bannedBy=""        - automatic (= via nginxlog hp=1)
//	source="protected_failed" etc.          - reserved for v0.2+
//
// reason is a free-form string (= shown in the UI).
func (m *Manager) AddWithSource(ctx context.Context, ip, ja4, source, reason, bannedBy string) {
	m.AddWithSourceAction(ctx, ip, ja4, source, reason, bannedBy, "")
}

// AddWithSourceAction is AddWithSource with an explicit per-row action (= the
// ban-file "<key>|<source>|<action>" action column).  action="" defers to the
// source default at flush/resolve time (= identical to AddWithSource); a valid
// chain mode (deny / pow_only / pow_then_captcha / captcha_only) pins the ban to
// that mode regardless of later DefaultAction edits.  The honeypot path uses
// this to make a per-preset action override persist on the ban itself, so both
// native (ban-file read) and forward-auth (banDecide rowAction) enforce the
// operator's per-preset choice on every subsequent request -- not just the first
// trip.  flush() writes EffectiveAction(action, source), so "" stays dynamic.
func (m *Manager) AddWithSourceAction(ctx context.Context, ip, ja4, source, reason, bannedBy, action string) {
	if m == nil {
		return
	}
	ip = normalizeIP(ip)
	ja4 = strings.TrimSpace(ja4)
	action = strings.TrimSpace(action)
	if ip == "" {
		return
	}
	if m.isWhitelisted(ip) {
		return
	}
	if bannedBy == "" {
		if vendor, ok := m.isEgress(ip); ok {
			m.egressLog(ip, vendor, "the "+source+" ban")
			return
		}
	}
	now := time.Now().Unix()
	// The client is banned this way already, and recently: nothing to
	// write, write out or announce (recentlyPlaced).
	if bannedBy == "" && m.recentlyPlaced(ip, ja4, source, action, now) {
		m.mu.Lock()
		m.repeatTrips++
		m.mu.Unlock()
		return
	}
	var expires int64
	// For manual permanent bans (= the caller manages duration separately),
	// use AddPermanent (provided separately).
	if m.duration > 0 {
		expires = now + int64(m.duration.Seconds())
	}
	if m.DB.WritesHeld() {
		// A schema update holds the write lock.  This runs on the access
		// log's receive loop (a honeypot hit), which must not stand still
		// for the busy timeout at every hit; and a ban that fails to write
		// is a ban that never happens.  Keep it, and write it when the lock
		// is free (loop).  It is enforced meanwhile: the ban file is
		// written from the database and the kept bans (reading goes on
		// under the hold), and the checks look at both.
		m.hold(heldBan{ip: ip, ja4: ja4, source: source, reason: reason, bannedBy: bannedBy,
			action: action, scope: DeriveScope(ip, ja4), bannedAt: now, expiresAt: expires})
		m.markDirty()
		m.requestFlush()
		return
	}
	// The write, within a bound (autoBanWriteWithin): this runs on the
	// access log's receive loop.  A write that cannot be made at once is
	// kept the way a hold keeps it -- in force from the file and the checks
	// -- and the loop writes it the moment it can.
	err := m.upsertWithin(ctx, autoBanWriteWithin, ip, ja4, source, reason, now, expires, bannedBy, action, DeriveScope(ip, ja4))
	if err != nil {
		m.hold(heldBan{ip: ip, ja4: ja4, source: source, reason: reason, bannedBy: bannedBy,
			action: action, scope: DeriveScope(ip, ja4), bannedAt: now, expiresAt: expires})
		m.markDirty()
		m.mu.Lock()
		say := time.Since(m.keptLoggedAt) > time.Minute
		if say {
			m.keptLoggedAt = time.Now()
		}
		m.mu.Unlock()
		if say {
			log.Printf("ban: the database did not take the write at once (%v); the ban is kept and enforced, and written when it can be", err)
		}
		m.wakeLoop()
		return
	}
	m.mirrorPut(mirrorEntry{ip: ip, ja4: ja4, scope: DeriveScope(ip, ja4), source: source, action: action,
		bannedBy: bannedBy, bannedAt: now, expiresAt: expires})
	m.markDirty()
	m.requestFlush()
	if m.OnCreated != nil {
		m.OnCreated(ip, ja4, source, reason, bannedBy)
	}
	if bannedBy == "" {
		if ja4 != "" {
			m.escalateIP(ctx, ip, source, action, now, expires)
		}
		m.escalate64(ctx, ip, source, action, now, expires)
	}
}

// AddAuto places a ban the daemon decided -- the proof-of-work pass budget's
// -- with an explicit scope, action and lifetime under its own source.  The
// bypass allowlist is honoured as everywhere; the write goes the way an
// automatic ban's does (kept and enforced when the database cannot take it
// at once); the row's action is pinned, since these sources have no default
// of their own and the fallback would be a hard deny.
func (m *Manager) AddAuto(ctx context.Context, ip, ja4, scope, source, reason, action string, expiresSec int64) {
	if m == nil {
		return
	}
	ip, ja4 = normalizeIP(ip), strings.TrimSpace(ja4)
	if ip == "" || m.isWhitelisted(ip) || validateBanKey(ip, ja4) != nil {
		return
	}
	if vendor, ok := m.isEgress(ip); ok {
		m.egressLog(ip, vendor, "the "+source+" ban")
		return
	}
	if scope == "" || (ja4 == "" && (scope == ScopeIPJA4 || scope == ScopeJA4Only)) {
		scope = DeriveScope(ip, ja4)
	} else {
		scope = ValidateScope(scope)
	}
	action = strings.TrimSpace(action)
	now := time.Now().Unix()
	var expires int64
	if expiresSec > 0 {
		expires = now + expiresSec
	}
	keep := func() {
		m.hold(heldBan{ip: ip, ja4: ja4, source: source, reason: reason,
			action: action, scope: scope, bannedAt: now, expiresAt: expires})
		m.markDirty()
		m.requestFlush()
	}
	if m.DB.WritesHeld() {
		keep()
		return
	}
	if err := m.upsertWithin(ctx, autoBanWriteWithin, ip, ja4, source, reason, now, expires, "", action, scope); err != nil {
		keep()
		m.wakeLoop()
		return
	}
	m.mirrorPut(mirrorEntry{ip: ip, ja4: ja4, scope: scope, source: source, action: action, bannedAt: now, expiresAt: expires})
	m.markDirty()
	m.requestFlush()
	if m.OnCreated != nil {
		m.OnCreated(ip, ja4, source, reason, "")
	}
	if scope == ScopeIPJA4 && ja4 != "" {
		m.escalateIP(ctx, ip, source, action, now, expires)
	}
	m.escalate64(ctx, ip, source, action, now, expires)
}

// AddManual: manual BAN from the admin / CLI.  expiresSec=0 -> permanent.
// action="" defers to settings.Bans.ManualDefaultAction at flush time;
// pass a valid chain mode (= deny / pow_only / pow_then_captcha /
// captcha_only) to override per row.
// validateBanKey rejects an ip or ja4 containing the ban-file field separator
// '|' or a newline, which would corrupt a line of the flushed ban file
// ("<key>|<source>|<action>") and could smuggle an extra entry.  Manual entry
// is admin-role only, so this is defense-in-depth against a self-inflicted
// malformed file (L-1).
func validateBanKey(ip, ja4 string) error {
	if strings.ContainsAny(ip, "|\n\r") || strings.ContainsAny(ja4, "|\n\r") {
		return errors.New("ip / ja4 must not contain '|' or newline characters")
	}
	return nil
}

func (m *Manager) AddManual(ctx context.Context, ip, ja4, reason, bannedBy, action string, expiresSec int64) error {
	return m.AddManualWithScope(ctx, ip, ja4, "", reason, bannedBy, action, expiresSec)
}

// AddManualWithScope is the explicit-scope variant.  Pass scope="" to fall
// back to DeriveScope(ip, ja4) — the BAN modal hands it explicitly so the
// operator's dropdown choice survives even when both fields are filled.
func (m *Manager) AddManualWithScope(ctx context.Context, ip, ja4, scope, reason, bannedBy, action string, expiresSec int64) error {
	if m == nil {
		return errors.New("manager nil")
	}
	ip = normalizeIP(ip)
	ja4 = strings.TrimSpace(ja4)
	if ip == "" && ja4 == "" {
		return errors.New("ip or ja4 is required")
	}
	if m.isWhitelisted(ip) {
		return errors.New("ip is on bypass whitelist")
	}
	if err := validateBanKey(ip, ja4); err != nil {
		return err
	}
	if scope == "" {
		scope = DeriveScope(ip, ja4)
	} else {
		scope = ValidateScope(scope)
	}
	if err := validateScopeKey(ip, ja4, scope); err != nil {
		return err
	}
	now := time.Now().Unix()
	var expiresAt int64
	if expiresSec > 0 {
		expiresAt = now + expiresSec
	}
	if m.DB.WritesHeld() {
		// A schema update holds the write lock.  The operator's ban is kept
		// the way an automatic one is -- in force from the file and the
		// checks at once, written when the lock is free -- and announced
		// now, since the operator is here now; the write does not announce
		// it again.  A full list is an error the operator sees, not a ban
		// that silently never happens.
		if !m.hold(heldBan{ip: ip, ja4: ja4, source: SourceManual, reason: reason, bannedBy: bannedBy,
			action: strings.TrimSpace(action), scope: scope, bannedAt: now, expiresAt: expiresAt, announced: true}) {
			return ErrHeldFull
		}
		m.markDirty()
		m.requestFlush()
		if m.OnCreated != nil {
			m.OnCreated(ip, ja4, SourceManual, reason, bannedBy)
		}
		return nil
	}
	if err := m.upsert(ctx, ip, ja4, SourceManual, reason, now, expiresAt, bannedBy, strings.TrimSpace(action), scope); err != nil {
		return err
	}
	m.mirrorPut(mirrorEntry{ip: ip, ja4: ja4, scope: scope, source: SourceManual, action: strings.TrimSpace(action),
		bannedBy: bannedBy, bannedAt: now, expiresAt: expiresAt})
	m.markDirty()
	m.requestFlush()
	if m.OnCreated != nil {
		m.OnCreated(ip, ja4, SourceManual, reason, bannedBy)
	}
	return nil
}

// validateScopeKey checks that the key fields a scope matches on are there,
// and that a prefix ("203.0.113.0/24", "2001:db8:1:2::/64") is used only as
// an address-wide ban: the module matches a prefix row against the address
// alone, so a fingerprint beside it would be a condition it never reads.
func validateScopeKey(ip, ja4, scope string) error {
	if scope == ScopeIPJA4 && (ip == "" || ja4 == "") {
		return errors.New("ip_ja4 scope requires both ip and ja4")
	}
	if scope == ScopeJA4Only && ja4 == "" {
		return errors.New("ja4_only scope requires ja4")
	}
	if scope == ScopeIPOnly && ip == "" {
		return errors.New("ip_only scope requires ip")
	}
	if strings.IndexByte(ip, '/') >= 0 {
		if _, ok := parsePrefixKey(ip); !ok {
			return errors.New("ip is neither an address nor a prefix (CIDR)")
		}
		if scope != ScopeIPOnly {
			return errors.New("a prefix (CIDR) bans the addresses in it: use the ip_only scope")
		}
	}
	return nil
}

// UpdateManual edits an existing manual-source row's mutable fields
// (= ip, ja4, reason, action, expires).  Restricted to source=manual so
// the honeypot / community_bans flusher that owns those rows is never
// raced by an operator click.  Same (ip, ja4) constraints as AddManual:
// at least one of the pair must be non-empty, and a non-empty ip must
// not be on the bypass whitelist.  UNIQUE (ip, ja4) collisions are
// surfaced as a user-friendly error so the dialog can show "another row
// already covers this fingerprint" instead of a generic SQL message.
func (m *Manager) UpdateManual(ctx context.Context, id int64, ip, ja4, scope, reason, action string, expiresSec int64) error {
	if m == nil {
		return errors.New("manager nil")
	}
	if m.DB.WritesHeld() {
		// An edit rewrites a row: nothing to keep in memory for it.  The
		// page says why and when to come back.
		return db.ErrWritesHeld
	}
	ip = normalizeIP(ip)
	ja4 = strings.TrimSpace(ja4)
	if ip == "" && ja4 == "" {
		return errors.New("ip or ja4 is required")
	}
	if m.isWhitelisted(ip) {
		return errors.New("ip is on bypass whitelist")
	}
	if err := validateBanKey(ip, ja4); err != nil {
		return err
	}
	if scope == "" {
		scope = DeriveScope(ip, ja4)
	} else {
		scope = ValidateScope(scope)
	}
	if err := validateScopeKey(ip, ja4, scope); err != nil {
		return err
	}
	var expiresAt int64
	if expiresSec > 0 {
		expiresAt = time.Now().Unix() + expiresSec
	}
	// Pre-check the UNIQUE (ip, ja4) collision so the SQL error never
	// reaches the caller (= portable across sqlite / mariadb).
	var dup int64
	if err := m.DB.Gorm.WithContext(ctx).Model(&db.Ban{}).
		Where("ip = ? AND ja4 = ? AND scope = ? AND id <> ?", ip, ja4, scope, id).
		Count(&dup).Error; err != nil {
		return err
	}
	if dup > 0 {
		return errors.New("another entry already covers this (ip, ja4, scope)")
	}
	res := m.DB.Gorm.WithContext(ctx).Model(&db.Ban{}).
		Where("id = ? AND source = ?", id, SourceManual).
		Updates(map[string]any{
			"ip":         ip,
			"ja4":        ja4,
			"reason":     reason,
			"expires_at": expiresAt,
			"action":     strings.TrimSpace(action),
			"scope":      scope,
		})
	if res.Error != nil {
		return res.Error
	}
	if res.RowsAffected == 0 {
		return errors.New("not found or row is not editable (= non-manual source)")
	}
	m.reloadMirror()
	m.markDirty()
	m.requestFlush()
	return nil
}

// Remove: unban (= remove the entry).  Disappears from the file on the next flush.
func (m *Manager) Remove(ctx context.Context, id int64) error {
	if m == nil {
		return errors.New("manager nil")
	}
	if m.DB.WritesHeld() {
		// The row cannot be deleted while a schema update holds the write
		// lock.  It is lifted now all the same: out of the file, the checks
		// and the list from here, deleted when the lock is free.
		var n int
		if err := m.DB.QueryRowContext(ctx, `SELECT COUNT(*) FROM unmask_ban WHERE id = ?`, id).Scan(&n); err != nil {
			return err
		}
		if n == 0 {
			return errors.New("not found")
		}
		m.mu.Lock()
		if m.lifted == nil {
			m.lifted = map[int64]bool{}
		}
		m.lifted[id] = true
		m.mu.Unlock()
		m.markDirty()
		m.requestFlush()
		return nil
	}
	res := m.DB.Gorm.WithContext(ctx).Where("id = ?", id).Delete(&db.Ban{})
	if res.Error != nil {
		return res.Error
	}
	if res.RowsAffected == 0 {
		return errors.New("not found")
	}
	m.reloadMirror()
	m.markDirty()
	m.requestFlush()
	return nil
}

// heldBan is a ban that could not be written while the database's writes
// were held: an automatic one from the access log, or an operator's.
type heldBan struct {
	ip, ja4, source, reason, bannedBy, action, scope string
	bannedAt, expiresAt                              int64
	// announced: OnCreated ran when the ban was kept (an operator's, told at
	// once), so the write does not run it again.
	announced bool
}

// ErrHeldFull: the list of bans kept for the end of a schema update is full.
var ErrHeldFull = errors.New("too many bans are waiting for the database update to finish; try again when it has")

// DropHeld takes a kept ban off the list before it is written: the operator
// lifting one placed during the hold.  Reports whether one was there.
func (m *Manager) DropHeld(ip, ja4, scope string) bool {
	if m == nil {
		return false
	}
	ip, ja4 = normalizeIP(ip), strings.TrimSpace(ja4)
	if scope == "" {
		scope = DeriveScope(ip, ja4)
	}
	m.mu.Lock()
	found := false
	rest := m.held[:0]
	for _, h := range m.held {
		if !found && h.ip == ip && h.ja4 == ja4 && h.scope == scope {
			found = true
			continue
		}
		rest = append(rest, h)
	}
	m.held = rest
	m.mu.Unlock()
	if found {
		m.markDirty()
		m.requestFlush()
	}
	return found
}

// heldBansMax bounds the bans kept while writes are held.  One per offending
// client, over the minutes an index build takes: far below this unless under
// attack, and an attack must not grow the list without limit.
const heldBansMax = 10000

// hold keeps b for the end of the hold, and reports whether it did: the list
// has a limit.
func (m *Manager) hold(b heldBan) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	// One entry per ban, as in the table (the upsert's key): a scanner that
	// trips the honeypot again and again refreshes its entry instead of
	// filling the list.  An entry announced once stays announced.
	for i := range m.held {
		if h := &m.held[i]; h.ip == b.ip && h.ja4 == b.ja4 && h.scope == b.scope {
			b.announced = b.announced || h.announced
			*h = b
			return true
		}
	}
	if len(m.held) >= heldBansMax {
		if !m.heldFull {
			m.heldFull = true
			log.Printf("ban: %d bans are waiting for the schema update to finish; further ones are not kept", heldBansMax)
		}
		return false
	}
	m.held = append(m.held, b)
	return true
}

// FlushHeld writes the bans kept while writes were held, if the database
// takes writes now.  For the daemon's shutdown, after it has stopped the
// schema update it started: the list is in memory only.
func (m *Manager) FlushHeld() {
	if m == nil || m.DB.WritesHeld() {
		return
	}
	m.writeHeld()
}

// heldMatch reports a kept ban that matches (ip, ja4) the way the mirror
// does: by the shape the ban's scope gives it, with ja4 == "" matching any
// ban naming the address.
func (m *Manager) heldMatch(ip, ja4 string) (action, source string, ok bool) {
	now := time.Now().Unix()
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, h := range m.held {
		if h.expiresAt != 0 && h.expiresAt <= now {
			continue
		}
		if heldMatches(h, ip, ja4) {
			return h.action, h.source, true
		}
	}
	return "", "", false
}

// heldMatches: whether the kept ban h holds on a request from (ip, ja4).
func heldMatches(h heldBan, ip, ja4 string) bool {
	onAddress := func() bool {
		if p, ok := parsePrefixKey(h.ip); ok {
			return addrInPrefix(p, ip)
		}
		return h.ip != "" && h.ip == ip
	}
	if ja4 == "" {
		return onAddress()
	}
	switch effectiveScope(h.ip, h.ja4, h.scope) {
	case ScopeJA4Only:
		return h.ja4 == ja4
	case ScopeIPOnly:
		return onAddress()
	default:
		return h.ip == ip && h.ja4 == ja4
	}
}

// writeHeld writes the bans kept while writes were held.  Called from loop
// once the lock is free.
func (m *Manager) writeHeld() {
	m.writeHeldMu.Lock()
	defer m.writeHeldMu.Unlock()
	m.mu.Lock()
	held := append([]heldBan(nil), m.held...)
	lifted := make([]int64, 0, len(m.lifted))
	for id := range m.lifted {
		lifted = append(lifted, id)
	}
	m.mu.Unlock()
	if len(held) == 0 && len(lifted) == 0 {
		return
	}
	// The lifted rows first: a ban placed again during the hold on a lifted
	// row's key is a row of its own, not a refresh of the one on its way
	// out.  A row already gone counts as lifted; a delete that fails stays
	// on the list for the next pass.
	deleted := 0
	for _, id := range lifted {
		if err := m.DB.Gorm.Where("id = ?", id).Delete(&db.Ban{}).Error; err != nil {
			log.Printf("ban delete (lifted during the schema update): %v", err)
			continue
		}
		deleted++
		m.mu.Lock()
		delete(m.lifted, id)
		m.mu.Unlock()
	}
	n := 0
	for _, b := range held {
		if err := m.upsert(context.Background(), b.ip, b.ja4, b.source, b.reason, b.bannedAt, b.expiresAt, b.bannedBy, b.action, b.scope); err != nil {
			log.Printf("ban upsert (kept during the schema update): %v", err)
			continue
		}
		n++
		if m.OnCreated != nil && !b.announced {
			m.OnCreated(b.ip, b.ja4, b.source, b.reason, b.bannedBy)
		}
	}
	// The mirror reads the rows back before the kept bans leave the list:
	// a check in between must find each ban in one or the other.
	if n > 0 || deleted > 0 {
		m.reloadMirror()
	}
	// Off the list only now that the rows are written: until then the file
	// has them from here, and a flush in the meantime -- an addition's --
	// must not write it without them.  One kept or refreshed since the copy
	// (a hold begun again) stays for the next time.
	done := make(map[heldBan]bool, len(held))
	for _, b := range held {
		done[b] = true
	}
	m.mu.Lock()
	rest := m.held[:0]
	for _, b := range m.held {
		if !done[b] {
			rest = append(rest, b)
		}
	}
	m.held, m.heldFull = rest, false
	m.mu.Unlock()
	log.Printf("ban: wrote %d of %d ban(s) kept and deleted %d of %d lifted during the schema update", n, len(held), deleted, len(lifted))
	if n > 0 || deleted > 0 {
		m.markDirty()
		m.requestFlush()
	}
}

func (m *Manager) markDirty() {
	m.mu.Lock()
	m.dirty = true
	m.mu.Unlock()
}

// upsert: update on conflict by the unique key (ip + ja4).  clause.OnConflict
// renders portably -- ON CONFLICT on sqlite, ON DUPLICATE KEY UPDATE on
// mariadb -- so the prior two-branch driver switch collapses to one path.
func (m *Manager) upsert(ctx context.Context, ip, ja4, source, reason string, bannedAt, expiresAt int64, bannedBy, action, scope string) error {
	return upsertOn(m.DB.Gorm.WithContext(ctx), ip, ja4, source, reason, bannedAt, expiresAt, bannedBy, action, scope)
}

// upsertWithin is upsert with the wait for the write lock bounded to within
// on SQLite -- the busy timeout of the one connection the write uses, put
// back after -- for a write made on the access log's receive loop.  A context
// deadline does not cut that wait short: it sits in SQLite's busy handler,
// not in a step the interrupt reaches.  MariaDB waits its own way.
func (m *Manager) upsertWithin(ctx context.Context, within time.Duration, ip, ja4, source, reason string, bannedAt, expiresAt int64, bannedBy, action, scope string) error {
	if m.DB.Driver != db.DriverSQLite {
		return m.upsert(ctx, ip, ja4, source, reason, bannedAt, expiresAt, bannedBy, action, scope)
	}
	return m.DB.Gorm.Connection(func(tx *gorm.DB) error {
		if err := tx.Exec(fmt.Sprintf("PRAGMA busy_timeout=%d", within.Milliseconds())).Error; err != nil {
			return err
		}
		defer tx.Exec("PRAGMA busy_timeout=5000")
		return upsertOn(tx.WithContext(ctx), ip, ja4, source, reason, bannedAt, expiresAt, bannedBy, action, scope)
	})
}

// upsertOn writes the row through g.
func upsertOn(g *gorm.DB, ip, ja4, source, reason string, bannedAt, expiresAt int64, bannedBy, action, scope string) error {
	row := db.Ban{
		IP: ip, JA4: ja4, Source: source, Reason: reason,
		BannedAt: bannedAt, ExpiresAt: expiresAt,
		BannedBy: bannedBy, Action: action, Scope: scope,
	}
	return g.Clauses(clause.OnConflict{
		// scope is part of the conflict key (DB-3): a honeypot ip_ja4 ban and a
		// manual ja4_only ban on the SAME (ip, ja4) are distinct rows, not an
		// overwrite.  Without scope here the upsert silently rewrote one into the
		// other -- which could widen a single-device ban into a JA4-wide ban
		// (every IP with that JA4), the exact ranking accident CLAUDE.md #4 guards.
		Columns: []clause.Column{{Name: "ip"}, {Name: "ja4"}, {Name: "scope"}},
		DoUpdates: clause.AssignmentColumns([]string{
			"source", "reason", "banned_at", "expires_at", "banned_by", "action",
		}),
	}).Create(&row).Error
}

// IsBanned: returns whether the (ip, ja4) tuple is banned.  ja4 == "" is
// an IP-only check (= fallback for when JA4 is not available in
// forward-auth mode).  Fast path that runs a single indexed query.
// Expired entries are treated as false.
func (m *Manager) IsBanned(ctx context.Context, ip, ja4 string) bool {
	_, _, banned := m.IsBannedActionSource(ctx, ip, ja4)
	return banned
}

// IsBannedActionSource: same as IsBannedSource but ALSO returns the per-row
// action override from the matching ban row (= the `action` column; empty means
// "use the source's default action").  banDecide uses this so a manual /
// community ban row with an explicit action (e.g. set to "deny" in the UI) is
// enforced in forward-auth mode too -- matching what native bakes into the ban
// file via EffectiveAction.  Without it, forward-auth re-resolved the SOURCE
// default and silently ignored the per-row action (UI showed "deny", daemon
// enforced the source default).  The action column always exists (db.migrate
// ensures it); old rows scan "".  First live row wins on multiple entries.
func (m *Manager) IsBannedActionSource(ctx context.Context, ip, ja4 string) (action, source string, banned bool) {
	if m == nil || ip == "" {
		return "", "", false
	}
	ip = normalizeIP(ip)
	if action, source, ok := m.heldMatch(ip, ja4); ok {
		return action, source, true
	}
	// The mirror answers; the table is asked only while there is none (it
	// could not be read), one line at a time as before.
	if e, found, loaded := m.mirrorMatch(ip, ja4); loaded {
		if found {
			return e.action, e.source, true
		}
		return "", "", false
	}
	now := time.Now().Unix()
	var (
		rows *sql.Rows
		err  error
	)
	if ja4 != "" {
		// The tuple, then the two wider shapes the module also tries: an
		// ip_only row ("<ip>|", every fingerprint from the address) and a
		// ja4_only row ("|<ja4>", the fingerprint from every address).  The
		// check used to take the tuple alone, so a ban placed on the address
		// itself -- by hand, or by the escalation above -- held in nginx and
		// not on this wire.
		rows, err = m.DB.QueryContext(ctx,
			`SELECT id, action, source, COALESCE(banned_by,''), ip FROM unmask_ban
			 WHERE ((ip = ? AND ja4 = ?) OR (ip = ? AND ja4 = '') OR (ip = '' AND ja4 = ?))
			   AND (expires_at = 0 OR expires_at > ?)
			 ORDER BY id`, ip, ja4, ip, ja4, now)
	} else {
		// JA4 absent (= e.g. forward-auth mode): decide by IP only.
		rows, err = m.DB.QueryContext(ctx,
			`SELECT id, action, source, COALESCE(banned_by,''), ip FROM unmask_ban
			 WHERE ip = ? AND (expires_at = 0 OR expires_at > ?)
			 ORDER BY id`, ip, now)
	}
	if err != nil {
		// A real DB failure.  Fail open (not-banned) for availability --
		// failing closed would block every visitor incl. search bots on a
		// DB blip -- but LOG it, else a degraded ban check is silently
		// invisible.
		log.Printf("ban: IsBannedActionSource query failed, treating as not-banned: %v", err)
		return "", "", false
	}
	defer rows.Close()
	// A row lifted during a hold is unbanned although still there: the
	// first live row that is not one wins.
	lifted := m.liftedIDs()
	for rows.Next() {
		var id int64
		var bannedBy, rowIP string
		if err := rows.Scan(&id, &action, &source, &bannedBy, &rowIP); err != nil {
			log.Printf("ban: IsBannedActionSource scan failed, treating as not-banned: %v", err)
			return "", "", false
		}
		if lifted[id] {
			continue
		}
		// An automatic ban on a CDN's egress does not hold here either (it
		// is left out of nginx's file the same way): the address is every
		// customer's.  An operator's own does.
		if bannedBy == "" && rowIP != "" {
			if _, ok := m.isEgress(rowIP); ok {
				continue
			}
		}
		return action, source, true
	}
	return "", "", false // genuinely not banned (the common case)
}

// IsBannedSource: returns the ban source string (= "honeypot" | "manual" |
// "communitybans" etc.) and whether the IP/JA4 is banned, for callers that
// don't need the per-row action.  Thin wrapper over IsBannedActionSource.
func (m *Manager) IsBannedSource(ctx context.Context, ip, ja4 string) (string, bool) {
	_, src, banned := m.IsBannedActionSource(ctx, ip, ja4)
	return src, banned
}

// Snapshot: return the current ban list (= excluding expired) sorted.
// For UI list display.
func (m *Manager) Snapshot() []Entry {
	if m == nil {
		return nil
	}
	ctx := context.Background()
	now := time.Now().Unix()
	rows, err := m.DB.QueryContext(ctx,
		`SELECT id, ip, ja4, source, COALESCE(reason,''), banned_at, expires_at, COALESCE(banned_by,''), COALESCE(action,''), COALESCE(scope,'')
		 FROM unmask_ban
		 WHERE expires_at = 0 OR expires_at > ?
		 ORDER BY ip, ja4`, now)
	if err != nil {
		log.Printf("ban snapshot: %v", err)
		return nil
	}
	defer rows.Close()
	lifted := m.liftedIDs()
	out := []Entry{}
	keys := map[[3]string]bool{}
	for rows.Next() {
		var e Entry
		var bannedAt, expiresAt int64
		if err := rows.Scan(&e.ID, &e.IP, &e.JA4, &e.Source, &e.Reason, &bannedAt, &expiresAt, &e.BannedBy, &e.Action, &e.Scope); err != nil {
			log.Printf("ban scan: %v", err)
			continue
		}
		if lifted[e.ID] {
			continue // unbanned during a hold; the row goes when the lock is free
		}
		e.BannedAt = time.Unix(bannedAt, 0)
		if expiresAt > 0 {
			e.ExpiresAt = time.Unix(expiresAt, 0)
		}
		if e.Scope == "" {
			e.Scope = DeriveScope(e.IP, e.JA4)
		}
		keys[[3]string{e.IP, e.JA4, e.Scope}] = true
		out = append(out, e)
	}
	// The bans kept while the database's writes are held: in force, so
	// listed, as the rows they will be.  One whose key the table has (a
	// refresh of that row) is the row.
	m.mu.Lock()
	kept := false
	for _, h := range m.held {
		if h.expiresAt != 0 && h.expiresAt <= now {
			continue
		}
		if keys[[3]string{h.ip, h.ja4, h.scope}] {
			continue
		}
		e := Entry{IP: h.ip, JA4: h.ja4, Source: h.source, Reason: h.reason, BannedAt: time.Unix(h.bannedAt, 0),
			BannedBy: h.bannedBy, Action: h.action, Scope: h.scope, Held: true}
		if h.expiresAt > 0 {
			e.ExpiresAt = time.Unix(h.expiresAt, 0)
		}
		out = append(out, e)
		kept = true
	}
	m.mu.Unlock()
	if kept {
		sort.SliceStable(out, func(i, j int) bool {
			if out[i].IP != out[j].IP {
				return out[i].IP < out[j].IP
			}
			return out[i].JA4 < out[j].JA4
		})
	}
	return out
}

// liftedIDs is a copy of the rows lifted during a hold, nil when there are
// none: the common case, and no allocation on the checks' path.
func (m *Manager) liftedIDs() map[int64]bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	if len(m.lifted) == 0 {
		return nil
	}
	out := make(map[int64]bool, len(m.lifted))
	for id := range m.lifted {
		out[id] = true
	}
	return out
}

func (m *Manager) loop() {
	defer close(m.doneCh)
	defer safe.Recover("ban-loop") // a panic here must not crash the daemon
	tick := time.NewTicker(60 * time.Second)
	defer tick.Stop()
	for {
		select {
		case <-m.stopCh:
			return
		case <-tick.C:
			// Under a hold the table cannot be written, but it can be read:
			// the file (the table and the kept bans) is still kept current.
			if !m.DB.WritesHeld() {
				m.writeHeld()
				if pruned := m.prune(); pruned > 0 {
					m.markDirty()
				}
			}
			if m.shouldFlush() && m.filePath != "" {
				_ = m.flush()
			}
		case <-m.wake:
			// A ban kept by the receive loop: into the file now, and into
			// the table when the lock is free.
			if m.shouldFlush() && m.filePath != "" {
				_ = m.flush()
			}
			if !m.DB.WritesHeld() {
				m.writeHeld()
			}
		}
	}
}

// prune: delete entries with expires_at <= now.  Returns the number deleted.
func (m *Manager) prune() int {
	ctx := context.Background()
	res := m.DB.Gorm.WithContext(ctx).
		Where("expires_at > 0 AND expires_at <= ?", time.Now().Unix()).
		Delete(&db.Ban{})
	if res.Error != nil {
		log.Printf("ban prune: %v", res.Error)
		return 0
	}
	return int(res.RowsAffected)
}

func (m *Manager) shouldFlush() bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.dirty
}

// requestFlush asks for the file to be written: at once when none was
// written within flushDebounce, else once at the end of the window for every
// request made meanwhile.  Nothing to do without a file.
func (m *Manager) requestFlush() {
	if m.filePath == "" {
		return
	}
	m.mu.Lock()
	if m.flushTimer != nil {
		m.mu.Unlock()
		return // one is due, and writes the list as it is then
	}
	wait := flushDebounce - time.Since(m.lastFlushAt)
	if wait <= 0 {
		m.mu.Unlock()
		if err := m.flush(); err != nil {
			log.Printf("ban: writing the ban file: %v", err)
		}
		return
	}
	m.flushTimer = time.AfterFunc(wait, func() {
		m.mu.Lock()
		m.flushTimer = nil
		m.mu.Unlock()
		if err := m.flush(); err != nil {
			log.Printf("ban: writing the ban file: %v", err)
		}
	})
	m.mu.Unlock()
}

// settle writes a write that is due now rather than at the end of the
// window.  For the tests, which read the file right after a burst.
func (m *Manager) settle() {
	m.mu.Lock()
	t := m.flushTimer
	m.flushTimer = nil
	m.mu.Unlock()
	if t != nil {
		t.Stop()
	}
	if m.filePath != "" {
		_ = m.flush()
	}
}

// flushCount is how many times the file was written (the tests).
func (m *Manager) flushCount() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.flushes
}

// flush: atomic-write the current DB contents to the ban file.  The mirror
// is rebuilt from the same read.
func (m *Manager) flush() (err error) {
	if m.filePath == "" {
		return nil
	}
	m.flushMu.Lock()
	defer m.flushMu.Unlock()
	m.mu.Lock()
	resolver := m.actionResolver
	// A change from here on belongs to the next write: the loop's tick
	// writes again if one comes in while this write is under way.
	m.dirty = false
	m.mu.Unlock()
	defer func() {
		if err != nil {
			m.markDirty()
		}
	}()
	now := time.Now().Unix()
	rows, err := m.loadMirror()
	if err != nil {
		return err
	}
	type k struct{ ip, ja4, source, action, scope, bannedBy string }
	resolve := func(e k) k {
		// Per-row action wins; fall back to the source's default action
		// via the resolver (= settings.Bans.ResolveAction).  Empty after
		// both lookups means "deny" -- the safest hard ban.
		if strings.TrimSpace(e.action) == "" && resolver != nil {
			e.action = resolver(e.source)
		}
		if strings.TrimSpace(e.action) == "" {
			e.action = "deny"
		}
		if strings.TrimSpace(e.source) == "" {
			e.source = "manual"
		}
		return e
	}
	// The bans kept while a schema update holds the writes: enforced now,
	// written to the table when the lock is free.  Ahead of the table's
	// rows, so that a kept ban -- the newer -- wins over the row it will
	// replace (the file keeps the first line of a key).
	keys := make([]k, 0, len(rows)+8)
	m.mu.Lock()
	for _, h := range m.held {
		if h.expiresAt != 0 && h.expiresAt <= now {
			continue
		}
		keys = append(keys, resolve(k{ip: h.ip, ja4: h.ja4, source: h.source, action: h.action, scope: h.scope, bannedBy: h.bannedBy}))
	}
	m.mu.Unlock()
	for _, e := range rows {
		keys = append(keys, resolve(k{ip: e.ip, ja4: e.ja4, source: e.source, action: e.action, scope: e.scope, bannedBy: e.bannedBy}))
	}

	// An automatic ban on a CDN's origin-facing address is kept in the table
	// (it says what happened) and left out of the file (it must not hold):
	// the address is every customer's.  An operator's own ban on such an
	// address holds -- it is their call.
	skipped := 0
	if m.egressFn != nil {
		filtered := keys[:0]
		for _, e := range keys {
			if e.bannedBy == "" && e.ip != "" {
				if _, ok := m.isEgress(e.ip); ok {
					skipped++
					continue
				}
			}
			filtered = append(filtered, e)
		}
		keys = filtered
	}
	m.mu.Lock()
	m.egressSkipped = skipped
	m.mu.Unlock()

	// File-line shape per scope (banKey).  DB always carries both ip + ja4
	// so the operator never loses the captured context; the file only
	// carries what the C plugin's bsearch needs to match against.
	//
	//   ip_ja4   -> "<ip>|<ja4>|src|act"   (= exact tuple, the legacy default)
	//   ja4_only -> "|<ja4>|src|act"       (= IP omitted; plugin pass 2 hits)
	//   ip_only  -> "<ip>||src|act"        (= JA4 omitted; plugin pass 3 hits)
	//
	// An ip_only row on a prefix is "<addr>/<len>||src|act": the plugin keeps
	// the keys with a '/' before the '|' apart and tries them by prefix after
	// the exact passes.
	type line struct{ key, action, source string }
	lines := make([]line, 0, len(keys))
	seen := make(map[string]bool, len(keys))
	for _, e := range keys {
		key := banKey(e.ip, e.ja4, e.scope)
		if seen[key] {
			continue // a kept ban the table already has
		}
		seen[key] = true
		lines = append(lines, line{key: key, action: e.action, source: e.source})
	}

	// sort by key so the C plugin's bsearch finds entries.  Required for
	// each pass independently -- pass 1 (= "<ip>|<ja4>"), pass 2 (= "|<ja4>"),
	// pass 3 (= "<ip>|") all share one sorted list since the keys are
	// distinguishable by their inner '|' position.
	sort.Slice(lines, func(i, j int) bool { return lines[i].key < lines[j].key })

	var buf strings.Builder
	buf.WriteString("# unmask ban list (= managed by unmask; do not edit)\n")
	buf.WriteString("# format: <key>|<source>|<action> per line; key is one of\n")
	buf.WriteString("#         <ip>|<ja4>  (exact tuple),  |<ja4>  (ja4-only),  <ip>|  (ip-only; <addr>/<len>| for a prefix)\n")
	fmt.Fprintf(&buf, "# count: %d\n", len(lines))
	fmt.Fprintf(&buf, "# generated_at: %s\n\n", time.Now().UTC().Format(time.RFC3339))
	for _, e := range lines {
		buf.WriteString(e.key)
		buf.WriteByte('|')
		buf.WriteString(e.source)
		buf.WriteByte('|')
		buf.WriteString(e.action)
		buf.WriteByte('\n')
	}

	if dir := filepath.Dir(m.filePath); dir != "" && dir != "." {
		_ = os.MkdirAll(dir, 0o755)
	}
	tmp := m.filePath + ".tmp"
	f, err := os.OpenFile(tmp, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o644)
	if err != nil {
		return err
	}
	if _, err := f.WriteString(buf.String()); err != nil {
		_ = f.Close()
		_ = os.Remove(tmp)
		return err
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		_ = os.Remove(tmp)
		return err
	}
	if err := f.Close(); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	if err := os.Rename(tmp, m.filePath); err != nil {
		return err
	}
	m.ensureReadable()
	m.mu.Lock()
	m.flushed = true
	m.lastFlushAt = time.Now()
	m.flushes++
	m.mu.Unlock()
	return nil
}

// ensureReadable: the list is read by nginx's WORKER, which runs as
// nginx.conf's `user`, not as the daemon.  The file is 0644 whatever the
// daemon's umask (the unit's UMask=0027 would make it 0640), and every
// directory above it that the daemon owns lets others pass through (x: the
// package shipped /var/lib/unmask as 0750 through 0.1.53-rc12, and nginx
// enforced no ban on any install whose worker is another user).  Only the
// x bit is added, and only on the daemon's own directories; what else is
// in them keeps its own mode (the database 0640, http.inc 0640).
func (m *Manager) ensureReadable() {
	if err := os.Chmod(m.filePath, 0o644); err != nil {
		log.Printf("ban: %s: chmod 0644: %v", m.filePath, err)
	}
	uid := uint32(os.Getuid())
	for d := filepath.Dir(m.filePath); d != "" && d != "." && d != filepath.Dir(d); d = filepath.Dir(d) {
		fi, err := os.Stat(d)
		if err != nil {
			return
		}
		st, ok := fi.Sys().(*syscall.Stat_t)
		if !ok || st.Uid != uid {
			return // not ours to change: the package or the operator owns it
		}
		if perm := fi.Mode().Perm(); perm&0o001 == 0 {
			if err := os.Chmod(d, perm|0o001); err != nil {
				log.Printf("ban: %s: chmod o+x (so nginx's worker can reach the ban list): %v", d, err)
				return
			}
			log.Printf("ban: %s: %#o -> %#o so nginx's worker can reach the ban list", d, perm, perm|0o001)
		}
	}
}

// Flushed: whether the list has been written since the daemon started.
// The admin's notice about a worker that cannot read the list waits for
// this: a list the daemon could not write is another problem (the doctor's
// "ban file dir"), and a test instance writing nowhere has no list to
// speak of.
func (m *Manager) Flushed() bool {
	if m == nil {
		return false
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.flushed
}

// escalateIP widens a run of automatic bans on one address to the address
// itself.  An automatic ban is scoped to the (address, JA4) pair, and a
// client that varies its ClientHello from one connection to the next -- a
// few lines of TLS client configuration -- arrived with a fresh fingerprint,
// a fresh pass budget and a fresh ban each time, so the bans never caught
// up with it.  Three distinct fingerprints banned from one address inside a
// day is not a household behind a NAT; from then on the address is banned
// whatever it presents, for as long as the ban that tipped it.
const (
	ipEscalateMinJA4 = 3
	ipEscalateWindow = 24 * time.Hour
)

func (m *Manager) escalateIP(ctx context.Context, ip, source, action string, now, expires int64) {
	if ip == "" || m.DB == nil || m.DB.Gorm == nil {
		return
	}
	// A CDN's egress carries every customer's traffic and more than one
	// fingerprint of the CDN's own: never the address as a whole.
	if vendor, ok := m.isEgress(ip); ok {
		m.egressLog(ip, vendor, "the address-wide ban")
		return
	}
	// Counted from the mirror: the automatic (address, JA4) bans on the
	// address inside the window, and whether an address-wide ban is there.
	since := now - int64(ipEscalateWindow/time.Second)
	have := false
	ja4s := map[string]bool{}
	m.mirrorMu.RLock()
	if m.mirror != nil {
		for i := range m.mirror.byIP[ip] {
			e := &m.mirror.byIP[ip][i]
			if !e.live(now) {
				continue
			}
			switch e.scope {
			case ScopeIPOnly:
				have = true
			case ScopeIPJA4:
				if e.ja4 != "" && e.bannedBy == "" && e.bannedAt >= since {
					ja4s[e.ja4] = true
				}
			}
		}
	}
	m.mirrorMu.RUnlock()
	if have || len(ja4s) < ipEscalateMinJA4 {
		return
	}
	reason := fmt.Sprintf("escalated: %d fingerprints from this address were banned within a day", len(ja4s))
	if err := m.upsertWithin(ctx, autoBanWriteWithin, ip, "", source, reason, now, expires, "", action, ScopeIPOnly); err != nil {
		return
	}
	m.mirrorPut(mirrorEntry{ip: ip, scope: ScopeIPOnly, source: source, action: action, bannedAt: now, expiresAt: expires})
	m.markDirty()
	m.requestFlush()
	if m.OnCreated != nil {
		m.OnCreated(ip, "", source, reason, "")
	}
}
