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
	"time"

	"gorm.io/gorm/clause"

	"github.com/unmask-sh/unmask/admin/internal/db"
	"github.com/unmask-sh/unmask/admin/internal/safe"
)

const (
	SourceHoneypot        = "honeypot"
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
	duration time.Duration // default TTL for honeypot/auto bans.  0 = permanent
	// whitelistFn reports whether an IP is on the bypass allowlist (= preset
	// crawler ranges + operator bypass_ips, CIDR-aware).  Injected by the admin
	// via SetWhitelist over the live settings' IPBypassMatcher, so toggling a
	// preset / adding a bypass IP takes effect without a manager restart; nil =
	// nothing whitelisted.  wlMu guards it because honeypot auto-bans (the flush
	// goroutine via AddWithSource) read it while AdminSettingsSave swaps it.
	whitelistFn func(ip string) bool
	wlMu        sync.RWMutex
	mu          sync.Mutex
	dirty       bool
	stopCh      chan struct{}
	doneCh      chan struct{}

	// actionResolver: per-source action picker injected by the admin.
	// Read on every flush() so a settings change reflects on the next
	// 60s tick without a manager restart.
	actionResolver ActionResolver

	// OnCreated: callback invoked when a ban is successfully added (= so
	// notifier can stay decoupled).  Nil is fine.  Assigned by the caller
	// (= so the ban package does not depend on notifier).
	OnCreated func(ip, ja4, source, reason, bannedBy string)
}

// SetActionResolver installs the per-source action picker.  Safe to call
// after Start (= reads happen on the flush goroutine).
func (m *Manager) SetActionResolver(r ActionResolver) {
	m.mu.Lock()
	m.actionResolver = r
	m.mu.Unlock()
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
	if m.filePath != "" {
		if err := m.flush(); err != nil {
			log.Printf("ban: initial flush: %v", err)
		}
	}
	go m.loop()
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
	if m == nil {
		return
	}
	ip = strings.TrimSpace(ip)
	ja4 = strings.TrimSpace(ja4)
	if ip == "" {
		return
	}
	if m.isWhitelisted(ip) {
		return
	}
	now := time.Now().Unix()
	var expires int64
	// For manual permanent bans (= the caller manages duration separately),
	// use AddPermanent (provided separately).
	if m.duration > 0 {
		expires = now + int64(m.duration.Seconds())
	}
	if err := m.upsert(ctx, ip, ja4, source, reason, now, expires, bannedBy, "", DeriveScope(ip, ja4)); err != nil {
		log.Printf("ban upsert: %v", err)
		return
	}
	m.markDirty()
	if m.filePath != "" {
		// Flush on new additions so the propagation delay is minimal.
		_ = m.flush()
	}
	if m.OnCreated != nil {
		m.OnCreated(ip, ja4, source, reason, bannedBy)
	}
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
	ip = strings.TrimSpace(ip)
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
	if scope == ScopeIPJA4 && (ip == "" || ja4 == "") {
		return errors.New("ip_ja4 scope requires both ip and ja4")
	}
	if scope == ScopeJA4Only && ja4 == "" {
		return errors.New("ja4_only scope requires ja4")
	}
	if scope == ScopeIPOnly && ip == "" {
		return errors.New("ip_only scope requires ip")
	}
	now := time.Now().Unix()
	var expiresAt int64
	if expiresSec > 0 {
		expiresAt = now + expiresSec
	}
	if err := m.upsert(ctx, ip, ja4, SourceManual, reason, now, expiresAt, bannedBy, strings.TrimSpace(action), scope); err != nil {
		return err
	}
	m.markDirty()
	if m.filePath != "" {
		_ = m.flush()
	}
	if m.OnCreated != nil {
		m.OnCreated(ip, ja4, SourceManual, reason, bannedBy)
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
	ip = strings.TrimSpace(ip)
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
	if scope == ScopeIPJA4 && (ip == "" || ja4 == "") {
		return errors.New("ip_ja4 scope requires both ip and ja4")
	}
	if scope == ScopeJA4Only && ja4 == "" {
		return errors.New("ja4_only scope requires ja4")
	}
	if scope == ScopeIPOnly && ip == "" {
		return errors.New("ip_only scope requires ip")
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
	m.markDirty()
	if m.filePath != "" {
		_ = m.flush()
	}
	return nil
}

// Remove: unban (= remove the entry).  Disappears from the file on the next flush.
func (m *Manager) Remove(ctx context.Context, id int64) error {
	if m == nil {
		return errors.New("manager nil")
	}
	res := m.DB.Gorm.WithContext(ctx).Where("id = ?", id).Delete(&db.Ban{})
	if res.Error != nil {
		return res.Error
	}
	if res.RowsAffected == 0 {
		return errors.New("not found")
	}
	m.markDirty()
	if m.filePath != "" {
		_ = m.flush()
	}
	return nil
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
	row := db.Ban{
		IP: ip, JA4: ja4, Source: source, Reason: reason,
		BannedAt: bannedAt, ExpiresAt: expiresAt,
		BannedBy: bannedBy, Action: action, Scope: scope,
	}
	return m.DB.Gorm.WithContext(ctx).Clauses(clause.OnConflict{
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
	if m == nil || ip == "" {
		return false
	}
	now := time.Now().Unix()
	var n int
	if ja4 != "" {
		// full tuple match
		err := m.DB.QueryRowContext(ctx,
			`SELECT COUNT(*) FROM unmask_ban
			 WHERE ip = ? AND ja4 = ? AND (expires_at = 0 OR expires_at > ?)`,
			ip, ja4, now).Scan(&n)
		if err != nil {
			// COUNT(*) always returns a row, so err is a real DB failure (never
			// ErrNoRows).  Fail open (not-banned) for availability -- failing
			// closed would block every visitor incl. search bots on a DB blip --
			// but LOG it, else a degraded ban check is silently invisible.
			log.Printf("ban: IsBanned(ip+ja4) query failed, treating as not-banned: %v", err)
			return false
		}
		return n > 0
	}
	// JA4 absent (= e.g. forward-auth mode): decide by IP only.
	err := m.DB.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM unmask_ban
		 WHERE ip = ? AND (expires_at = 0 OR expires_at > ?)`,
		ip, now).Scan(&n)
	if err != nil {
		log.Printf("ban: IsBanned(ip) query failed, treating as not-banned: %v", err)
		return false
	}
	return n > 0
}

// IsBannedSource: same as IsBanned but also returns the source string
// of the matching entry (= "honeypot" | "manual" | "communitybans" etc.).
// When the IP has multiple live entries the first row wins; that's good
// enough for the auth_request gate which just needs to know "is this a
// honeypot-derived ban or something else."  Empty source on no match.
func (m *Manager) IsBannedSource(ctx context.Context, ip, ja4 string) (string, bool) {
	if m == nil || ip == "" {
		return "", false
	}
	now := time.Now().Unix()
	var src string
	if ja4 != "" {
		err := m.DB.QueryRowContext(ctx,
			`SELECT source FROM unmask_ban
			 WHERE ip = ? AND ja4 = ? AND (expires_at = 0 OR expires_at > ?)
			 LIMIT 1`,
			ip, ja4, now).Scan(&src)
		if errors.Is(err, sql.ErrNoRows) {
			return "", false // genuinely not banned (the common case)
		}
		if err != nil {
			log.Printf("ban: IsBannedSource(ip+ja4) query failed, treating as not-banned: %v", err)
			return "", false
		}
		return src, true
	}
	err := m.DB.QueryRowContext(ctx,
		`SELECT source FROM unmask_ban
		 WHERE ip = ? AND (expires_at = 0 OR expires_at > ?)
		 LIMIT 1`,
		ip, now).Scan(&src)
	if errors.Is(err, sql.ErrNoRows) {
		return "", false
	}
	if err != nil {
		log.Printf("ban: IsBannedSource(ip) query failed, treating as not-banned: %v", err)
		return "", false
	}
	return src, true
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
	out := []Entry{}
	for rows.Next() {
		var e Entry
		var bannedAt, expiresAt int64
		if err := rows.Scan(&e.ID, &e.IP, &e.JA4, &e.Source, &e.Reason, &bannedAt, &expiresAt, &e.BannedBy, &e.Action, &e.Scope); err != nil {
			log.Printf("ban scan: %v", err)
			continue
		}
		e.BannedAt = time.Unix(bannedAt, 0)
		if expiresAt > 0 {
			e.ExpiresAt = time.Unix(expiresAt, 0)
		}
		if e.Scope == "" {
			e.Scope = DeriveScope(e.IP, e.JA4)
		}
		out = append(out, e)
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
			if pruned := m.prune(); pruned > 0 {
				m.markDirty()
			}
			if m.shouldFlush() && m.filePath != "" {
				_ = m.flush()
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

// flush: atomic-write the current DB contents to the ban file.
func (m *Manager) flush() error {
	if m.filePath == "" {
		return nil
	}
	m.mu.Lock()
	resolver := m.actionResolver
	m.mu.Unlock()
	now := time.Now().Unix()
	rows, err := m.DB.QueryContext(context.Background(),
		`SELECT ip, ja4, source, action, scope FROM unmask_ban
		 WHERE expires_at = 0 OR expires_at > ?
		 ORDER BY ip, ja4`, now)
	if err != nil {
		return err
	}
	type k struct{ ip, ja4, source, action, scope string }
	keys := []k{}
	for rows.Next() {
		var e k
		if err := rows.Scan(&e.ip, &e.ja4, &e.source, &e.action, &e.scope); err != nil {
			rows.Close()
			return err
		}
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
		// Legacy rows without scope (= pre-migration) fall back to inferred.
		if e.scope == "" {
			e.scope = DeriveScope(e.ip, e.ja4)
		}
		keys = append(keys, e)
	}
	rows.Close()

	// File-line shape per scope.  DB always carries both ip + ja4 so the
	// operator never loses the captured context; the file only carries
	// what the C plugin's bsearch needs to match against.
	//
	//   ip_ja4   -> "<ip>|<ja4>|src|act"   (= exact tuple, the legacy default)
	//   ja4_only -> "|<ja4>|src|act"       (= IP omitted; plugin pass 2 hits)
	//   ip_only  -> "<ip>||src|act"        (= JA4 omitted; plugin pass 3 hits)
	type line struct{ key, action, source string }
	lines := make([]line, 0, len(keys))
	for _, e := range keys {
		var key string
		switch e.scope {
		case ScopeJA4Only:
			key = "|" + e.ja4
		case ScopeIPOnly:
			key = e.ip + "|"
		default: // ScopeIPJA4
			key = e.ip + "|" + e.ja4
		}
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
	buf.WriteString("#         <ip>|<ja4>  (exact tuple),  |<ja4>  (ja4-only),  <ip>|  (ip-only)\n")
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
	m.mu.Lock()
	m.dirty = false
	m.mu.Unlock()
	return nil
}
