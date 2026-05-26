// Package ban: manage the persistent BAN list (= DB backed + file flush for nginx).
//
// How it works:
//   - source of truth: the DB (= unmask_ban table).  Carries metadata
//     (= source / reason / banned_by).  Used for admin UI listing, manual
//     unban, and statistics.
//   - nginx integration: write out a ban file (= "<ip>|<ja4>" per line).
//     The unmask module watches mtime and reloads, exposing
//     $unmask_banned as 1/0.
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

	"github.com/unmask-sh/unmask/admin/internal/db"
)

const (
	SourceHoneypot        = "honeypot"
	SourceManual          = "manual"
	SourceProtectedFailed = "protected_failed" // v0.2+
	SourceRateLimitAbuse  = "rate_limit_abuse" // v0.2+
	SourceJA4Loop         = "ja4_loop"         // v0.2+
)

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
}

// Manager: ban management with the DB as the source of truth.  When
// filePath is empty, file flushing is skipped (= used in tests where
// nginx integration is unnecessary).
type Manager struct {
	DB        *db.DB
	filePath  string
	duration  time.Duration // default TTL for honeypot/auto bans.  0 = permanent
	whitelist map[string]bool
	mu        sync.Mutex
	dirty     bool
	stopCh    chan struct{}
	doneCh    chan struct{}

	// OnCreated: callback invoked when a ban is successfully added (= so
	// notifier can stay decoupled).  Nil is fine.  Assigned by the caller
	// (= so the ban package does not depend on notifier).
	OnCreated func(ip, ja4, source, reason, bannedBy string)
}

// New: initialize the ban manager.  filePath="" disables file flush
// (= test stub).
func New(d *db.DB, filePath string, duration time.Duration, whitelist []string) *Manager {
	wl := map[string]bool{}
	for _, ip := range whitelist {
		wl[strings.TrimSpace(ip)] = true
	}
	return &Manager{
		DB:        d,
		filePath:  filePath,
		duration:  duration,
		whitelist: wl,
		stopCh:    make(chan struct{}),
		doneCh:    make(chan struct{}),
	}
}

// Start: launch the prune + flush goroutine.  Initial flush of the ban file.
func (m *Manager) Start() {
	if m == nil {
		return
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
	if m.whitelist[ip] {
		return
	}
	now := time.Now().Unix()
	var expires int64
	// For manual permanent bans (= the caller manages duration separately),
	// use AddPermanent (provided separately).
	if m.duration > 0 {
		expires = now + int64(m.duration.Seconds())
	}
	if err := m.upsert(ctx, ip, ja4, source, reason, now, expires, bannedBy); err != nil {
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
func (m *Manager) AddManual(ctx context.Context, ip, ja4, reason, bannedBy string, expiresSec int64) error {
	if m == nil {
		return errors.New("manager nil")
	}
	ip = strings.TrimSpace(ip)
	ja4 = strings.TrimSpace(ja4)
	if ip == "" {
		return errors.New("ip is empty")
	}
	if m.whitelist[ip] {
		return errors.New("ip is on bypass whitelist")
	}
	now := time.Now().Unix()
	var expiresAt int64
	if expiresSec > 0 {
		expiresAt = now + expiresSec
	}
	if err := m.upsert(ctx, ip, ja4, SourceManual, reason, now, expiresAt, bannedBy); err != nil {
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

// Remove: unban (= remove the entry).  Disappears from the file on the next flush.
func (m *Manager) Remove(ctx context.Context, id int64) error {
	if m == nil {
		return errors.New("manager nil")
	}
	res, err := m.DB.ExecContext(ctx, `DELETE FROM unmask_ban WHERE id = ?`, id)
	if err != nil {
		return err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
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

// upsert: update on conflict by the unique key (ip + ja4).  Branches per
// driver (= SQLite and MariaDB use different UPSERT syntax).
func (m *Manager) upsert(ctx context.Context, ip, ja4, source, reason string, bannedAt, expiresAt int64, bannedBy string) error {
	switch m.DB.Driver {
	case db.DriverSQLite:
		_, err := m.DB.ExecContext(ctx,
			`INSERT INTO unmask_ban (ip, ja4, source, reason, banned_at, expires_at, banned_by)
			 VALUES (?, ?, ?, ?, ?, ?, ?)
			 ON CONFLICT(ip, ja4) DO UPDATE SET
			   source     = excluded.source,
			   reason     = excluded.reason,
			   banned_at  = excluded.banned_at,
			   expires_at = excluded.expires_at,
			   banned_by  = excluded.banned_by`,
			ip, ja4, source, reason, bannedAt, expiresAt, bannedBy)
		return err
	default: // MariaDB
		_, err := m.DB.ExecContext(ctx,
			`INSERT INTO unmask_ban (ip, ja4, source, reason, banned_at, expires_at, banned_by)
			 VALUES (?, ?, ?, ?, ?, ?, ?)
			 ON DUPLICATE KEY UPDATE
			   source     = VALUES(source),
			   reason     = VALUES(reason),
			   banned_at  = VALUES(banned_at),
			   expires_at = VALUES(expires_at),
			   banned_by  = VALUES(banned_by)`,
			ip, ja4, source, reason, bannedAt, expiresAt, bannedBy)
		return err
	}
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
		return false
	}
	return n > 0
}

// IsBannedSource: same as IsBanned but also returns the source string
// of the matching entry (= "honeypot" | "manual" | "sharedfeed" etc.).
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
		if err != nil {
			return "", false
		}
		return src, true
	}
	err := m.DB.QueryRowContext(ctx,
		`SELECT source FROM unmask_ban
		 WHERE ip = ? AND (expires_at = 0 OR expires_at > ?)
		 LIMIT 1`,
		ip, now).Scan(&src)
	if err != nil {
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
		`SELECT id, ip, ja4, source, COALESCE(reason,''), banned_at, expires_at, COALESCE(banned_by,'')
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
		if err := rows.Scan(&e.ID, &e.IP, &e.JA4, &e.Source, &e.Reason, &bannedAt, &expiresAt, &e.BannedBy); err != nil {
			log.Printf("ban scan: %v", err)
			continue
		}
		e.BannedAt = time.Unix(bannedAt, 0)
		if expiresAt > 0 {
			e.ExpiresAt = time.Unix(expiresAt, 0)
		}
		out = append(out, e)
	}
	return out
}

func (m *Manager) loop() {
	defer close(m.doneCh)
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
	res, err := m.DB.ExecContext(ctx,
		`DELETE FROM unmask_ban WHERE expires_at > 0 AND expires_at <= ?`,
		time.Now().Unix())
	if err != nil {
		log.Printf("ban prune: %v", err)
		return 0
	}
	n, _ := res.RowsAffected()
	return int(n)
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
	now := time.Now().Unix()
	rows, err := m.DB.QueryContext(context.Background(),
		`SELECT ip, ja4 FROM unmask_ban
		 WHERE expires_at = 0 OR expires_at > ?
		 ORDER BY ip, ja4`, now)
	if err != nil {
		return err
	}
	type k struct{ ip, ja4 string }
	keys := []k{}
	for rows.Next() {
		var e k
		if err := rows.Scan(&e.ip, &e.ja4); err != nil {
			rows.Close()
			return err
		}
		keys = append(keys, e)
	}
	rows.Close()

	// sort by ip|ja4 (= the rendered order. required for the binary
	// search in the nginx module).
	sort.Slice(keys, func(i, j int) bool {
		if keys[i].ip != keys[j].ip {
			return keys[i].ip < keys[j].ip
		}
		return keys[i].ja4 < keys[j].ja4
	})

	var buf strings.Builder
	buf.WriteString("# unmask ban list (= managed by unmask-admin; do not edit)\n")
	buf.WriteString("# format: <ip>|<ja4> per line\n")
	buf.WriteString(fmt.Sprintf("# count: %d\n", len(keys)))
	buf.WriteString(fmt.Sprintf("# generated_at: %s\n\n", time.Now().UTC().Format(time.RFC3339)))
	for _, e := range keys {
		buf.WriteString(e.ip)
		buf.WriteByte('|')
		buf.WriteString(e.ja4)
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

// Wrapper around sql.Result for callers that need to thread it.
type sqlResult struct{ res sql.Result }

func (s sqlResult) RowsAffected() (int64, error) { return s.res.RowsAffected() }
func (s sqlResult) LastInsertId() (int64, error) { return s.res.LastInsertId() }
