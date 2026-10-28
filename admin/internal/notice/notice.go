// Package notice keeps the daemon's alerts for the admin's own notification
// list: the bell in the top bar and the page behind it.
//
// The notifier sends an alert by webhook and by mail; this is its third
// channel, and the one every install has -- most have neither of the others
// set up, and an alert that reached nobody was gone.  Every alert lands here
// whatever the external channels' switches say: the switches are about how
// much mail the operator wants, and a row here costs nothing to receive.
//
// A row is the event's fields (the same the webhook's generic payload
// carries), not a text: the page writes the line in the reader's language,
// where mail had to pick one at send time.  Bans fold into one row per hour
// -- a honeypot that trips all day is a row an hour, not hundreds -- the row
// counting them, by source, and naming the latest.
//
// Read state is a mark per account (unmask_notice_seen): the id of the newest
// row the account had opened the list to.  Unread is what is above it, so
// opening the list reads everything, and a folded row that grows after it was
// seen stays seen -- the next hour's row is the new one.  A row can be for one
// account (UserID); nothing writes such rows yet, the column is there so that
// a personal notice needs no migration when one comes.
package notice

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"sort"
	"sync"
	"time"

	"github.com/unmask-sh/unmask/admin/internal/db"
	"github.com/unmask-sh/unmask/admin/internal/notifier"
	"gorm.io/gorm/clause"
)

// The kinds, as the webhook names the events.
const (
	KindBan       = notifier.EventBanCreated
	KindBurst     = notifier.EventChallengeBurst
	KindOverBlock = notifier.EventOverBlock
	KindAdvisor   = notifier.EventAdvisorDigest
	KindPreview   = notifier.EventPreviewChallenged
	// KindFailsafe: the plugin's fail-safe stripped the nginx module and the
	// configuration is rendered without it (handlers.RunNativeFailsafeWatch
	// writes the row when the marker appears, and one when it goes).  Not a
	// webhook event: the daemon's own observation, written with Put.
	KindFailsafe = "native_failsafe"
)

// How a row is marked: the notifier's table (notifier.Severity), one answer
// for the list and for the choice of webhook.
const (
	SeverityInfo = notifier.SeverityInfo
	SeverityWarn = notifier.SeverityWarn
	SeverityCrit = notifier.SeverityCrit
)

// banIPsKept is how many of an hour's banned addresses the folded row names.
const banIPsKept = 5

// Entry is one row as the page reads it.
type Entry struct {
	ID        int64
	CreatedAt int64 // unix seconds (UTC) of the event, the first one of a folded row
	UpdatedAt int64 // of the last event folded in
	Kind      string
	Severity  string
	UserID    *int64 // nil: every administrator
	Site      string
	GroupKey  string
	Events    int
	Detail    map[string]any
}

// Store writes and reads the rows.  Every method is nil-safe.
type Store struct {
	DB *db.DB
	// mu serialises writes: two bans in the same second must fold into one
	// row, not race past each other into two.
	mu sync.Mutex
	// held: the entries that could not be written -- the database's writes
	// held, or busy past the deadline (2026-10-17: a hundred ban notices
	// lost behind a backlog being written) -- tried again until they are,
	// oldest first; bounded.  heldMu guards it and retrying.
	heldMu   sync.Mutex
	held     []Entry
	retrying bool
}

// heldMax bounds the entries kept for a retry.
const heldMax = 1000

// retryEvery is how often the kept entries are tried again.
const retryEvery = 30 * time.Second

// New returns a store over conn.
func New(conn *db.DB) *Store { return &Store{DB: conn} }

// Add is the notifier's channel (notifier.Inbox): event is the webhook's
// event name, fields its payload.  Best-effort, like the other channels: a
// failure is logged and the alert is still sent elsewhere.
func (s *Store) Add(event string, fields map[string]any) {
	if s == nil || s.DB == nil {
		return
	}
	e := fromEvent(event, fields)
	if e.Kind == "" {
		return
	}
	if s.DB.WritesHeld() {
		s.keep(e)
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := s.Put(ctx, e); err != nil {
		log.Printf("notice %s: %v (kept for a retry)", event, err)
		s.keep(e)
	}
}

// keep holds e for a later try and sees to it that one is made.
func (s *Store) keep(e Entry) {
	s.heldMu.Lock()
	defer s.heldMu.Unlock()
	if len(s.held) >= heldMax {
		s.held = s.held[1:]
	}
	s.held = append(s.held, e)
	if !s.retrying {
		s.retrying = true
		go s.retryLoop()
	}
}

// retryLoop writes the kept entries every retryEvery until none are left.
func (s *Store) retryLoop() {
	for {
		time.Sleep(retryEvery)
		if s.RetryHeld() == 0 {
			s.heldMu.Lock()
			if len(s.held) == 0 {
				s.retrying = false
				s.heldMu.Unlock()
				return
			}
			s.heldMu.Unlock()
		}
	}
}

// RetryHeld tries the kept entries once, oldest first, and reports how many
// are still kept (0: none left, or the database's writes are held, in which
// case nothing was tried).  Called by the retry loop, and by the tests.
func (s *Store) RetryHeld() int {
	if s == nil || s.DB == nil || s.DB.WritesHeld() {
		return 0
	}
	s.heldMu.Lock()
	batch := s.held
	s.held = nil
	s.heldMu.Unlock()
	var back []Entry
	for i, e := range batch {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		err := s.Put(ctx, e)
		cancel()
		if err != nil {
			// The rest waits for the next try, in order.
			back = append(back, batch[i:]...)
			break
		}
	}
	s.heldMu.Lock()
	s.held = append(back, s.held...)
	n := len(s.held)
	s.heldMu.Unlock()
	if written := len(batch) - len(back); written > 0 {
		log.Printf("notice: wrote %d kept entr%s", written, map[bool]string{true: "y", false: "ies"}[written == 1])
	}
	return n
}

// fromEvent turns a webhook payload into a row: event, site and ts become
// columns, the rest is the detail.
func fromEvent(event string, fields map[string]any) Entry {
	switch event {
	case KindBan, KindBurst, KindOverBlock, KindAdvisor, KindPreview:
	default:
		return Entry{}
	}
	e := Entry{Kind: event, Severity: notifier.Severity(event, fields), Detail: map[string]any{}}
	e.CreatedAt = time.Now().Unix()
	for k, v := range fields {
		switch k {
		case "event":
		case "severity": // the payload's copy of the mark; the row has its column
		case "site":
			e.Site, _ = v.(string)
		case "ts":
			if ts := asInt64(v); ts > 0 {
				e.CreatedAt = ts
			}
		default:
			e.Detail[k] = v
		}
	}
	e.UpdatedAt = e.CreatedAt
	e.Events = 1
	if event == KindBan {
		e.GroupKey = fmt.Sprintf("%s:%d", KindBan, e.CreatedAt/3600*3600)
	}
	return e
}

// Put writes e: a new row, or -- when e carries a group key that an existing
// row has -- the fold of e into that row.
func (s *Store) Put(ctx context.Context, e Entry) error {
	if s == nil || s.DB == nil {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if e.CreatedAt == 0 {
		e.CreatedAt = time.Now().Unix()
	}
	if e.UpdatedAt == 0 {
		e.UpdatedAt = e.CreatedAt
	}
	if e.Events <= 0 {
		e.Events = 1
	}
	if e.Severity == "" {
		e.Severity = SeverityInfo
	}
	if e.GroupKey != "" {
		var prev db.Notice
		err := s.DB.Gorm.WithContext(ctx).Where("group_key = ?", e.GroupKey).Order("id DESC").Limit(1).Find(&prev).Error
		if err != nil {
			return err
		}
		if prev.ID != 0 {
			merged := fold(prev, e)
			return s.DB.Gorm.WithContext(ctx).Model(&db.Notice{}).Where("id = ?", prev.ID).Updates(map[string]any{
				"updated_at": e.UpdatedAt,
				"events":     prev.Events + e.Events,
				"severity":   e.Severity,
				"detail":     merged,
			}).Error
		}
	}
	detail := e.Detail
	if e.Kind == KindBan {
		detail = banFirst(detail)
	}
	b, err := json.Marshal(detail)
	if err != nil {
		return err
	}
	row := db.Notice{
		CreatedAt: e.CreatedAt, UpdatedAt: e.UpdatedAt, Kind: e.Kind, Severity: e.Severity,
		UserID: e.UserID, Site: e.Site, GroupKey: e.GroupKey, Events: e.Events, Detail: string(b),
	}
	return s.DB.Gorm.WithContext(ctx).Create(&row).Error
}

// banFirst gives a lone ban the shape a folded row has, so the page reads
// both the same way: the count by source and the addresses named.
func banFirst(d map[string]any) map[string]any {
	out := make(map[string]any, len(d)+2)
	for k, v := range d {
		out[k] = v
	}
	src, _ := d["source"].(string)
	if src == "" {
		src = "unknown"
	}
	out["sources"] = map[string]any{src: float64(1)}
	if ip, _ := d["ip"].(string); ip != "" {
		out["ips"] = []any{ip}
	} else {
		out["ips"] = []any{}
	}
	return out
}

// fold merges a ban into the hour's row: the row's latest ban becomes this
// one, the count by source goes up, the address joins the ones named.
func fold(prev db.Notice, e Entry) string {
	var d map[string]any
	if json.Unmarshal([]byte(prev.Detail), &d) != nil || d == nil {
		d = map[string]any{}
	}
	sources, _ := d["sources"].(map[string]any)
	if sources == nil {
		sources = map[string]any{}
	}
	ips, _ := d["ips"].([]any)
	for k, v := range e.Detail {
		d[k] = v
	}
	src, _ := e.Detail["source"].(string)
	if src == "" {
		src = "unknown"
	}
	sources[src] = asInt64(sources[src]) + 1
	d["sources"] = sources
	if ip, _ := e.Detail["ip"].(string); ip != "" {
		kept := []any{ip}
		for _, x := range ips {
			if x != ip && len(kept) < banIPsKept {
				kept = append(kept, x)
			}
		}
		ips = kept
	}
	d["ips"] = ips
	b, _ := json.Marshal(d)
	return string(b)
}

// List returns the rows userID may see -- everyone's and its own -- newest
// first; kind narrows to one kind ("" = all).
func (s *Store) List(ctx context.Context, userID int64, kind string, limit, offset int) ([]Entry, error) {
	if s == nil || s.DB == nil {
		return nil, nil
	}
	if limit <= 0 || limit > 1000 {
		limit = 100
	}
	q := s.DB.Gorm.WithContext(ctx).Where("user_id IS NULL OR user_id = ?", userID)
	if kind != "" {
		q = q.Where("kind = ?", kind)
	}
	var rows []db.Notice
	if err := q.Order("id DESC").Limit(limit).Offset(max(offset, 0)).Find(&rows).Error; err != nil {
		return nil, err
	}
	out := make([]Entry, 0, len(rows))
	for _, r := range rows {
		out = append(out, toEntry(r))
	}
	return out, nil
}

// Count is how many rows List would page through.
func (s *Store) Count(ctx context.Context, userID int64, kind string) (int, error) {
	if s == nil || s.DB == nil {
		return 0, nil
	}
	q := s.DB.Gorm.WithContext(ctx).Model(&db.Notice{}).Where("user_id IS NULL OR user_id = ?", userID)
	if kind != "" {
		q = q.Where("kind = ?", kind)
	}
	var n int64
	err := q.Count(&n).Error
	return int(n), err
}

// Unread counts the rows userID may see above its mark.
func (s *Store) Unread(ctx context.Context, userID int64) (int, error) {
	if s == nil || s.DB == nil {
		return 0, nil
	}
	var n int
	err := s.DB.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM unmask_notice
		 WHERE id > COALESCE((SELECT seen_id FROM unmask_notice_seen WHERE user_id = ?), 0)
		   AND (user_id IS NULL OR user_id = ?)`, userID, userID).Scan(&n)
	return n, err
}

// SeenID is userID's mark: the id of the newest row it had opened the list
// to (0 when it never has).
func (s *Store) SeenID(ctx context.Context, userID int64) (int64, error) {
	if s == nil || s.DB == nil {
		return 0, nil
	}
	var row db.NoticeSeen
	err := s.DB.Gorm.WithContext(ctx).Where("user_id = ?", userID).Limit(1).Find(&row).Error
	return row.SeenID, err
}

// MarkSeen moves userID's mark up to upTo -- never down: a stale page that
// reports an older id does not unread what a newer one read.  Returns the
// mark as it now stands.
func (s *Store) MarkSeen(ctx context.Context, userID, upTo int64) (int64, error) {
	if s == nil || s.DB == nil || userID <= 0 {
		return 0, nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	cur, err := s.SeenID(ctx, userID)
	if err != nil {
		return 0, err
	}
	if upTo <= cur {
		return cur, nil
	}
	row := db.NoticeSeen{UserID: userID, SeenID: upTo, SeenAt: time.Now().Unix()}
	err = s.DB.Gorm.WithContext(ctx).Clauses(clause.OnConflict{
		Columns:   []clause.Column{{Name: "user_id"}},
		DoUpdates: clause.AssignmentColumns([]string{"seen_id", "seen_at"}),
	}).Create(&row).Error
	return upTo, err
}

// Newest is the id of the newest row userID may see (0 when there is none):
// what opening the list marks seen up to.
func (s *Store) Newest(ctx context.Context, userID int64) (int64, error) {
	if s == nil || s.DB == nil {
		return 0, nil
	}
	var id *int64
	err := s.DB.QueryRowContext(ctx,
		`SELECT MAX(id) FROM unmask_notice WHERE user_id IS NULL OR user_id = ?`, userID).Scan(&id)
	if err != nil || id == nil {
		return 0, err
	}
	return *id, nil
}

// Prune deletes rows older than retentionDays (<= 0: keep everything), and
// the marks of accounts that no longer exist.
func (s *Store) Prune(ctx context.Context, retentionDays int) (int64, error) {
	if s == nil || s.DB == nil || retentionDays <= 0 {
		return 0, nil
	}
	cutoff := time.Now().Add(-time.Duration(retentionDays) * 24 * time.Hour).Unix()
	res, err := s.DB.ExecContext(ctx, `DELETE FROM unmask_notice WHERE created_at < ?`, cutoff)
	if err != nil {
		return 0, err
	}
	n, _ := res.RowsAffected()
	if _, err := s.DB.ExecContext(ctx,
		`DELETE FROM unmask_notice_seen WHERE user_id NOT IN (SELECT id FROM unmask_user)`); err != nil {
		return n, err
	}
	return n, nil
}

func toEntry(r db.Notice) Entry {
	e := Entry{
		ID: r.ID, CreatedAt: r.CreatedAt, UpdatedAt: r.UpdatedAt, Kind: r.Kind, Severity: r.Severity,
		UserID: r.UserID, Site: r.Site, GroupKey: r.GroupKey, Events: r.Events,
	}
	if json.Unmarshal([]byte(r.Detail), &e.Detail) != nil || e.Detail == nil {
		e.Detail = map[string]any{}
	}
	return e
}

// Sources is a folded ban row's count by source, largest first.
func (e Entry) Sources() []SourceCount {
	m, _ := e.Detail["sources"].(map[string]any)
	out := make([]SourceCount, 0, len(m))
	for k, v := range m {
		out = append(out, SourceCount{Source: k, N: int(asInt64(v))})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].N != out[j].N {
			return out[i].N > out[j].N
		}
		return out[i].Source < out[j].Source
	})
	return out
}

// SourceCount is one source's share of a folded ban row.
type SourceCount struct {
	Source string
	N      int
}

// Str reads a string field of the detail ("" when absent).
func (e Entry) Str(key string) string {
	s, _ := e.Detail[key].(string)
	return s
}

// Int reads a number field of the detail (0 when absent).
func (e Entry) Int(key string) int64 { return asInt64(e.Detail[key]) }

// Bool reads a boolean field of the detail (false when absent).
func (e Entry) Bool(key string) bool {
	b, _ := e.Detail[key].(bool)
	return b
}

// asInt64 reads a number however JSON or the notifier typed it.
func asInt64(v any) int64 {
	switch x := v.(type) {
	case int:
		return int64(x)
	case int64:
		return x
	case int32:
		return int64(x)
	case float64:
		return int64(x)
	case json.Number:
		n, _ := x.Int64()
		return n
	}
	return 0
}
