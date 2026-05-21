// Package events provides helpers to INSERT into unmask_event and aggregate.
package events

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net"
	"strings"
	"sync/atomic"
	"time"

	"github.com/unmask-sh/unmask/admin/internal/db"
)

type Phase string

const (
	PhaseServe              Phase = "serve"
	PhaseLoad               Phase = "load"
	PhasePoWPass            Phase = "pow_pass"             // multi-step mode: PoW solved, handing off to the next stage (= _bv NOT yet issued; payload.next records the follow-up)
	PhaseCaptcha            Phase = "captcha"              // CAPTCHA UI displayed (= still unauthenticated)
	PhaseBVPowOnly          Phase = "bv_pow_only"          // _bv issued via challenge_mode=pow_only
	PhaseBVCaptchaOnly      Phase = "bv_captcha_only"      // _bv issued via challenge_mode=captcha_only
	PhaseBVPowThenCaptcha   Phase = "bv_pow_then_captcha"  // _bv issued via challenge_mode=pow_then_captcha
	PhaseVerifyNG           Phase = "verify_ng"            // /verify rejected (= CAPTCHA failed)
	PhaseError              Phase = "error"                // JS exception / external CAPTCHA provider failure (payload.kind discriminates)
	PhaseCookieErr          Phase = "cookie_err"
	PhaseCheck              Phase = "check" // single auth_request /api/check hit
)

// allowedPhases gates which beacon phase strings the server accepts on
// /api/debug.  Authentication-completion phases follow the "bv_" + chMode
// pattern so adding a new challenge_mode in the future means adding the
// matching entry here only — no JSON_EXTRACT, no schema churn.
var allowedPhases = map[string]bool{
	"serve":                true,
	"load":                 true,
	"pow_pass":             true,
	"captcha":              true,
	"bv_pow_only":          true,
	"bv_captcha_only":      true,
	"bv_pow_then_captcha":  true,
	"verify_ng":            true,
	"error":                true,
	"cookie_err":           true,
	"check":                true,
}

func IsValidPhase(p string) bool { return allowedPhases[p] }

// PackIP returns the binary representation of an IPv4 (4B) or IPv6 (16B)
// address, or nil if `s` is not parseable.
func PackIP(s string) []byte {
	if s == "" {
		return nil
	}
	ip := net.ParseIP(s)
	if ip == nil {
		return nil
	}
	if v4 := ip.To4(); v4 != nil {
		out := make([]byte, 4)
		copy(out, v4)
		return out
	}
	out := make([]byte, 16)
	copy(out, ip.To16())
	return out
}

type Event struct {
	Site         string // "" -> "default" on INSERT
	Host         string // own host id (resolved at startup from settings.Server.HostID > os.Hostname()).  "" -> "default"
	IPPacked     []byte
	UserAgent    string
	JA4          string
	JA4Verdict   string
	JA4VerdictID int // preset rule ID (1-99 built-in / 100+ extra).  unknown is 0 (stored as NULL)
	Phase        string
	Flags        int
	ReloadCount  int
	CookieBV     string
	CookieBR     string
	Payload      map[string]any
	// OccurredAt is the server ingest time, captured the moment the event
	// enters the persistence layer (InsertAsync / Insert).  Stored with
	// millisecond precision so same-second events keep their true order in
	// the hunt log.  A zero value is filled with time.Now().UTC() at insert.
	OccurredAt time.Time
}

// eventTimeFormat is the canonical millisecond-precision, UTC layout written
// into unmask_event.date_created.  Fixed-width and zero-padded, so lexical
// order equals chronological order (works for both the SQLite TEXT column and
// MariaDB DATETIME(3)).
const eventTimeFormat = "2006-01-02 15:04:05.000"

// globalFlusher is set at process startup via StartFlusher.  nil is safe
// (falls back to a direct synchronous INSERT).  Singleton because passing a
// flusher through many handlers is more cumbersome than one global.  Assumes
// one process per DB.
var globalFlusher atomic.Pointer[Flusher]

// StartFlusher: call once at process startup.  Subsequent InsertAsync calls
// enqueue via the flusher in batches.  An existing globalFlusher is not
// overwritten (calling twice does not start a second one).
func StartFlusher(d *db.DB, batchSize, intervalMs int) *Flusher {
	if globalFlusher.Load() != nil {
		return globalFlusher.Load()
	}
	f := NewFlusher(d, batchSize, intervalMs)
	globalFlusher.Store(f)
	return f
}

// StopFlusher: for graceful shutdown.  Drains the queue, flushes once more,
// then exits the worker.
func StopFlusher() {
	if f := globalFlusher.Load(); f != nil {
		f.Stop()
		globalFlusher.Store(nil)
	}
}

// GlobalFlusherSetConfig: hot-reload batch size / interval via the settings
// save path.  No-op if the flusher is not running yet (pre-startup).
func GlobalFlusherSetConfig(batchSize, intervalMs int) {
	if f := globalFlusher.Load(); f != nil {
		f.SetConfig(batchSize, intervalMs)
	}
}

// GlobalFlusherDropped returns the number of dropped events.  Used by metrics / status.
func GlobalFlusherDropped() uint64 {
	if f := globalFlusher.Load(); f != nil {
		return f.DroppedCount()
	}
	return 0
}

// InsertAsync detaches event writes from the request hot path.
//   - globalFlusher present (normal operation): enqueue to the batch queue
//     (non-blocking).  Bulk INSERT after at most flushInterval (default 1s)
//     or batchSize entries.
//   - globalFlusher nil (pre-startup / CLI path / tests): single-row INSERT
//     in a fire-and-forget goroutine.
func InsertAsync(d *db.DB, e *Event) {
	if d == nil || e == nil {
		return
	}
	// Stamp the ingest time here, before the event is buffered by the
	// flusher.  Doing it at flush time would record the flush instant
	// (up to flushInterval late) instead of when the event arrived.
	if e.OccurredAt.IsZero() {
		e.OccurredAt = time.Now().UTC()
	}
	if f := globalFlusher.Load(); f != nil {
		f.Submit(e)
		return
	}
	// fallback: spawn a single-row goroutine when the flusher is not running.
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = Insert(ctx, d, e)
	}()
}

// PruneOldEvents deletes rows from unmask_event where date_created < (now - retentionDays).
// Aggregates (unmask_aggregate) are not touched.  No-op if retentionDays <= 0.
// Intended to be called every 24h from a goroutine in main.go.
func PruneOldEvents(ctx context.Context, d *db.DB, retentionDays int) (int64, error) {
	if retentionDays <= 0 || d == nil {
		return 0, nil
	}
	var stmt string
	if d.Driver == db.DriverSQLite {
		stmt = fmt.Sprintf(`DELETE FROM unmask_event WHERE date_created < datetime('now', '-%d days')`, retentionDays)
	} else {
		stmt = fmt.Sprintf(`DELETE FROM unmask_event WHERE date_created < DATE_SUB(NOW(), INTERVAL %d DAY)`, retentionDays)
	}
	res, err := d.ExecContext(ctx, stmt)
	if err != nil {
		return 0, err
	}
	n, _ := res.RowsAffected()
	return n, nil
}

// insertStmt is shared between batch and single-row inserts.
const insertStmt = `INSERT INTO unmask_event
        (site, host, ip_address, user_agent, ja4, ja4_verdict, ja4_verdict_id, phase, flags, reload_count,
         cookie_bv, cookie_br, payload_json, date_created)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`

// prepareInsertArgs expands an Event into a SQL bind args slice.  Shared
// between batch and single-row paths.  Returns nil for an invalid phase
// (caller skips the row).
func prepareInsertArgs(e *Event) []any {
	if e == nil || !IsValidPhase(e.Phase) {
		return nil
	}
	ua := truncate(e.UserAgent, 255)
	ja4 := nullIfEmpty(e.JA4)
	verdict := nullIfEmpty(e.JA4Verdict)
	cookieBV := nullIfEmpty(e.CookieBV)
	cookieBR := nullIfEmpty(e.CookieBR)

	var payloadText sql.NullString
	if e.Payload != nil {
		buf, err := json.Marshal(e.Payload)
		if err == nil {
			s := string(buf)
			if len(s) > 4000 {
				s = s[:4000]
			}
			payloadText = sql.NullString{String: s, Valid: true}
		}
	}

	site := e.Site
	if site == "" {
		site = "default"
	}
	// Safety net: site is the visitor Host (handler-normalized), but cap it at
	// the unmask_event.site column width in case an unnormalized value slips in.
	site = truncate(site, 64)
	host := e.Host
	if host == "" {
		host = "default"
	}

	var verdictID sql.NullInt64
	if e.JA4VerdictID > 0 {
		verdictID = sql.NullInt64{Int64: int64(e.JA4VerdictID), Valid: true}
	}
	occurred := e.OccurredAt
	if occurred.IsZero() {
		occurred = time.Now()
	}
	return []any{
		site, host, e.IPPacked, sqlStr(ua), ja4, verdict, verdictID, e.Phase,
		e.Flags, e.ReloadCount, cookieBV, cookieBR, payloadText,
		occurred.UTC().Format(eventTimeFormat),
	}
}

// Insert writes one row into unmask_event.  Best-effort: failures only log.
func Insert(ctx context.Context, d *db.DB, e *Event) error {
	if e != nil && e.OccurredAt.IsZero() {
		e.OccurredAt = time.Now().UTC()
	}
	args := prepareInsertArgs(e)
	if args == nil {
		return errors.New("invalid event")
	}
	if _, err := d.ExecContext(ctx, insertStmt, args...); err != nil {
		log.Printf("unmask_event insert failed: %v", err)
		return err
	}
	return nil
}

// Row is one row produced by tail / SSE.  Distinct from Event used for Insert
// (this is the output-side struct).
//
// Date is a UTC string ("2006-01-02 15:04:05.000").  Clients that want to
// reformat in the picker's TZ should use TsMs (unix millis) with the JS Date
// API; Ts (unix sec) is kept for callers that do not need sub-second precision.
type Row struct {
	ID          int64  `json:"id"`
	Date        string `json:"date"`
	Ts          int64  `json:"ts"`    // unix sec (0 if parse failed / not retrieved)
	TsMs        int64  `json:"ts_ms"` // unix millis; sub-second precision for the hunt log
	Site        string `json:"site"`
	Host        string `json:"host,omitempty"` // identifies "which machine produced this row" on a shared DB.  Omitted on single-host installs.
	IP          string `json:"ip"`
	UA          string `json:"ua,omitempty"`
	JA4         string `json:"ja4,omitempty"`
	Verdict     string `json:"verdict,omitempty"`
	Phase       string `json:"phase"`
	Flags       int    `json:"flags"`
	ReloadCount int    `json:"reload_count"`
	CookieBV    string `json:"cookie_bv,omitempty"`
	CookieBR    string `json:"cookie_br,omitempty"`
	Payload     string `json:"payload,omitempty"`
	// Action: sub-decision extracted from payload_json ("pass" / "block" etc).
	// Primarily meaningful for phase=check (the auth_request action value).
	// Used by the UI to display "check(pass)" / "check(block)".
	Action string `json:"action,omitempty"`
	// RLZone: zone name hit by rate-limit.  Sourced from payload "rl_zone".
	// Empty for normal requests (not a rate-limit hit).
	RLZone string `json:"rl_zone,omitempty"`
	// Path: original URL path the client requested.  Sourced from payload_json
	// "orig_path" (the path before challenge HTML was returned / the
	// auth_request origin URI).  Query string included.  Shown in the URL
	// column of the raw hunt log table.
	Path string `json:"path,omitempty"`
}

// extractAction is a lightweight parser that pulls "action" out of payload_json.
// Faster than calling a JSON parser (phase=check only, but high-volume).
// Returns "" on failure / missing / malformed input.
func extractAction(payload string) string {
	return extractStringField(payload, "action", 32)
}

// extractRLZone pulls "rl_zone" out of payload_json.  Requests that are not
// rate-limit hits do not carry it (returns "").  Zone names are alnum + "_"
// up to 32 chars.
func extractRLZone(payload string) string {
	return extractStringField(payload, "rl_zone", 32)
}

// extractPath pulls a URL path out of payload_json.  Field names vary by phase:
//   - phase=check (auth_request mode): "uri" (X-Original-URI or RequestURI)
//   - phase=serve (challenge HTML served, e.g. via rate-limit hit): "orig_path"
//   - phase=load / pow / captcha / verify_ok / verify_ng / etc: "url" sent by
//     the client (location.href).  In auth_request mode nginx dispatches
//     internally via error_page, so the original URL stays in the URL bar
//     and challenge.js sends it through.  Native mode rewrites to
//     /unmask/challenge/..., so we prefer "orig_path" sent via
//     window.UNMASK.orig_path embedded in challenge.html.
// Used by the URL column in the raw hunt log table.
func extractPath(payload string) string {
	if p := extractStringField(payload, "orig_path", 1024); p != "" {
		return p
	}
	if p := extractStringField(payload, "uri", 1024); p != "" {
		return p
	}
	// "url" field (location.href sent by challenge.js).  If full URL, strip
	// the host and return path + query only.
	if u := extractStringField(payload, "url", 1024); u != "" {
		return urlToPath(u)
	}
	return ""
}

// urlToPath: "https://example.com/foo?bar=1" -> "/foo?bar=1".
// If there is no scheme/host (already a path), return as-is.  The challenge
// HTML URL itself (/unmask/challenge/...) is expected to be excluded by the
// caller (relevant phases prefer orig_path, so this only fires under
// auth_request mode where the URL bar still holds the original URL).
func urlToPath(u string) string {
	if u == "" {
		return ""
	}
	if u[0] == '/' {
		return u
	}
	i := strings.Index(u, "://")
	if i < 0 {
		return ""
	}
	rest := u[i+3:]
	if j := strings.IndexByte(rest, '/'); j >= 0 {
		return rest[j:]
	}
	return "/"
}

// extractStringField is the shared string-field extractor.  maxLen caps the
// expected upper bound.
func extractStringField(payload, key string, maxLen int) string {
	if payload == "" {
		return ""
	}
	needle := `"` + key + `":"`
	idx := strings.Index(payload, needle)
	if idx < 0 {
		return ""
	}
	rest := payload[idx+len(needle):]
	end := strings.IndexByte(rest, '"')
	if end < 0 || end > maxLen {
		return ""
	}
	return rest[:end]
}

// eventTimeLayouts lists every layout unmask has written into date_created:
// the current millisecond format first, then legacy second-precision rows
// (the old DEFAULT CURRENT_TIMESTAMP) and the ISO-8601 variant modernc/sqlite
// returns for those.
var eventTimeLayouts = []string{
	"2006-01-02 15:04:05.000",
	"2006-01-02T15:04:05.000Z",
	"2006-01-02 15:04:05",
	"2006-01-02T15:04:05Z",
}

// normalizeEventTime unifies a driver-returned date_created (SQLite hands back
// TEXT, MariaDB a time.Time) into a UTC display string, unix seconds and unix
// millis.  An unparseable value surfaces as the cleaned raw string with ts 0.
func normalizeEventTime(date sql.NullTime, dateStr sql.NullString) (display string, tsSec, tsMs int64) {
	var t time.Time
	switch {
	case date.Valid:
		t = date.Time.UTC()
	case dateStr.Valid:
		for _, layout := range eventTimeLayouts {
			if parsed, err := time.Parse(layout, dateStr.String); err == nil {
				t = parsed.UTC()
				break
			}
		}
		if t.IsZero() {
			s := strings.TrimSuffix(strings.ReplaceAll(dateStr.String, "T", " "), "Z")
			return s, 0, 0
		}
	default:
		return "", 0, 0
	}
	return t.Format(eventTimeFormat), t.Unix(), t.UnixMilli()
}

// FetchSince returns rows with id > sinceID, optionally filtered by site / phase / hosts.
// Ordered by id ASC.  Limit is capped to 1..500.  Called by both CLI tail and SSE.
//
// hosts: nil / empty means all hosts.  Non-empty narrows with IN (...) (for
// the dashboard's multi-select filter).  "All hosts" is the default; non-empty
// is used only when a host filter is requested.
func FetchSince(ctx context.Context, d *db.DB, sinceID int64, site, phase string, hosts []string, limit int) ([]Row, error) {
	if limit < 1 {
		limit = 1
	} else if limit > 500 {
		limit = 500
	}
	stmt := `SELECT id, date_created, site, host, ip_address, user_agent, ja4, ja4_verdict,
	         phase, flags, reload_count, cookie_bv, cookie_br, payload_json
	         FROM unmask_event WHERE id > ?`
	args := []any{sinceID}
	if site != "" {
		stmt += " AND site = ?"
		args = append(args, site)
	}
	if phase != "" {
		stmt += " AND phase = ?"
		args = append(args, phase)
	}
	if hf, hargs := buildHostFilter(hosts); hf != "" {
		stmt += hf
		args = append(args, hargs...)
	}
	stmt += " ORDER BY id ASC LIMIT ?"
	args = append(args, limit)

	rows, err := d.QueryContext(ctx, stmt, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := make([]Row, 0, 32)
	for rows.Next() {
		var (
			id, flags, rcount       int64
			date                    sql.NullTime
			dateStr                 sql.NullString
			site_, host_, phase_    string
			ipBytes                 []byte
			ua, ja4, verdict        sql.NullString
			cBV, cBR, payload       sql.NullString
		)
		// SQLite returns TEXT as string; MariaDB returns DATETIME as time.Time.  Handle both.
		if d.Driver == db.DriverSQLite {
			if err := rows.Scan(&id, &dateStr, &site_, &host_, &ipBytes, &ua, &ja4, &verdict,
				&phase_, &flags, &rcount, &cBV, &cBR, &payload); err != nil {
				return nil, err
			}
		} else {
			if err := rows.Scan(&id, &date, &site_, &host_, &ipBytes, &ua, &ja4, &verdict,
				&phase_, &flags, &rcount, &cBV, &cBR, &payload); err != nil {
				return nil, err
			}
		}
		dStr, ts, tsMs := normalizeEventTime(date, dateStr)
		r := Row{
			ID:          id,
			Date:        dStr,
			Ts:          ts,
			TsMs:        tsMs,
			Site:        site_,
			Host:        host_,
			IP:          unpackIP(ipBytes),
			UA:          ua.String,
			JA4:         ja4.String,
			Verdict:     verdict.String,
			Phase:       phase_,
			Flags:       int(flags),
			ReloadCount: int(rcount),
			CookieBV:    cBV.String,
			CookieBR:    cBR.String,
			Payload:     payload.String,
		}
		if r.Phase == "check" {
			r.Action = extractAction(payload.String)
			r.RLZone = extractRLZone(payload.String)
		}
		// Path is extracted regardless of phase (recorded for load / serve / check).
		r.Path = extractPath(payload.String)
		out = append(out, r)
	}
	return out, rows.Err()
}

// FetchPaged fetches the most recent rows id DESC, limit per page from offset.  Used by the hunt tab UI.
//   filter: ipSubstr (LIKE on IP), ja4Substr (LIKE on JA4), phase, sinceMin (now - sinceMin minutes; 0 for unlimited)
//   site  : "" for all sites; non-empty narrows to that one site (single-select filter).
//   hosts : nil/empty for all hosts; non-empty narrows via IN (...) (multi-select filter).
//
// Sits on the shared SQLite / MariaDB driver abstraction.  Caps at limit 1000 / offset 100000.
func FetchPaged(ctx context.Context, d *db.DB, ipSubstr, ja4Substr, phase, site string, hosts []string, sinceMin int, limit, offset int) ([]Row, error) {
	if limit < 1 || limit > 1000 {
		limit = 100
	}
	if offset < 0 || offset > 100000 {
		offset = 0
	}
	stmt := `SELECT id, date_created, site, host, ip_address, user_agent, ja4, ja4_verdict,
	         phase, flags, reload_count, cookie_bv, cookie_br, payload_json
	         FROM unmask_event WHERE 1=1`
	args := []any{}
	if phase != "" {
		stmt += " AND phase = ?"
		args = append(args, phase)
	}
	if ja4Substr != "" {
		stmt += " AND ja4 LIKE ?"
		args = append(args, "%"+ja4Substr+"%")
	}
	// IP is packed binary ([]byte 4 / 16 bytes), so LIKE cannot narrow it.
	// Only exact match is supported (pass a valid IP as ipSubstr).
	if ipSubstr != "" {
		if pkt := PackIP(ipSubstr); pkt != nil {
			stmt += " AND ip_address = ?"
			args = append(args, pkt)
		}
	}
	if site != "" {
		stmt += " AND site = ?"
		args = append(args, site)
	}
	if hf, hargs := buildHostFilter(hosts); hf != "" {
		stmt += hf
		args = append(args, hargs...)
	}
	if sinceMin > 0 {
		stmt += " AND date_created > " + d.NowMinusMinutes(sinceMin)
	}
	// Order by the millisecond ingest timestamp so same-second events keep
	// their true arrival order; id is the deterministic tie-breaker for the
	// rare case of two events sharing an identical millisecond.
	stmt += " ORDER BY date_created DESC, id DESC LIMIT ? OFFSET ?"
	args = append(args, limit, offset)

	rows, err := d.QueryContext(ctx, stmt, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := make([]Row, 0, limit)
	for rows.Next() {
		var (
			id, flags, rcount       int64
			date                    sql.NullTime
			dateStr                 sql.NullString
			site_, host_, phase_    string
			ipBytes                 []byte
			ua, ja4, verdict        sql.NullString
			cBV, cBR, payload       sql.NullString
		)
		if d.Driver == db.DriverSQLite {
			if err := rows.Scan(&id, &dateStr, &site_, &host_, &ipBytes, &ua, &ja4, &verdict,
				&phase_, &flags, &rcount, &cBV, &cBR, &payload); err != nil {
				return nil, err
			}
		} else {
			if err := rows.Scan(&id, &date, &site_, &host_, &ipBytes, &ua, &ja4, &verdict,
				&phase_, &flags, &rcount, &cBV, &cBR, &payload); err != nil {
				return nil, err
			}
		}
		dStr, ts, tsMs := normalizeEventTime(date, dateStr)
		row := Row{
			ID: id, Date: dStr, Ts: ts, TsMs: tsMs, Site: site_, Host: host_, IP: unpackIP(ipBytes),
			UA: ua.String, JA4: ja4.String, Verdict: verdict.String,
			Phase: phase_, Flags: int(flags), ReloadCount: int(rcount),
			CookieBV: cBV.String, CookieBR: cBR.String, Payload: payload.String,
		}
		if row.Phase == "check" {
			row.Action = extractAction(payload.String)
			row.RLZone = extractRLZone(payload.String)
		}
		row.Path = extractPath(payload.String)
		out = append(out, row)
	}
	return out, rows.Err()
}

// RankRow is one row of a ranking aggregate (used by the bot hunt tab for IP/UA/JA4 rankings).
type RankRow struct {
	Key   string // one of IP / UA / JA4
	Count int
}

// RankByIP aggregates unmask_event from the last sinceMin minutes by IP.  Top limit entries.
func RankByIP(ctx context.Context, d *db.DB, sinceMin, limit int) ([]RankRow, error) {
	if limit < 1 || limit > 200 {
		limit = 30
	}
	stmt := `SELECT ip_address, COUNT(*) AS c FROM unmask_event
	         WHERE date_created > ` + d.NowMinusMinutes(sinceMin) + `
	         GROUP BY ip_address ORDER BY c DESC LIMIT ?`
	rows, err := d.QueryContext(ctx, stmt, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []RankRow{}
	for rows.Next() {
		var ipBytes []byte
		var c int
		if err := rows.Scan(&ipBytes, &c); err != nil {
			return nil, err
		}
		out = append(out, RankRow{Key: unpackIP(ipBytes), Count: c})
	}
	return out, rows.Err()
}

// RankByJA4 aggregates unmask_event from the last sinceMin minutes by JA4.
func RankByJA4(ctx context.Context, d *db.DB, sinceMin, limit int) ([]RankRow, error) {
	if limit < 1 || limit > 200 {
		limit = 30
	}
	stmt := `SELECT COALESCE(ja4, ''), COUNT(*) AS c FROM unmask_event
	         WHERE date_created > ` + d.NowMinusMinutes(sinceMin) + `
	         GROUP BY ja4 ORDER BY c DESC LIMIT ?`
	rows, err := d.QueryContext(ctx, stmt, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []RankRow{}
	for rows.Next() {
		var k string
		var c int
		if err := rows.Scan(&k, &c); err != nil {
			return nil, err
		}
		out = append(out, RankRow{Key: k, Count: c})
	}
	return out, rows.Err()
}

// RankByUA aggregates unmask_event from the last sinceMin minutes by UA.
func RankByUA(ctx context.Context, d *db.DB, sinceMin, limit int) ([]RankRow, error) {
	if limit < 1 || limit > 200 {
		limit = 30
	}
	stmt := `SELECT COALESCE(user_agent, ''), COUNT(*) AS c FROM unmask_event
	         WHERE date_created > ` + d.NowMinusMinutes(sinceMin) + `
	         GROUP BY user_agent ORDER BY c DESC LIMIT ?`
	rows, err := d.QueryContext(ctx, stmt, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []RankRow{}
	for rows.Next() {
		var k string
		var c int
		if err := rows.Scan(&k, &c); err != nil {
			return nil, err
		}
		out = append(out, RankRow{Key: k, Count: c})
	}
	return out, rows.Err()
}

// DistinctSites lists the distinct site values observed in unmask_event.
// Used by site dropdown / datalist suggestions.  Capped at 100 entries.
func DistinctSites(ctx context.Context, d *db.DB) ([]string, error) {
	rows, err := d.QueryContext(ctx,
		`SELECT DISTINCT site FROM unmask_event WHERE site IS NOT NULL AND site != '' ORDER BY site LIMIT 100`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []string{}
	for rows.Next() {
		var s string
		if err := rows.Scan(&s); err != nil {
			return nil, err
		}
		out = append(out, s)
	}
	return out, rows.Err()
}

// DistinctHosts lists the distinct host values observed in unmask_event.
// Used by the host multi-select filter.  Capped at 200 entries.
//
// On a shared DB this returns "every host that ever wrote here" (retired
// machines linger).  A separate endpoint with a date_created filter could
// exclude retired hosts, but the shotgun list is sufficient for now.
func DistinctHosts(ctx context.Context, d *db.DB) ([]string, error) {
	rows, err := d.QueryContext(ctx,
		`SELECT DISTINCT host FROM unmask_event WHERE host IS NOT NULL AND host != '' ORDER BY host LIMIT 200`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []string{}
	for rows.Next() {
		var s string
		if err := rows.Scan(&s); err != nil {
			return nil, err
		}
		out = append(out, s)
	}
	return out, rows.Err()
}

// buildHostFilter converts a hosts slice into " AND host IN (?, ?, ...)" plus args.
// nil / empty returns empty (no filter).  Duplicates and empty strings are
// dropped.  Capped at 64 entries as a safety guard (the dashboard never
// generates that many choices).
func buildHostFilter(hosts []string) (string, []any) {
	if len(hosts) == 0 {
		return "", nil
	}
	seen := make(map[string]bool, len(hosts))
	args := make([]any, 0, len(hosts))
	for _, h := range hosts {
		h = strings.TrimSpace(h)
		if h == "" || seen[h] {
			continue
		}
		seen[h] = true
		args = append(args, h)
		if len(args) >= 64 {
			break
		}
	}
	if len(args) == 0 {
		return "", nil
	}
	placeholders := strings.Repeat("?,", len(args))
	placeholders = placeholders[:len(placeholders)-1]
	return " AND host IN (" + placeholders + ")", args
}

// MaxID returns the largest id currently in unmask_event (= start point for
// "tail from now").  Returns 0 if table is empty.
func MaxID(ctx context.Context, d *db.DB) (int64, error) {
	row := d.QueryRowContext(ctx, `SELECT COALESCE(MAX(id), 0) FROM unmask_event`)
	var n int64
	if err := row.Scan(&n); err != nil {
		return 0, err
	}
	return n, nil
}

func unpackIP(b []byte) string {
	switch len(b) {
	case 4:
		return net.IP(b).To4().String()
	case 16:
		return net.IP(b).To16().String()
	}
	return ""
}

// CountRecentByIP returns how many events from `ipPacked` happened in the
// last `minutes` minutes.  Used to enforce per-IP debug rate limit.
func CountRecentByIP(ctx context.Context, d *db.DB, ipPacked []byte, minutes int) (int, error) {
	stmt := `SELECT COUNT(*) FROM unmask_event WHERE ip_address = ? AND date_created > ` +
		d.NowMinusMinutes(minutes)
	row := d.QueryRowContext(ctx, stmt, ipPacked)
	var n int
	if err := row.Scan(&n); err != nil {
		return 0, err
	}
	return n, nil
}

func truncate(s string, n int) string {
	if len(s) > n {
		return s[:n]
	}
	return s
}

func nullIfEmpty(s string) sql.NullString {
	if s == "" {
		return sql.NullString{}
	}
	return sql.NullString{String: s, Valid: true}
}

// sqlStr is like nullIfEmpty but for UA where empty string is also allowed.
func sqlStr(s string) sql.NullString { return nullIfEmpty(s) }
