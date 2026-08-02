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
	"sort"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/unmask-sh/unmask/admin/internal/db"
)

type Phase string

const (
	PhaseServe            Phase = "serve"
	PhaseLoad             Phase = "load"
	PhasePoWPass          Phase = "pow_pass"            // multi-step mode: PoW solved, handing off to the next stage (= _bv NOT yet issued; payload.next records the follow-up)
	PhaseCaptcha          Phase = "captcha"             // CAPTCHA UI displayed (= still unauthenticated)
	PhaseBVPowOnly        Phase = "bv_pow_only"         // _bv issued via challenge_mode=pow_only
	PhaseBVCaptchaOnly    Phase = "bv_captcha_only"     // _bv issued via challenge_mode=captcha_only
	PhaseBVPowThenCaptcha Phase = "bv_pow_then_captcha" // _bv issued via challenge_mode=pow_then_captcha
	PhaseVerifyNG         Phase = "verify_ng"           // /verify rejected (= CAPTCHA failed)
	PhaseError            Phase = "error"               // JS exception / external CAPTCHA provider failure (payload.kind discriminates)
	PhaseCookieErr        Phase = "cookie_err"
	PhaseCheck            Phase = "check"            // single auth_request /api/check hit
	PhaseBVRebind         Phase = "bv_rebind"        // _bv silently re-bound to a new IP on the challenge route (roaming client, no PoW shown)
	PhaseBVRebindReject   Phase = "bv_rebind_reject" // a silent roaming rebind was refused; payload.reason gives the cause (no_bvj / bvj_invalid / ja4_mismatch / ua_mismatch / asn_mismatch / cap) and the client falls through to a real challenge
)

// allowedPhases gates which beacon phase strings the server accepts on
// /api/debug.  Authentication-completion phases follow the "bv_" + chMode
// pattern so adding a new challenge_mode in the future means adding the
// matching entry here only — no JSON_EXTRACT, no schema churn.
var allowedPhases = map[string]bool{
	"serve":               true,
	"load":                true,
	"pow_pass":            true,
	"captcha":             true,
	"bv_pow_only":         true,
	"bv_captcha_only":     true,
	"bv_pow_then_captcha": true,
	"verify_ng":           true,
	"error":               true,
	"cookie_err":          true,
	// abandon: the visitor left while the challenge was still running (tab
	// closed, back, navigated away).  Without it a departure is invisible and
	// reads exactly like a bot that fetched the page and never executed the
	// JS -- the only way to tell them apart was the absence of a later phase,
	// which cannot distinguish "gave up after 3 seconds" from "never ran".
	// The payload carries the phase it left from and the elapsed ms, so the
	// question the counts cannot answer -- are we losing people to the wait,
	// and at which step -- becomes measurable.
	"abandon":          true,
	"check":            true,
	"bv_rebind":        true,
	"bv_rebind_reject": true,
}

func IsValidPhase(p string) bool { return allowedPhases[p] }

// parsePhaseList turns the hunt filter's phase value into a validated set.
// One name behaves as before; a comma-separated list lets the UI offer groups
// ("passed", "in flight", "rejected") without a second query parameter.
// Anything not a known phase is dropped -- the value is user input, and a
// silent drop keeps a typo from widening the result set instead of narrowing
// it.  Order is preserved and duplicates collapse, so the SQL placeholder
// count always matches.
func parsePhaseList(v string) []string {
	if strings.TrimSpace(v) == "" {
		return nil
	}
	seen := map[string]bool{}
	out := make([]string, 0, 4)
	for _, p := range strings.Split(v, ",") {
		p = strings.TrimSpace(p)
		if p == "" || seen[p] || !allowedPhases[p] {
			continue
		}
		seen[p] = true
		out = append(out, p)
	}
	return out
}

// CanonicalPhaseFilter validates a hunt phase filter value (one name, or a
// comma-separated group) and returns it in canonical form -- known names only,
// de-duplicated, original order.  Returns "" when nothing in the value is a
// known phase, which callers treat as "keep what the user typed" so the query
// returns nothing instead of everything.
func CanonicalPhaseFilter(v string) string {
	return strings.Join(parsePhaseList(v), ",")
}

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
	Scheme       string // "http" / "https" — captured server-side from X-Forwarded-Proto (= the nginx-rendered config overrides any client-sent value).  "" = unknown / pre-migration row.
	Port         int    // listener port captured server-side from X-Forwarded-Port.  0 = unknown / pre-migration row.
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
	// Compute the cutoff in Go so the SQL stays driver-agnostic (= no more
	// datetime('now',…) vs DATE_SUB(NOW(),…) branch).  The original column
	// is DATETIME; the mysql driver parses time.Time, the glebarez/modernc
	// driver compares ISO8601-ish strings -- the comparison "<" works for
	// both, so we pass a time.Time bind and let the driver format it.
	// .UTC() because rows are stored UTC-at-rest and the sqlite driver
	// formats the bind in the value's own zone -- a host-local cutoff would
	// skew the retention boundary by the host TZ offset.
	cutoff := time.Now().UTC().Add(-time.Duration(retentionDays) * 24 * time.Hour)
	res, err := d.ExecContext(ctx,
		`DELETE FROM unmask_event WHERE date_created < ?`, cutoff)
	if err != nil {
		return 0, err
	}
	n, _ := res.RowsAffected()
	return n, nil
}

// insertStmt is shared between batch and single-row inserts.
const insertStmt = `INSERT INTO unmask_event
        (site, host, scheme, port, ip_address, user_agent, ja4, ja4_verdict, ja4_verdict_id, phase, flags, reload_count,
         cookie_bv, cookie_br, payload_json, ref_id, date_created)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`

// prepareInsertArgs expands an Event into a SQL bind args slice.  Shared
// between batch and single-row paths.  Returns nil for an invalid phase
// (caller skips the row).
func prepareInsertArgs(e *Event) []any {
	if e == nil || !IsValidPhase(e.Phase) {
		return nil
	}
	ua := truncate(e.UserAgent, 255)
	ja4 := nullIfEmpty(e.JA4)
	// ja4_verdict is VARCHAR(40) and comes from the X-JA4-Verdict header on the
	// beacon path; cap it so an over-long value can't raise MariaDB error 1406
	// and roll back the entire (default 100-event) batch insert.
	verdict := nullIfEmpty(truncate(e.JA4Verdict, 40))
	cookieBV := nullIfEmpty(e.CookieBV)
	cookieBR := nullIfEmpty(e.CookieBR)

	var payloadText sql.NullString
	// ref_id is a plain column the writer fills, indexed so the support lookup
	// ("a visitor is on the phone quoting the code from the block page") seeks
	// instead of scanning.  Filled from the serialized payload with the same
	// extractRef the read path uses, so there is one definition of what the ref
	// is -- and reading it back costs nothing, unlike a computed column.
	var refID sql.NullString
	if e.Payload != nil {
		buf, err := json.Marshal(e.Payload)
		if err == nil {
			s := string(buf)
			if len(s) > 4000 {
				// A byte-truncation here would cut mid-token and produce invalid
				// JSON, which breaks every dashboard card that JSON-parses
				// payload_json.  Store a valid sentinel instead of corrupt JSON.
				s = `{"_truncated":true}`
			}
			payloadText = sql.NullString{String: s, Valid: true}
			refID = nullIfEmpty(extractRef(s))
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
		occurred = time.Now().UTC() // UTC-at-rest, matching the OccurredAt fill in InsertAsync
	}
	scheme := strings.ToLower(strings.TrimSpace(e.Scheme))
	if scheme != "http" && scheme != "https" {
		scheme = "" // stored as empty string for unknown / pre-X-Forwarded-Proto setups
	}
	port := e.Port
	if port < 0 || port > 65535 {
		port = 0
	}
	return []any{
		site, host, scheme, port, e.IPPacked, sqlStr(ua), ja4, verdict, verdictID, e.Phase,
		e.Flags, e.ReloadCount, cookieBV, cookieBR, payloadText, refID,
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
	Host        string `json:"host,omitempty"`   // identifies "which machine produced this row" on a shared DB.  Omitted on single-host installs.
	Scheme      string `json:"scheme,omitempty"` // "http" / "https" -- server-side captured from X-Forwarded-Proto so the URL popover can build a real address.  Empty for rows ingested before migration 0010.
	Port        int    `json:"port,omitempty"`   // listener port captured server-side from X-Forwarded-Port.  0 = unknown / pre-migration.
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
	// BeaconToken: identifier minted per challenge HTML serve and echoed by
	// every subsequent beacon from that challenge session.  Used by the hunt
	// UI's "session view" to collapse 3-5 rows of one challenge fire into a
	// single row.  Different challenge serves get different tokens, so a bot
	// reloading repeatedly is never accidentally merged.
	BeaconToken string `json:"bt,omitempty"`
	// Ref: the short human-readable correlation id shown at the bottom of the
	// challenge / deny / ban page (the "Ref" a blocked visitor quotes when they
	// contact support).  Sourced from payload "ref".  Lets an operator tie that
	// report back to this exact serve event + its decision context via
	// `unmask events --ref`.  Empty on phases that never render a page.
	Ref string `json:"ref,omitempty"`
	// LBWarning: operator-misconfiguration / spoof signal sourced from payload
	// "lb_warning".  Non-empty when the /api/check request carried an LB-
	// forwarded header (X-Client-JA4 / X-Unmask-Site) that the admin's
	// TrustForwarded* settings rejected -- almost always an operator setup gap
	// where the proxy forwards JA4 but the admin never opted in, occasionally
	// a visitor probing whether the header is honored.  Empty on phase=check
	// rows with a clean header set, and on all challenge-flow phases.
	LBWarning string `json:"lb_warning,omitempty"`
	// Reason: roaming-rebind decision sourced from payload "reason".  On
	// phase=bv_rebind_reject it is the refusal cause (no_bvj / bvj_invalid /
	// ja4_mismatch / ua_mismatch / asn_mismatch / cap); on phase=bv_rebind it is
	// how the rebind passed (ja4_relaxed / asn / match).  Lets the hunt log render
	// "bv_rebind_reject(ja4_mismatch)" / "bv_rebind(ja4_relaxed)" so an operator
	// sees WHY/HOW a roaming rebind went the way it did.
	Reason string `json:"reason,omitempty"`
	// ForceReason: why a challenge was forced, sourced from payload
	// "force_reason" (rate_limit / ja4_bot / honeypot / banned / protected /
	// test / none).  Present on phase=serve rows.  Distinct from Reason above
	// (the roaming-rebind cause); notably surfaces rate_limit so a rate-limit
	// block is greppable / countable from `unmask events`.
	ForceReason string `json:"force_reason,omitempty"`
	// AbandonPhase / LeftAtMs / NoticeDelayMs: departure detail, sourced from
	// the abandon beacon.  AbandonPhase is the step the visitor was on when
	// they left; LeftAtMs is when they actually left (the browser's own event
	// timestamp) and NoticeDelayMs how much later the page was able to run the
	// handler -- the PoW holds the main thread, so those two differ and only
	// the first answers "how long did they wait".  Empty / zero off abandon rows.
	AbandonPhase string `json:"abandon_phase,omitempty"`
	// AbandonVia: "pagehide" (left the page -- navigated away or closed) or
	// "hidden" (only backgrounded the tab, so they may still come back).  The
	// distinction browsers DO let us make, unlike Back-vs-close.
	AbandonVia    string `json:"abandon_via,omitempty"`
	LeftAtMs      int    `json:"left_at_ms,omitempty"`
	NoticeDelayMs int    `json:"notice_delay_ms,omitempty"`
	// Returned: on phase=abandon rows, whether the same client sent anything
	// else within the next 30 seconds.  Browsers refuse to tell JS whether a
	// visitor pressed Back or closed the tab, and the one hint they do give
	// (the bfcache persisted flag) is structurally false here because a
	// challenge page must be served no-store.  The server can still answer the
	// question that matters: going back lands the visitor somewhere and
	// produces another request, while closing produces silence.  0 = nothing
	// followed (gone), >0 = they stayed on the site.
	Returned int `json:"returned,omitempty"`
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

// extractLBWarning pulls "lb_warning" out of payload_json.  Set by AuthCheck
// (= phase=check only) when the request carried an LB-forwarded header that
// the admin's trust config rejected.  Cap at 256 chars; the writer concatenates
// at most a couple of short fixed strings, so anything longer is malformed.
func extractLBWarning(payload string) string {
	return extractStringField(payload, "lb_warning", 256)
}

// extractBeaconToken pulls "bt" out of payload_json.  The token is generated
// per challenge HTML serve and carried by every subsequent beacon from that
// challenge session (load / pow / captcha / verify_ok / etc.), so it is the
// natural primary key for collapsing the hunt-log table into one row per
// challenge session.  Empty for `phase=check` rows (= the auth_request
// subrequest never opens a challenge), in which case the hunt UI falls back
// to "no grouping" for that row.
func extractBeaconToken(payload string) string {
	return extractStringField(payload, "bt", 64)
}

// extractRef pulls "ref" out of payload_json -- the 16-hex-char correlation id
// shown on the challenge / deny / ban page.
func extractRef(payload string) string {
	return extractStringField(payload, "ref", 16)
}

// extractReason pulls "reason" out of payload_json -- the rebind-refusal cause
// on phase=bv_rebind_reject (no_bvj / bvj_invalid / ja4_mismatch / ua_mismatch /
// asn_mismatch / cap).  Empty on phases that don't carry it.
func extractReason(payload string) string {
	return extractStringField(payload, "reason", 24)
}

// decorateRowFromPayload fills every payload-derived Row field.  ONE function on
// purpose: FetchSince, FetchPaged and scanEventRows each decorate rows, and
// maintaining the extract list per-site is how force_reason ended up populated
// on one path and missing on the other two (partial-row-shape bug).  Path is
// phase-independent (load / serve / check); BeaconToken rides every
// challenge-flow phase and is absent on phase=check.
func decorateRowFromPayload(row *Row, payload string) {
	row.Path = extractPath(payload)
	row.BeaconToken = extractBeaconToken(payload)
	row.Ref = extractRef(payload)
	row.Reason = extractReason(payload)
	row.ForceReason = extractForceReason(payload)
	if row.Phase == "abandon" {
		row.AbandonPhase = extractStringField(payload, "abandon_phase", 32)
		row.AbandonVia = extractStringField(payload, "abandon_via", 16)
		row.LeftAtMs = extractIntField(payload, "left_at_ms")
		row.NoticeDelayMs = extractIntField(payload, "notice_delay_ms")
	}
}

// extractIntField pulls a bare (unquoted) numeric field out of payload_json.
// Same hand-rolled approach as extractStringField: these run on every hunt row,
// and a full JSON parse per row costs more than the field is worth.
func extractIntField(payload, key string) int {
	needle := `"` + key + `":`
	i := strings.Index(payload, needle)
	if i < 0 {
		return 0
	}
	rest := payload[i+len(needle):]
	j := 0
	for j < len(rest) && (rest[j] == ' ') {
		j++
	}
	start := j
	for j < len(rest) && rest[j] >= '0' && rest[j] <= '9' {
		j++
	}
	if j == start || j-start > 12 {
		return 0
	}
	n, err := strconv.Atoi(rest[start:j])
	if err != nil {
		return 0
	}
	return n
}

// extractForceReason pulls "force_reason" out of payload_json -- why a challenge
// was forced (rate_limit / ja4_bot / honeypot / banned / protected / test /
// none).  Recorded on phase=serve rows; empty elsewhere.
func extractForceReason(payload string) string {
	return extractStringField(payload, "force_reason", 24)
}

// extractPath pulls a URL path out of payload_json.  Field names vary by phase:
//   - phase=check (forward-auth mode): "uri" (X-Original-URI or RequestURI)
//   - phase=serve (challenge HTML served, e.g. via rate-limit hit): "orig_path"
//   - phase=load / pow / captcha / verify_ok / verify_ng / etc: "url" sent by
//     the client (location.href).  In forward-auth mode nginx dispatches
//     internally via error_page, so the original URL stays in the URL bar
//     and challenge.js sends it through.  Native mode rewrites to
//     /unmask/challenge/..., so we prefer "orig_path" sent via
//     window.UNMASK.orig_path embedded in challenge.html.
//
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
// forward-auth mode where the URL bar still holds the original URL).
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
	// Find the closing quote, skipping \" (and any other \x) escapes so a value
	// containing an escaped quote isn't truncated early (L-C2).  The returned
	// slice keeps the JSON escaping; a caller needing literal text unescapes it.
	end := -1
	for i := 0; i < len(rest) && i <= maxLen; i++ {
		if rest[i] == '\\' {
			i++ // skip the escaped character
			continue
		}
		if rest[i] == '"' {
			end = i
			break
		}
	}
	if end < 0 {
		return ""
	}
	return rest[:end]
}

// eventTimeLayouts lists the layouts admin writes into date_created.
// The millisecond format is canonical; the ISO-8601 variant is what
// modernc/sqlite returns to Go for the same value.
//
// The bare-second layouts are the robust fallback: Go's time.Parse
// auto-absorbs a fractional second after the seconds field when the
// layout itself carries no fractional specifier, so they match ANY
// precision (.35 / .350 / .350000 / none).  Without them a value with
// other than exactly 3 fractional digits (= e.g. a DATETIME(2) column,
// or a trailing-zero-trimmed store) fails every strict layout, falls
// through to the raw-string branch with ts=0, and the operator sees an
// un-reformatted UTC string (= no operator-TZ, no JST) on the hunt log.
// Keep in sync with dashboard.parseDateTimeToUnix.
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
	stmt := `SELECT id, date_created, site, host, scheme, port, ip_address, user_agent, ja4, ja4_verdict,
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
			id, flags, rcount    int64
			date                 sql.NullTime
			dateStr              sql.NullString
			site_, host_, phase_ string
			scheme_              sql.NullString
			port_                sql.NullInt64
			ipBytes              []byte
			ua, ja4, verdict     sql.NullString
			cBV, cBR, payload    sql.NullString
		)
		// SQLite returns TEXT as string; MariaDB returns DATETIME as time.Time.  Handle both.
		if d.Driver == db.DriverSQLite {
			if err := rows.Scan(&id, &dateStr, &site_, &host_, &scheme_, &port_, &ipBytes, &ua, &ja4, &verdict,
				&phase_, &flags, &rcount, &cBV, &cBR, &payload); err != nil {
				return nil, err
			}
		} else {
			if err := rows.Scan(&id, &date, &site_, &host_, &scheme_, &port_, &ipBytes, &ua, &ja4, &verdict,
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
			Scheme:      scheme_.String,
			Port:        int(port_.Int64),
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
			r.LBWarning = extractLBWarning(payload.String)
		}
		decorateRowFromPayload(&r, payload.String)
		out = append(out, r)
	}
	return out, rows.Err()
}

// huntWindowKey carries a custom [from,to] range (unix sec UTC) through ctx so
// the hunt queries can bound to an operator-chosen period instead of only the
// trailing `sinceMin`.  Kept local to the events package (a tiny mirror of
// dashboard's Window plumbing) to avoid an events->dashboard import cycle.
type huntWindowKey struct{}

// WithHuntWindow attaches a custom [fromTS,toTS] window to ctx.  The hunt
// handler calls this once for range=custom; FetchPaged / RankBy* then bound to
// it.  A zero / inverted pair is ignored (the trailing sinceMin applies).
func WithHuntWindow(ctx context.Context, fromTS, toTS int64) context.Context {
	return context.WithValue(ctx, huntWindowKey{}, [2]int64{fromTS, toTS})
}

// huntFreezeKey carries the id the hunt page froze its result set at.
type huntFreezeKey struct{}

// WithHuntFreeze bounds every subsequent hunt query to rows that already
// existed when the operator started paging.
//
// Without it, offset paging over a log that is still being written double-shows
// rows: `?offset=100` means "skip the newest 100", and by the time the operator
// clicks it, events have arrived and pushed the rows they just read down past
// that mark, so the next page opens with rows from the previous one.  A busy
// node writes fast enough for the whole page to be rows already seen.
//
// The bound is an id rather than a timestamp because ids are assigned at INSERT
// while date_created is captured earlier, when the event enters the write
// queue: a row flushed after the freeze can still carry a timestamp from before
// it, and a timestamp bound would let exactly those rows shift the paging it is
// meant to hold still.
func WithHuntFreeze(ctx context.Context, maxID int64) context.Context {
	return context.WithValue(ctx, huntFreezeKey{}, maxID)
}

// huntFreeze returns the frozen upper-bound id, or 0 when the view is live.
func huntFreeze(ctx context.Context) int64 {
	id, _ := ctx.Value(huntFreezeKey{}).(int64)
	return id
}

// MaxEventID is the freeze point the hunt page pins its paging to: the newest
// row that exists right now.  Filters are deliberately not applied -- the id
// only has to separate "already stored" from "arrived while the operator was
// reading", and an unfiltered MAX(id) is an index lookup.
func MaxEventID(ctx context.Context, d *db.DB) (int64, error) {
	var id sql.NullInt64
	if err := d.QueryRowContext(ctx, `SELECT MAX(id) FROM unmask_event`).Scan(&id); err != nil {
		return 0, err
	}
	return id.Int64, nil
}

// dateCreatedWindow returns the date_created predicate for a hunt query: the ctx
// custom window when present, else the trailing `date_created > now-sinceMin`,
// else "" when sinceMin<=0 (the "0 = unlimited" contract FetchPaged relies on).
func dateCreatedWindow(ctx context.Context, d *db.DB, sinceMin int) string {
	if w, ok := ctx.Value(huntWindowKey{}).([2]int64); ok && w[0] > 0 && w[1] > w[0] {
		lo := time.Unix(w[0], 0).UTC().Format("2006-01-02 15:04:05")
		hi := time.Unix(w[1], 0).UTC().Format("2006-01-02 15:04:05")
		return "date_created >= '" + lo + "' AND date_created <= '" + hi + "'"
	}
	if sinceMin > 0 {
		return "date_created > " + d.NowMinusMinutes(sinceMin)
	}
	return ""
}

// FetchPaged fetches the most recent rows id DESC, limit per page from offset.  Used by the hunt tab UI.
//
//	filter: ipSubstr (LIKE on IP), ja4Substr (LIKE on JA4), phase, sinceMin (now - sinceMin minutes; 0 for unlimited)
//	site  : "" for all sites; non-empty narrows to that one site (single-select filter).
//	hosts : nil/empty for all hosts; non-empty narrows via IN (...) (multi-select filter).
//
// Sits on the shared SQLite / MariaDB driver abstraction.  Caps at limit 1000 / offset 100000.
// SessionBleed is how many rows FetchPagedWithBleed reads on each side of the
// page window so a session split by the page boundary can still be shown
// whole.  What matters is not how many rows a session HAS (3-4 in practice)
// but how far they SPREAD once interleaved with concurrent traffic -- a
// 4-row session that takes a minute to finish can span hundreds of row
// positions on a busy install.  Measured on a 60k-row fleet sample: 2.6% of
// sessions spread past 8 rows (the old value, which left orphan fragments on
// page boundaries), 0.08% past 100, 0.03% past 200 (max seen 658).  200
// covers 99.97% for a worst-case read of pageSize+400 rows -- the bleed is
// fetched and scanned but never enriched, so the cost is a few ms of extra
// SQLite scan.  The residual tail still degrades to the fragment marker the
// UI draws.
const SessionBleed = 200

// FetchPagedWithBleed returns the page window plus SessionBleed rows on each
// side, and reports where the window starts within the returned slice.
//
// The log is ordered newest-first and paginated by ROW, while the hunt UI
// groups rows into sessions -- so a page boundary lands in the middle of a
// session roughly twice per page (measured: 2 of 41 sessions at offset 200),
// and the operator sees a chain with its head or tail missing.  Reading a
// little past both edges lets the UI complete those chains; the caller decides
// which sessions the page owns, so the extra rows never add sessions of their
// own (see the handler).
func FetchPagedWithBleed(ctx context.Context, d *db.DB, ipSubstr, ja4Substr, uaSubstr, ref, phase, forceReason, site string, hosts []string, sinceMin int, limit, offset int) (rows []Row, windowStart int, err error) {
	if limit < 1 || limit > 1000 {
		limit = 100
	}
	if offset < 0 || offset > 100000 {
		offset = 0
	}
	lead := SessionBleed
	if lead > offset {
		lead = offset // first page: nothing newer to read
	}
	rows, err = FetchPaged(ctx, d, ipSubstr, ja4Substr, uaSubstr, ref, phase, forceReason, site,
		hosts, sinceMin, limit+lead+SessionBleed, offset-lead)
	return rows, lead, err
}

// maxFetchRows caps a single FetchPaged read: the largest page (1000) plus a
// full bleed on both sides.  Out-of-range limits CLAMP to the nearest bound --
// resetting to 100 (the old behaviour) silently shrank the n=1000 page the
// moment the bleed pushed the request to 1016 rows.
const maxFetchRows = 1000 + 2*SessionBleed

func FetchPaged(ctx context.Context, d *db.DB, ipSubstr, ja4Substr, uaSubstr, ref, phase, forceReason, site string, hosts []string, sinceMin int, limit, offset int) ([]Row, error) {
	if limit < 1 {
		limit = 100
	}
	if limit > maxFetchRows {
		limit = maxFetchRows
	}
	if offset < 0 || offset > 100000 {
		offset = 0
	}
	stmt := `SELECT id, date_created, site, host, scheme, port, ip_address, user_agent, ja4, ja4_verdict,
	         phase, flags, reload_count, cookie_bv, cookie_br, payload_json
	         FROM unmask_event WHERE 1=1`
	args := []any{}
	// phase accepts a comma-separated list so the UI can offer meaningful
	// groups -- "everything that passed", "everything still in flight" -- which
	// is what an operator actually asks the log, rather than forcing one
	// concrete phase at a time and re-running the query for each.  Unknown
	// names are dropped instead of being passed to SQL: the value reaches here
	// from a query string.
	if phases := parsePhaseList(phase); len(phases) > 0 {
		stmt += " AND phase IN (" + strings.TrimSuffix(strings.Repeat("?,", len(phases)), ",") + ")"
		for _, p := range phases {
			args = append(args, p)
		}
	} else if strings.TrimSpace(phase) != "" {
		// Asked to filter, but nothing in the value is a real phase.  Return
		// nothing rather than everything: a typo must not silently hand back
		// the whole log while the form still shows a filter as applied.
		stmt += " AND 1=0"
	}
	// force_reason: the axis that raised the challenge, matched exactly against
	// payload "force_reason" (header / stale / asn / geo / honeypot / banned /
	// protected / rate_limit / ...).  Lets the hunt filter to "all challenges a
	// given axis forced".
	if forceReason != "" {
		stmt += " AND payload_json LIKE ?"
		args = append(args, `%"force_reason":"`+forceReason+`"%`)
	}
	if ja4Substr != "" {
		stmt += " AND ja4 LIKE ?"
		args = append(args, "%"+ja4Substr+"%")
	}
	// ua: case-insensitive substring over the stored User-Agent -- the hunt box
	// uses it to pull every request carrying a given crawler UA (e.g. the fake
	// "Googlebot" flood, whose source IPs the operator then wants to see).
	// LIKE is ASCII-case-insensitive on both engines here (SQLite default
	// NOCASE-less LIKE folds ASCII; MariaDB LIKE folds by the column collation),
	// which is what a UA search wants.  Same escaping posture as ja4 above --
	// the value rides a ? placeholder, so % / _ only widen the match, never
	// inject; the caller trims and length-caps it.
	if uaSubstr != "" {
		stmt += " AND user_agent LIKE ?"
		args = append(args, "%"+uaSubstr+"%")
	}
	// ref: the support correlation id, matched exactly against the indexed
	// ref_id column (migration 0025).  This used to be a LIKE over
	// payload_json, which read every row in the table -- 53 seconds on a
	// 3.4M-row production database, on the path an operator takes while a
	// blocked visitor is waiting for an answer.
	if ref != "" {
		stmt += " AND ref_id = ?"
		args = append(args, ref)
	}
	// IP is packed binary ([]byte 4 / 16 bytes), so LIKE cannot narrow it.
	// Only exact match is supported (pass a valid IP as ipSubstr).
	if ipSubstr != "" {
		if pkt := PackIP(ipSubstr); pkt != nil {
			stmt += " AND ip_address = ?"
			args = append(args, pkt)
		}
	}
	// An ASN drill-down arrives as the set of addresses that resolved to the
	// network (see WithIPSet).  The event row carries no ASN column -- the
	// network is derived from the mmdb at display time -- so naming the
	// addresses is the only way to express "requests from this network".
	// An empty set means the network had no addresses in the window, which
	// must return nothing rather than everything.
	if set, ok := ipSetFrom(ctx); ok {
		packed := make([]any, 0, len(set))
		for _, ip := range set {
			if p := PackIP(ip); p != nil {
				packed = append(packed, p)
			}
		}
		if len(packed) == 0 {
			stmt += " AND 1=0"
		} else {
			stmt += " AND ip_address IN (" + strings.TrimSuffix(strings.Repeat("?,", len(packed)), ",") + ")"
			args = append(args, packed...)
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
	if wc := dateCreatedWindow(ctx, d, sinceMin); wc != "" {
		stmt += " AND " + wc
	}
	// Hold the result set still while the operator pages through it (see
	// WithHuntFreeze).  Live views leave this unset.
	if maxID := huntFreeze(ctx); maxID > 0 {
		stmt += " AND id <= ?"
		args = append(args, maxID)
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
			id, flags, rcount    int64
			date                 sql.NullTime
			dateStr              sql.NullString
			site_, host_, phase_ string
			scheme_              sql.NullString
			port_                sql.NullInt64
			ipBytes              []byte
			ua, ja4, verdict     sql.NullString
			cBV, cBR, payload    sql.NullString
		)
		if d.Driver == db.DriverSQLite {
			if err := rows.Scan(&id, &dateStr, &site_, &host_, &scheme_, &port_, &ipBytes, &ua, &ja4, &verdict,
				&phase_, &flags, &rcount, &cBV, &cBR, &payload); err != nil {
				return nil, err
			}
		} else {
			if err := rows.Scan(&id, &date, &site_, &host_, &scheme_, &port_, &ipBytes, &ua, &ja4, &verdict,
				&phase_, &flags, &rcount, &cBV, &cBR, &payload); err != nil {
				return nil, err
			}
		}
		dStr, ts, tsMs := normalizeEventTime(date, dateStr)
		row := Row{
			ID: id, Date: dStr, Ts: ts, TsMs: tsMs, Site: site_, Host: host_, Scheme: scheme_.String, Port: int(port_.Int64), IP: unpackIP(ipBytes),
			UA: ua.String, JA4: ja4.String, Verdict: verdict.String,
			Phase: phase_, Flags: int(flags), ReloadCount: int(rcount),
			CookieBV: cBV.String, CookieBR: cBR.String, Payload: payload.String,
		}
		if row.Phase == "check" {
			row.Action = extractAction(payload.String)
			row.RLZone = extractRLZone(payload.String)
			row.LBWarning = extractLBWarning(payload.String)
		}
		decorateRowFromPayload(&row, payload.String)
		out = append(out, row)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	fillAbandonReturned(ctx, d, out)
	return out, nil
}

// fillAbandonReturned answers, for each abandon row on the page, whether that
// client sent anything else in the following 30 seconds.
//
// It is the only way to tell "pressed Back" from "closed the tab": browsers do
// not expose the gesture, and the bfcache hint that hints at it is always false
// for a no-store challenge page.  Going back navigates somewhere and shows up
// as another request; closing shows up as nothing.
//
// One query per abandon row, and only for abandon rows -- a page of the hunt
// log holds a handful at most, so this costs nothing on the common path and
// nothing at all on pages with none.  A failing lookup leaves the field at 0
// rather than failing the page: this is a hint beside the row, not the row.
func fillAbandonReturned(ctx context.Context, d *db.DB, rows []Row) {
	for i := range rows {
		if rows[i].Phase != "abandon" || rows[i].IP == "" {
			continue
		}
		ipb := PackIP(rows[i].IP)
		if ipb == nil {
			continue
		}
		// The window bound is computed here rather than in SQL: SQLite spells
		// it datetime(x,'+30 seconds') and MariaDB DATE_ADD(x, INTERVAL 30
		// SECOND), and a formatted literal needs neither.
		if rows[i].TsMs == 0 {
			continue
		}
		until := time.UnixMilli(rows[i].TsMs).UTC().Add(30 * time.Second).Format(eventTimeFormat)
		var n sql.NullInt64
		err := d.QueryRowContext(ctx, `
            SELECT COUNT(*) FROM unmask_event
            WHERE ip_address = ? AND id <> ?
              AND date_created > ? AND date_created <= ?`,
			ipb, rows[i].ID, rows[i].Date, until).Scan(&n)
		if err != nil {
			continue
		}
		rows[i].Returned = int(n.Int64)
	}
}

// FetchByRef returns events whose payload carries the given correlation ref (the
// id shown on the challenge / deny / ban page).  Backs `unmask events --ref` so
// an operator can tie a blocked visitor's reported id to the exact serve event
// and its decision context (verdict / flags / ip / ja4 / time).  The ref is
// base32 + a dash, so it carries no SQL/LIKE metacharacters and the pattern is
// safe to assemble directly; callers still validate the charset before this.
func FetchByRef(ctx context.Context, d *db.DB, ref string, limit int) ([]Row, error) {
	if limit < 1 || limit > 500 {
		limit = 50
	}
	stmt := `SELECT id, date_created, site, host, scheme, port, ip_address, user_agent, ja4, ja4_verdict,
	         phase, flags, reload_count, cookie_bv, cookie_br, payload_json
	         FROM unmask_event WHERE ref_id = ? ORDER BY id DESC LIMIT ?`
	rows, err := d.QueryContext(ctx, stmt, ref, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return scanEventRows(d, rows)
}

// scanEventRows materializes Rows from a result set selecting the standard event
// column list (the same 16 columns FetchSince / FetchPaged select, in order).
func scanEventRows(d *db.DB, rows *sql.Rows) ([]Row, error) {
	out := make([]Row, 0, 32)
	for rows.Next() {
		var (
			id, flags, rcount    int64
			date                 sql.NullTime
			dateStr              sql.NullString
			site_, host_, phase_ string
			scheme_              sql.NullString
			port_                sql.NullInt64
			ipBytes              []byte
			ua, ja4, verdict     sql.NullString
			cBV, cBR, payload    sql.NullString
		)
		if d.Driver == db.DriverSQLite {
			if err := rows.Scan(&id, &dateStr, &site_, &host_, &scheme_, &port_, &ipBytes, &ua, &ja4, &verdict,
				&phase_, &flags, &rcount, &cBV, &cBR, &payload); err != nil {
				return nil, err
			}
		} else {
			if err := rows.Scan(&id, &date, &site_, &host_, &scheme_, &port_, &ipBytes, &ua, &ja4, &verdict,
				&phase_, &flags, &rcount, &cBV, &cBR, &payload); err != nil {
				return nil, err
			}
		}
		dStr, ts, tsMs := normalizeEventTime(date, dateStr)
		row := Row{
			ID: id, Date: dStr, Ts: ts, TsMs: tsMs, Site: site_, Host: host_, Scheme: scheme_.String, Port: int(port_.Int64), IP: unpackIP(ipBytes),
			UA: ua.String, JA4: ja4.String, Verdict: verdict.String,
			Phase: phase_, Flags: int(flags), ReloadCount: int(rcount),
			CookieBV: cBV.String, CookieBR: cBR.String, Payload: payload.String,
		}
		if row.Phase == "check" {
			row.Action = extractAction(payload.String)
			row.RLZone = extractRLZone(payload.String)
			row.LBWarning = extractLBWarning(payload.String)
		}
		decorateRowFromPayload(&row, payload.String)
		out = append(out, row)
	}
	return out, rows.Err()
}

// RankRow is one row of a ranking aggregate (used by the bot hunt tab for IP/UA/JA4 rankings).
type RankRow struct {
	Key   string // one of IP / UA / JA4
	Count int
}

// OverBlockStats returns the challenge serve volume and the distinct client-IP
// count over the last `minutes`, for the over-block circuit breaker.  A high
// serves/distinctIPs ratio means the same visitors are being re-challenged
// instead of passing -- a challenge loop (the 2026-06-08 tool1-jp incident).
func OverBlockStats(ctx context.Context, d *db.DB, minutes int) (serves, distinctIPs int, err error) {
	stmt := `SELECT COUNT(*), COUNT(DISTINCT ip_address) FROM unmask_event
	         WHERE phase = 'serve' AND date_created > ` + d.NowMinusMinutes(minutes)
	err = d.QueryRowContext(ctx, stmt).Scan(&serves, &distinctIPs)
	return serves, distinctIPs, err
}

// eventDateHint pins an unmask_event query to the date_created index.  It is
// applied only to the GROUP BY ip_address queries: those are the ones SQLite
// otherwise answers by scanning the entire (ip_address, date_created) covering
// index, making them cost O(all events) instead of O(events in the window) --
// and unlike the low-cardinality columns, ANALYZE does not rescue them.  Skipped
// when there is no date window, since INDEXED BY on a query that cannot use the
// index is a SQLite error.  See db.EventDateIndexHint.
func eventDateHint(d *db.DB, window string) string {
	if window == "" {
		return ""
	}
	return d.EventDateIndexHint()
}

// RankByIP aggregates unmask_event from the last sinceMin minutes by IP.  Top limit entries.
func RankByIP(ctx context.Context, d *db.DB, sinceMin, limit int) ([]RankRow, error) {
	if limit < 1 || limit > 200 {
		limit = 30
	}
	win := dateCreatedWindow(ctx, d, sinceMin)
	stmt := `SELECT ip_address, COUNT(*) AS c FROM unmask_event` + eventDateHint(d, win) + `
	         WHERE ` + win + `
	         GROUP BY ip_address ORDER BY c DESC LIMIT ?`
	rows, err := d.QueryContext(ctx, stmt, limit)
	if err != nil && strings.Contains(err.Error(), "idx_unmask_event_date") {
		// INDEXED BY turns a MISSING index into a hard error rather than a slow
		// plan (failed/blocked migrate, hand-rebuilt schema).  Degrade to the
		// unhinted slow-but-correct query instead of an empty hunt ranking.
		rows, err = d.QueryContext(ctx, `SELECT ip_address, COUNT(*) AS c FROM unmask_event
	         WHERE `+win+`
	         GROUP BY ip_address ORDER BY c DESC LIMIT ?`, limit)
	}
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
	         WHERE ` + dateCreatedWindow(ctx, d, sinceMin) + `
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

// SampleIPForJA4 returns the IP that appears the most often with the given
// JA4 fingerprint inside the last sinceMin minutes.  Used by the hunt page
// to surface a representative IP next to each JA4 ranking row so the
// operator can open the IP BAN dialog and report (ip, ja4) to community.
// Returns "" when no IP is found (= the JA4 only appears in events without
// an IP, or no events match).
func SampleIPForJA4(ctx context.Context, d *db.DB, sinceMin int, ja4 string) (string, error) {
	if ja4 == "" {
		return "", nil
	}
	win := dateCreatedWindow(ctx, d, sinceMin)
	stmt := `SELECT ip_address FROM unmask_event` + eventDateHint(d, win) + `
	         WHERE ` + win + `
	           AND COALESCE(ja4, '') = ?
	           AND COALESCE(ip_address, '') <> ''
	         GROUP BY ip_address ORDER BY COUNT(*) DESC LIMIT 1`
	var ip string
	row := d.QueryRowContext(ctx, stmt, ja4)
	err := row.Scan(&ip)
	if err != nil && strings.Contains(err.Error(), "idx_unmask_event_date") {
		// Same missing-index degradation as RankByIP.
		row = d.QueryRowContext(ctx, `SELECT ip_address FROM unmask_event
	         WHERE `+win+`
	           AND COALESCE(ja4, '') = ?
	           AND COALESCE(ip_address, '') <> ''
	         GROUP BY ip_address ORDER BY COUNT(*) DESC LIMIT 1`, ja4)
		err = row.Scan(&ip)
	}
	if err != nil {
		if err == sql.ErrNoRows {
			return "", nil
		}
		return "", err
	}
	return ip, nil
}

// RankByUA aggregates unmask_event from the last sinceMin minutes by UA.
func RankByUA(ctx context.Context, d *db.DB, sinceMin, limit int) ([]RankRow, error) {
	if limit < 1 || limit > 200 {
		limit = 30
	}
	stmt := `SELECT COALESCE(user_agent, ''), COUNT(*) AS c FROM unmask_event
	         WHERE ` + dateCreatedWindow(ctx, d, sinceMin) + `
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

// ASNRankRow: one network in the hunt ASN ranking.
type ASNRankRow struct {
	ASN   uint   // Autonomous System Number (0 = the mmdb had no answer)
	Org   string // ASN organization, as the mmdb spells it
	IPs   int    // distinct client IPs seen from this network in the window
	Count int    // events from this network in the window
}

// RankByASN aggregates the window by client network.  Top `limit` rows, ordered
// by distinct IPs (not events): a botnet spread thin across a network is exactly
// what the IP ranking cannot show, since every one of its addresses sits near
// the bottom with a handful of requests each.  Ordering by distinct IPs puts
// that shape first, which is the reason this ranking exists.
//
// The ASN is not stored on the event -- it is resolved from the IP against the
// mmdb, so the caller injects `resolve` (the handler owns the reader; this
// package must not depend on it).  A nil resolver, or one that answers 0,
// folds into a single "unknown" row rather than vanishing, so the ranking's
// totals stay honest when the mmdb is missing.
//
// Cost: this reads EVERY distinct IP in the window (no LIMIT can be pushed into
// SQL -- the ranking key is computed after the query), so the date-index hint is
// load-bearing.  Measured on a 6.6M-row production DB over 24h / 111k distinct
// IPs: 0.36s with the hint, 48s without it, because the unhinted planner walks
// the whole (ip_address, date_created) index instead of seeking the window.
func RankByASN(ctx context.Context, d *db.DB, sinceMin, limit int, resolve func(ip string) (uint, string)) ([]ASNRankRow, error) {
	if limit < 1 || limit > 200 {
		limit = 30
	}
	win := dateCreatedWindow(ctx, d, sinceMin)
	const cols = `SELECT ip_address, COUNT(*) AS c FROM unmask_event`
	rows, err := d.QueryContext(ctx, cols+eventDateHint(d, win)+` WHERE `+win+` GROUP BY ip_address`)
	if err != nil && strings.Contains(err.Error(), "idx_unmask_event_date") {
		// Same degradation as RankByIP: INDEXED BY makes a missing index a hard
		// error, and a slow ranking beats an empty one.
		rows, err = d.QueryContext(ctx, cols+` WHERE `+win+` GROUP BY ip_address`)
	}
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	type agg struct {
		org   string
		ips   int
		count int
	}
	byASN := map[uint]*agg{}
	for rows.Next() {
		var ipBytes []byte
		var c int
		if err := rows.Scan(&ipBytes, &c); err != nil {
			return nil, err
		}
		var asn uint
		var org string
		if ip := unpackIP(ipBytes); ip != "" && resolve != nil {
			asn, org = resolve(ip)
		}
		a := byASN[asn]
		if a == nil {
			a = &agg{}
			byASN[asn] = a
		}
		// Keep the first non-empty spelling: an mmdb can carry blank org rows
		// for some prefixes of a network that is named on others.
		if a.org == "" {
			a.org = org
		}
		a.ips++
		a.count += c
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}

	out := make([]ASNRankRow, 0, len(byASN))
	for asn, a := range byASN {
		out = append(out, ASNRankRow{ASN: asn, Org: a.org, IPs: a.ips, Count: a.count})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].IPs != out[j].IPs {
			return out[i].IPs > out[j].IPs
		}
		if out[i].Count != out[j].Count {
			return out[i].Count > out[j].Count
		}
		return out[i].ASN < out[j].ASN // stable order for equal rows
	})
	if len(out) > limit {
		out = out[:limit]
	}
	return out, nil
}

// distinctColSQL builds the "distinct non-empty values of an indexed column"
// query used by the host / site pickers on every admin page.
//
// A plain `SELECT DISTINCT <col> ... ORDER BY <col> LIMIT n` scans the ENTIRE
// (<col>, date_created) covering index because SQLite cannot early-terminate a
// DISTINCT — on tool1-us (6.6M rows, ONE distinct host) that measured ~34s cold
// / ~1s warm, paid on every admin page load.  For SQLite we emulate a loose
// index scan with a recursive CTE: each step seeks the next value with
// MIN(<col>) WHERE <col> > prev, i.e. one index seek per DISTINCT value, so the
// cost is O(k·log n) in the number of distinct values, not O(n) rows (measured
// ~4ms).  The recursion yields values ascending, matching the old ORDER BY.
// `<col> > ”` excludes both NULL and ” (empty sorts first).
//
// MariaDB keeps the plain DISTINCT: InnoDB already does a loose index scan for
// DISTINCT on an indexed-prefix column, so the rewrite would add nothing.
//
// col is a fixed internal identifier ("host"/"site"), never user input.
func distinctColSQL(d *db.DB, col string, limit int) string {
	if d.Driver == "sqlite" {
		return fmt.Sprintf(`WITH RECURSIVE d(v) AS (
    SELECT (SELECT MIN(%[1]s) FROM unmask_event WHERE %[1]s > '')
    UNION ALL
    SELECT (SELECT MIN(%[1]s) FROM unmask_event WHERE %[1]s > d.v) FROM d WHERE d.v IS NOT NULL
)
SELECT v FROM d WHERE v IS NOT NULL LIMIT %[2]d`, col, limit)
	}
	return fmt.Sprintf(
		`SELECT DISTINCT %[1]s FROM unmask_event WHERE %[1]s IS NOT NULL AND %[1]s != '' ORDER BY %[1]s LIMIT %[2]d`,
		col, limit)
}

// DistinctSites lists the distinct site values observed in unmask_event.
// Used by site dropdown / datalist suggestions.  Capped at 100 entries.
func DistinctSites(ctx context.Context, d *db.DB) ([]string, error) {
	rows, err := d.QueryContext(ctx, distinctColSQL(d, "site", 100))
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
	rows, err := d.QueryContext(ctx, distinctColSQL(d, "host", 200))
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

type ipSetKey struct{}

// WithIPSet narrows a fetch to an explicit set of addresses.
//
// The hunt page's other rankings filter on a column the event actually carries
// (ip / ja4 / user_agent).  A network does not exist on the row -- it is
// resolved from the mmdb when the page renders -- so the only way to ask the
// log for "requests from this network" is to work out which addresses those
// are and name them.  IPsInASN produces that set.
func WithIPSet(ctx context.Context, ips []string) context.Context {
	return context.WithValue(ctx, ipSetKey{}, ips)
}

func ipSetFrom(ctx context.Context) ([]string, bool) {
	v, ok := ctx.Value(ipSetKey{}).([]string)
	return v, ok
}

// MaxASNDrillIPs caps how many addresses an ASN drill-down will name.  A
// hosting AS can contribute tens of thousands in a wide window, and every one
// becomes a bound parameter.  IPsInASN reports the true count alongside the
// capped set so the caller can say the view is partial rather than present a
// truncated answer as the whole one.
const MaxASNDrillIPs = 5000

// IPsInASN: the distinct addresses seen in the window that resolve to asn,
// most-active first, plus how many there were in total.
//
// Same scan as RankByASN -- every distinct address in the window, resolved
// through the mmdb -- so it carries the same cost and the same index pin.
func IPsInASN(ctx context.Context, d *db.DB, sinceMin int, asn uint, resolve func(ip string) (uint, string)) (ips []string, total int, err error) {
	if d == nil || resolve == nil {
		return nil, 0, nil
	}
	win := dateCreatedWindow(ctx, d, sinceMin)
	const cols = `SELECT ip_address, COUNT(*) AS c FROM unmask_event`
	rows, err := d.QueryContext(ctx, cols+eventDateHint(d, win)+` WHERE `+win+` GROUP BY ip_address ORDER BY c DESC`)
	if err != nil && strings.Contains(err.Error(), "idx_unmask_event_date") {
		rows, err = d.QueryContext(ctx, cols+` WHERE `+win+` GROUP BY ip_address ORDER BY c DESC`)
	}
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	for rows.Next() {
		var ipBytes []byte
		var c int
		if err := rows.Scan(&ipBytes, &c); err != nil {
			return nil, 0, err
		}
		ip := unpackIP(ipBytes)
		if ip == "" {
			continue
		}
		got, _ := resolve(ip)
		if got != asn {
			continue
		}
		total++
		if len(ips) < MaxASNDrillIPs {
			ips = append(ips, ip)
		}
	}
	return ips, total, rows.Err()
}
