// /unmask/metrics — Prometheus text format exporter (pure stdlib, no client_golang).
//
// Emitted metrics:
//
//	unmask_db_up                                   1 when the daemon has its database, 0 while it runs without one (gauge)
//	unmask_event_total{phase=...,verdict=...}      event rows this daemon has written since it started (counter)
//	unmask_event_unique_ip                         distinct addresses behind the last 24 hours of events (gauge)
//	unmask_verify_score_bucket{le=...} / _sum / _count   behavioral score distribution (histogram)
//	unmask_captcha_math_no_input_total             correct math answers with no input events (counter)
//	unmask_schema_update_pending / _running        schema updates left for the operator (gauges)
//	unmask_native_failsafe_active                  1 while the plugin's fail-safe has the module stripped (gauge)
//	unmask_nginx_config_stale                      1 while a render waits for its reload (gauge)
//	unmask_ban_file_worker_readable                0 when nginx's worker cannot read the ban list (gauge)
//	unmask_nginxlog_dropped_total                  access-log lines dropped at a full receiver queue (counter)
//	unmask_events_bad_rows_total                   event rows dropped because the database refused their data (counter)
//	unmask_events_dropped_total                    events dropped by the batch writer's backlog cap (counter)
//	unmask_db_query_seconds_sum / _count{op=...}   time spent in the exporter's own database reads (summary)
//
// A scrape reads memory and a few files, and the database once a minute at
// most (the unique-address sketches).  The event counter in particular is
// counted where the rows are written (events.WrittenCounts) and never read
// back from the table: it used to be a GROUP BY over the last 24 hours of
// unmask_event, which is not a counter -- it fell whenever a row left the
// window -- and was a scan of a day of events on every cache miss.
//
// Why no client_golang: avoid adding a dependency.  Counter and histogram are
// implementable with stdlib + sync/atomic, and the text format is simple.
package handlers

import (
	"context"
	"fmt"
	"net/http"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/unmask-sh/unmask/admin/internal/dashboard"
	"github.com/unmask-sh/unmask/admin/internal/db"
	"github.com/unmask-sh/unmask/admin/internal/events"
	"github.com/unmask-sh/unmask/admin/internal/nginxconf"
	"github.com/unmask-sh/unmask/admin/internal/settings"
)

// scoreBuckets: histogram bucket boundaries for behavioral score observations.
var scoreBuckets = []float64{0.1, 0.2, 0.3, 0.4, 0.5, 0.6, 0.7, 0.8, 0.9, 1.0}

type metricsState struct {
	scoreCount uint64
	scoreSum   uint64   // microsecond-style fixed-point: x1000
	scoreBkt   []uint64 // len = len(scoreBuckets)+1 (last = +Inf)
	// mathNoInput: correct math answers that arrived with zero input events on
	// the answer field -- answered programmatically.  Those passes are issued
	// at proof-of-work grade instead of CAPTCHA grade; this counts how often
	// that happens, which is also how an operator sees automated traffic
	// leaning on the accessibility fallback.
	mathNoInput uint64
	qLat        sync.Map // op string -> *latencyAcc

	// uniq: the last reading of the 24-hour unique addresses (uniqueIPs),
	// when it was taken, and the database it was taken from.
	uniqMu  sync.Mutex
	uniq    int
	uniqAt  time.Time
	uniqFor *db.DB
}

type latencyAcc struct {
	count uint64
	sum   uint64 // nanoseconds total
}

var Metrics = &metricsState{
	scoreBkt: make([]uint64, len(scoreBuckets)+1),
}

// CountMathNoInputEvidence: called when a correct math answer arrived with no
// input events behind it (see the downgrade in VerifyJSON).
func (m *metricsState) CountMathNoInputEvidence() {
	atomic.AddUint64(&m.mathNoInput, 1)
}

// ObserveScore: called each time /api/verify computes a score.
func (m *metricsState) ObserveScore(score float64) {
	atomic.AddUint64(&m.scoreCount, 1)
	atomic.AddUint64(&m.scoreSum, uint64(score*1000))
	for i, b := range scoreBuckets {
		if score <= b {
			atomic.AddUint64(&m.scoreBkt[i], 1)
			return
		}
	}
	atomic.AddUint64(&m.scoreBkt[len(scoreBuckets)], 1)
}

// ObserveQuery: DB query latency.
func (m *metricsState) ObserveQuery(op string, d time.Duration) {
	v, _ := m.qLat.LoadOrStore(op, &latencyAcc{})
	acc := v.(*latencyAcc)
	atomic.AddUint64(&acc.count, 1)
	atomic.AddUint64(&acc.sum, uint64(d.Nanoseconds()))
}

// promLabelEscaper escapes a label value for the text exposition format,
// which knows three escapes and no others: backslash, double quote, line
// feed.  (Go's %q writes a tab as \t and a control byte as \x01, and a
// scraper refuses the whole exposition for either.)
var promLabelEscaper = strings.NewReplacer(`\`, `\\`, `"`, `\"`, "\n", `\n`)

// promLabel is s as a label value, between its quotes.
func promLabel(s string) string {
	return promLabelEscaper.Replace(strings.ToValidUTF8(s, "\uFFFD"))
}

// Metrics: GET {base}/metrics
func (h *Handler) Metrics(w http.ResponseWriter, r *http.Request) {
	// /metrics is registered with no middleware and the rendered nginx proxies
	// all of /unmask/ to the admin with no allow/deny, so without an app-layer
	// gate any internet client could read traffic/verdict stats.  Default to
	// loopback-only; metrics_allow_from widens it.  The address is resolved
	// the way the admin gate resolves it (adminClientIP): the forwarded
	// headers count only off a trusted proxy, so a client that reaches the
	// daemon directly cannot name a loopback address in X-Real-IP and read.
	allow := settings.EnabledValues(h.cfg().Nginx.MetricsAllowFrom, h.cfg().Nginx.MetricsAllowFromDisabled)
	if len(allow) == 0 {
		allow = []string{"127.0.0.0/8", "::1/128"}
	}
	if !ipAllowed(adminClientIP(r, *h.cfg()), allow) {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	// A daemon that runs without its database (a start that could not open
	// it; db_wait.go) still answers the scrape: what it reads from memory and
	// from disk is exported, what it would read from the database is left
	// out, and unmask_db_up says which of the two this is.  The handler used
	// to dereference the nil handle, so the one state an alert most wants to
	// see was a failed scrape.
	hasDB := h.DB != nil

	w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")

	fmt.Fprintln(w, "# HELP unmask_db_up 1 when the daemon has its database; 0 while it runs without one (the start could not open it: challenge pages are served, a set-up install retries by itself, and readyz answers 503)")
	fmt.Fprintln(w, "# TYPE unmask_db_up gauge")
	fmt.Fprintf(w, "unmask_db_up %d\n", gaugeBit(hasDB))

	// The rows written, from the writer's own count (events/written.go): it
	// starts at zero with the daemon and only goes up, which is what rate()
	// and increase() need of a counter.  Each daemon counts what it wrote
	// itself, also where several share one database.
	fmt.Fprintln(w, "# HELP unmask_event_total event rows this daemon has written to the database since it started, by phase and verdict")
	fmt.Fprintln(w, "# TYPE unmask_event_total counter")
	for _, c := range events.WrittenCounts() {
		fmt.Fprintf(w, "unmask_event_total{phase=\"%s\",verdict=\"%s\"} %d\n",
			promLabel(c.Phase), promLabel(c.Verdict), c.N)
	}

	// The unique addresses of the last 24 hours, when the rollup can say:
	// no sample, rather than a 0 that reads as "nobody came", while it
	// cannot.
	if n, ok := Metrics.uniqueIPs(r.Context(), h.DB); ok {
		fmt.Fprintln(w, "# HELP unmask_event_unique_ip distinct source addresses behind the events of the last 24 hours (an estimate from the hourly rollup of the database, so the same on every daemon sharing it)")
		fmt.Fprintln(w, "# TYPE unmask_event_unique_ip gauge")
		fmt.Fprintf(w, "unmask_event_unique_ip %d\n", n)
	}

	// score histogram
	count := atomic.LoadUint64(&Metrics.scoreCount)
	sum := atomic.LoadUint64(&Metrics.scoreSum)
	fmt.Fprintln(w, "# HELP unmask_verify_score Behavioral score distribution from /api/verify")
	fmt.Fprintln(w, "# TYPE unmask_verify_score histogram")
	cum := uint64(0)
	for i, b := range scoreBuckets {
		cum += atomic.LoadUint64(&Metrics.scoreBkt[i])
		fmt.Fprintf(w, "unmask_verify_score_bucket{le=\"%g\"} %d\n", b, cum)
	}
	cum += atomic.LoadUint64(&Metrics.scoreBkt[len(scoreBuckets)])
	fmt.Fprintf(w, "unmask_verify_score_bucket{le=\"+Inf\"} %d\n", cum)
	fmt.Fprintf(w, "unmask_verify_score_sum %g\n", float64(sum)/1000)
	fmt.Fprintf(w, "unmask_verify_score_count %d\n", count)

	fmt.Fprintln(w, "# HELP unmask_captcha_math_no_input_total Correct math answers with no input events (answered programmatically; passed at proof-of-work grade)")
	fmt.Fprintln(w, "# TYPE unmask_captcha_math_no_input_total counter")
	fmt.Fprintf(w, "unmask_captcha_math_no_input_total %d\n", atomic.LoadUint64(&Metrics.mathNoInput))

	// Schema updates left for the operator.  Not without a database: nothing
	// has looked at its schema, and a 0 would say that something had.
	if hasDB {
		waiting, running := h.SchemaWaiting()
		fmt.Fprintln(w, "# HELP unmask_schema_update_pending Schema updates waiting for the operator (applied from the admin UI or with `unmask migrate`)")
		fmt.Fprintln(w, "# TYPE unmask_schema_update_pending gauge")
		fmt.Fprintf(w, "unmask_schema_update_pending %d\n", waiting)
		fmt.Fprintln(w, "# HELP unmask_schema_update_running 1 while a schema update is being applied")
		fmt.Fprintln(w, "# TYPE unmask_schema_update_running gauge")
		fmt.Fprintf(w, "unmask_schema_update_running %d\n", gaugeBit(running))
	}

	// The nginx side, for an alert rule: the plugin's fail-safe (the module
	// stripped and the configuration rendered without it: protection off),
	// a render nginx has not loaded, and a ban list nginx's worker cannot
	// read.  All three are read from disk on each scrape -- a stat each.
	dir := h.renderOutDir()
	fmt.Fprintln(w, "# HELP unmask_native_failsafe_active 1 while the plugin's fail-safe has the nginx module stripped and the configuration rendered without it (protection off; see `unmask doctor`)")
	fmt.Fprintln(w, "# TYPE unmask_native_failsafe_active gauge")
	fmt.Fprintf(w, "unmask_native_failsafe_active %d\n", gaugeBit(nginxconf.FailsafeActive(dir)))
	_, stale := nginxconf.ReloadNeeded(dir)
	fmt.Fprintln(w, "# HELP unmask_nginx_config_stale 1 while a rendered nginx configuration waits for a reload (cleared once the access log shows nginx running it)")
	fmt.Fprintln(w, "# TYPE unmask_nginx_config_stale gauge")
	fmt.Fprintf(w, "unmask_nginx_config_stale %d\n", gaugeBit(stale))
	fmt.Fprintln(w, "# HELP unmask_ban_file_worker_readable 0 when nginx's worker cannot read the ban list the daemon writes (nginx then enforces no ban); 1 otherwise, including when there is no list to read")
	fmt.Fprintln(w, "# TYPE unmask_ban_file_worker_readable gauge")
	fmt.Fprintf(w, "unmask_ban_file_worker_readable %d\n", gaugeBit(h.banFileNotice() == nil))

	// What the ingest let go, since the daemon started: lines the access-log
	// receiver dropped at a full queue (nginx then counts them as sent), event
	// rows a batch write dropped because the database refused their data, and
	// events the batch writer's backlog cap dropped.
	fmt.Fprintln(w, "# HELP unmask_nginxlog_dropped_total access-log lines the receiver dropped at a full queue since the daemon started")
	fmt.Fprintln(w, "# TYPE unmask_nginxlog_dropped_total counter")
	fmt.Fprintf(w, "unmask_nginxlog_dropped_total %d\n", h.NginxLog.DroppedLines())
	fmt.Fprintln(w, "# HELP unmask_events_bad_rows_total event rows a batch write dropped because the database refused their data, since the daemon started")
	fmt.Fprintln(w, "# TYPE unmask_events_bad_rows_total counter")
	fmt.Fprintf(w, "unmask_events_bad_rows_total %d\n", events.GlobalFlusherDroppedBadRows())
	fmt.Fprintln(w, "# HELP unmask_events_dropped_total events the batch writer dropped at its backlog cap since the daemon started")
	fmt.Fprintln(w, "# TYPE unmask_events_dropped_total counter")
	fmt.Fprintf(w, "unmask_events_dropped_total %d\n", events.GlobalFlusherDropped())

	// The exporter's own database reads: a sum and a count per op, which is
	// a summary (without quantiles) and was declared a counter, a type whose
	// samples carry the family's own name.
	fmt.Fprintln(w, "# HELP unmask_db_query_seconds time spent in the exporter's own database reads, per op (sum and count; no quantiles)")
	fmt.Fprintln(w, "# TYPE unmask_db_query_seconds summary")
	type opPair struct {
		op    string
		count uint64
		sum   uint64
	}
	var ops []opPair
	Metrics.qLat.Range(func(k, v any) bool {
		acc := v.(*latencyAcc)
		ops = append(ops, opPair{
			op:    k.(string),
			count: atomic.LoadUint64(&acc.count),
			sum:   atomic.LoadUint64(&acc.sum),
		})
		return true
	})
	sort.Slice(ops, func(i, j int) bool { return ops[i].op < ops[j].op })
	for _, op := range ops {
		fmt.Fprintf(w, "unmask_db_query_seconds_sum{op=\"%s\"} %g\n", promLabel(op.op), float64(op.sum)/1e9)
		fmt.Fprintf(w, "unmask_db_query_seconds_count{op=\"%s\"} %d\n", promLabel(op.op), op.count)
	}
}

const (
	// uniqueIPHours is the window of unmask_event_unique_ip.
	uniqueIPHours = 24
	// uniqueIPKeep is how long one reading of it stands: the rollup it is
	// read from is folded once a minute, so a scrape that comes sooner would
	// read the same sketches again.
	uniqueIPKeep = time.Minute
	// uniqueIPBudget bounds the read; a scrape is not kept waiting on a
	// database that is busy.
	uniqueIPBudget = 3 * time.Second
)

// uniqueIPs is the distinct addresses behind the last 24 hours of events,
// from the hourly rollup's sketches (dashboard.EventDistinctIPs), read at
// most once per uniqueIPKeep.  ok is false when there is nothing to export:
// no database, a rollup that has not completed a pass yet, or a read that
// failed or ran out of its budget.  A failure is not kept -- the next scrape
// asks again -- and is never turned into a 0: the reading used to be a
// COUNT(DISTINCT) over a day of raw events whose error was dropped, and the
// zero it left behind was cached and exported as the answer.
func (m *metricsState) uniqueIPs(ctx context.Context, d *db.DB) (n int, ok bool) {
	if d == nil {
		return 0, false
	}
	m.uniqMu.Lock()
	defer m.uniqMu.Unlock()
	if m.uniqFor == d && time.Since(m.uniqAt) < uniqueIPKeep {
		return m.uniq, true
	}
	rctx, cancel := context.WithTimeout(ctx, uniqueIPBudget)
	defer cancel()
	t0 := time.Now()
	n, ok = dashboard.EventDistinctIPs(rctx, d, uniqueIPHours)
	if !ok {
		return 0, false
	}
	m.ObserveQuery("metrics_unique_ip", time.Since(t0))
	m.uniq, m.uniqAt, m.uniqFor = n, time.Now(), d
	return n, true
}

// gaugeBit is a state as a gauge reads it.
func gaugeBit(on bool) int {
	if on {
		return 1
	}
	return 0
}
