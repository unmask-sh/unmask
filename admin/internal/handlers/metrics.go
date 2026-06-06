// /unmask/metrics — Prometheus text format exporter (pure stdlib, no client_golang).
//
// Emitted metrics:
//
//	unmask_event_total{phase=...,verdict=...}      counter
//	unmask_verify_score_count                      score histogram (count)
//	unmask_verify_score_sum                        score histogram (sum)
//	unmask_verify_score_bucket{le=...}             score histogram (bucket)
//	unmask_db_query_seconds{op=...} (sum/count)    DB query latency (Counter pair)
//
// challenge phases are counted by events.Insert on each admin request, so the
// /metrics handler reads them by GROUP BY directly from the DB on invocation
// (= cached for 30 seconds).
//
// Why no client_golang: avoid adding a dependency.  Counter and histogram are
// implementable with stdlib + sync/atomic, and the text format is simple.
package handlers

import (
	"context"
	"fmt"
	"net/http"
	"sort"
	"sync"
	"sync/atomic"
	"time"
)

// scoreBuckets: histogram bucket boundaries for behavioral score observations.
var scoreBuckets = []float64{0.1, 0.2, 0.3, 0.4, 0.5, 0.6, 0.7, 0.8, 0.9, 1.0}

type metricsState struct {
	scoreCount uint64
	scoreSum   uint64   // microsecond-style fixed-point: x1000
	scoreBkt   []uint64 // len = len(scoreBuckets)+1 (last = +Inf)
	qLat       sync.Map // op string -> *latencyAcc

	cache      *metricsSnapshot
	cacheUntil time.Time
	cacheMu    sync.Mutex
}

type latencyAcc struct {
	count uint64
	sum   uint64 // nanoseconds total
}

var Metrics = &metricsState{
	scoreBkt: make([]uint64, len(scoreBuckets)+1),
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

type phaseRow struct {
	Phase   string
	Verdict string
	Count   uint64
}

type metricsSnapshot struct {
	phaseRows []phaseRow
	totalRows uint64
	uniqueIPs uint64
}

// Metrics: GET {base}/metrics
func (h *Handler) Metrics(w http.ResponseWriter, r *http.Request) {
	// /metrics is registered with no middleware and the rendered nginx proxies
	// all of /unmask/ to the admin with no allow/deny, so without an app-layer
	// gate any internet client could read traffic/verdict stats.  Default to
	// loopback-only; metrics_allow_from widens it.
	allow := h.Settings.Nginx.MetricsAllowFrom
	if len(allow) == 0 {
		allow = []string{"127.0.0.0/8", "::1/128"}
	}
	if !ipAllowed(clientIP(r), allow) {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	snap := Metrics.snapshot(r.Context(), h)

	w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")

	// unmask_event_total
	fmt.Fprintln(w, "# HELP unmask_event_total Total events recorded by phase and verdict")
	fmt.Fprintln(w, "# TYPE unmask_event_total counter")
	for _, r := range snap.phaseRows {
		fmt.Fprintf(w, "unmask_event_total{phase=%q,verdict=%q} %d\n",
			r.Phase, r.Verdict, r.Count)
	}

	fmt.Fprintln(w, "# HELP unmask_event_unique_ip Unique source IPs that hit any phase in last 24h")
	fmt.Fprintln(w, "# TYPE unmask_event_unique_ip gauge")
	fmt.Fprintf(w, "unmask_event_unique_ip %d\n", snap.uniqueIPs)

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

	// DB latency
	fmt.Fprintln(w, "# HELP unmask_db_query_seconds DB query latency (sum & count, per op)")
	fmt.Fprintln(w, "# TYPE unmask_db_query_seconds counter")
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
		fmt.Fprintf(w, "unmask_db_query_seconds_count{op=%q} %d\n", op.op, op.count)
		fmt.Fprintf(w, "unmask_db_query_seconds_sum{op=%q} %g\n", op.op, float64(op.sum)/1e9)
	}
}

// snapshot reads aggregate counters from the DB.  Cached for 30 seconds to
// avoid hammering DB on prometheus scrape (= default 15s scrape * 1 instance).
func (m *metricsState) snapshot(ctx context.Context, h *Handler) *metricsSnapshot {
	m.cacheMu.Lock()
	defer m.cacheMu.Unlock()
	if m.cache != nil && time.Now().Before(m.cacheUntil) {
		return m.cache
	}

	snap := &metricsSnapshot{}
	t0 := time.Now()
	stmt := fmt.Sprintf(`
        SELECT phase, COALESCE(ja4_verdict, '(none)') AS v, COUNT(*) FROM unmask_event
        WHERE date_created > %s
        GROUP BY phase, ja4_verdict`, h.DB.NowMinusMinutes(24*60))
	rows, err := h.DB.QueryContext(ctx, stmt)
	if err == nil {
		defer rows.Close()
		for rows.Next() {
			var pr phaseRow
			if err := rows.Scan(&pr.Phase, &pr.Verdict, &pr.Count); err != nil {
				continue
			}
			snap.phaseRows = append(snap.phaseRows, pr)
			snap.totalRows += pr.Count
		}
	}
	m.ObserveQuery("metrics_phase_group", time.Since(t0))

	t0 = time.Now()
	row := h.DB.QueryRowContext(ctx, fmt.Sprintf(
		`SELECT COUNT(DISTINCT ip_address) FROM unmask_event WHERE date_created > %s`,
		h.DB.NowMinusMinutes(24*60)))
	_ = row.Scan(&snap.uniqueIPs)
	m.ObserveQuery("metrics_unique_ip", time.Since(t0))

	m.cache = snap
	m.cacheUntil = time.Now().Add(30 * time.Second)
	return snap
}
