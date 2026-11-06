package handlers

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/unmask-sh/unmask/admin/internal/dashboard"
	"github.com/unmask-sh/unmask/admin/internal/events"
)

// promFamily is one metric family of a scrape as the text format declares
// it.
type promFamily struct {
	typ     string
	help    int
	types   int
	samples []promSample
}

type promSample struct {
	name   string // as written: the family's name, or with a suffix
	labels map[string]string
	value  string
}

// parseExposition reads a scrape the way a scraper does, strictly: every
// sample must follow its family's TYPE line and sit in that family's one
// block, and a label value may use the format's three escapes and no other.
// It returns the families by name and fails the test on anything a scraper
// would refuse.
func parseExposition(t *testing.T, body string) map[string]*promFamily {
	t.Helper()
	fams := map[string]*promFamily{}
	closed := map[string]bool{} // families whose block has ended
	current := ""
	open := func(name string) *promFamily {
		if closed[name] {
			t.Fatalf("family %s has lines in two places", name)
		}
		if current != "" && current != name {
			closed[current] = true
		}
		current = name
		if fams[name] == nil {
			fams[name] = &promFamily{}
		}
		return fams[name]
	}
	for n, line := range strings.Split(strings.TrimRight(body, "\n"), "\n") {
		switch {
		case strings.HasPrefix(line, "# HELP "):
			f := strings.SplitN(strings.TrimPrefix(line, "# HELP "), " ", 2)
			if len(f) != 2 || f[1] == "" {
				t.Fatalf("line %d: a HELP with no text: %q", n+1, line)
			}
			open(f[0]).help++
		case strings.HasPrefix(line, "# TYPE "):
			f := strings.Fields(strings.TrimPrefix(line, "# TYPE "))
			if len(f) != 2 {
				t.Fatalf("line %d: malformed TYPE: %q", n+1, line)
			}
			fam := open(f[0])
			if len(fam.samples) > 0 {
				t.Fatalf("line %d: TYPE of %s after its samples", n+1, f[0])
			}
			fam.types++
			fam.typ = f[1]
		case line == "" || strings.HasPrefix(line, "#"):
			t.Fatalf("line %d: unexpected %q", n+1, line)
		default:
			s := parsePromSample(t, n+1, line)
			owner := ""
			for name, fam := range fams {
				if promSampleBelongs(s.name, name, fam.typ) && len(name) > len(owner) {
					owner = name
				}
			}
			if owner == "" {
				t.Fatalf("line %d: sample %s belongs to no declared family", n+1, s.name)
			}
			fam := open(owner)
			fam.samples = append(fam.samples, s)
		}
	}
	return fams
}

// promSampleBelongs: whether a sample named sample may appear in a family
// of this name and type.
func promSampleBelongs(sample, family, typ string) bool {
	switch typ {
	case "counter", "gauge":
		return sample == family
	case "histogram":
		return sample == family+"_bucket" || sample == family+"_sum" || sample == family+"_count"
	case "summary":
		return sample == family || sample == family+"_sum" || sample == family+"_count"
	}
	return false
}

func parsePromSample(t *testing.T, n int, line string) promSample {
	t.Helper()
	s := promSample{labels: map[string]string{}}
	rest := line
	if i := strings.IndexAny(rest, "{ "); i < 0 {
		t.Fatalf("line %d: no value: %q", n, line)
	} else {
		s.name, rest = rest[:i], rest[i:]
	}
	if strings.HasPrefix(rest, "{") {
		rest = rest[1:]
		for !strings.HasPrefix(rest, "}") {
			eq := strings.Index(rest, `="`)
			if eq < 0 {
				t.Fatalf("line %d: malformed labels: %q", n, line)
			}
			key := rest[:eq]
			rest = rest[eq+2:]
			var val strings.Builder
			for {
				if rest == "" {
					t.Fatalf("line %d: unterminated label value: %q", n, line)
				}
				c := rest[0]
				rest = rest[1:]
				if c == '"' {
					break
				}
				if c != '\\' {
					val.WriteByte(c)
					continue
				}
				if rest == "" {
					t.Fatalf("line %d: dangling backslash: %q", n, line)
				}
				switch rest[0] {
				case '\\':
					val.WriteByte('\\')
				case '"':
					val.WriteByte('"')
				case 'n':
					val.WriteByte('\n')
				default:
					t.Fatalf("line %d: escape \\%c is not one the text format has: %q", n, rest[0], line)
				}
				rest = rest[1:]
			}
			s.labels[key] = val.String()
			rest = strings.TrimPrefix(rest, ",")
		}
		rest = rest[1:]
	}
	s.value = strings.TrimSpace(rest)
	if s.value == "" || strings.ContainsAny(s.value, " \t") {
		t.Fatalf("line %d: malformed value: %q", n, line)
	}
	return s
}

// What /metrics writes is what a scraper accepts, family by family: one HELP
// and one TYPE each, every sample under a family of the right type and name
// -- a counter's and a gauge's samples carry the family's own name, a
// histogram's and a summary's their suffixes -- and each family in one
// block.  unmask_db_query_seconds was declared a counter while its samples
// were _sum and _count, which belong to no counter.
func TestMetricsExpositionIsWellFormed(t *testing.T) {
	h := newTestHandler(t)
	// Something in every family that has labels: a row written (with a
	// verdict a careless escaper would break on), a score, a timed read.
	awkward := "quote\" back\\slash\ttab"
	if err := events.Insert(context.Background(), h.DB, &events.Event{
		IPPacked: events.PackIP("192.0.2.9"), Phase: "serve", JA4Verdict: awkward,
	}); err != nil {
		t.Fatal(err)
	}
	Metrics.ObserveScore(0.42)
	Metrics.ObserveQuery("exposition_test", 3*time.Millisecond)

	code, body := scrapeMetrics(h)
	if code != 200 {
		t.Fatalf("scrape: %d", code)
	}
	fams := parseExposition(t, body)

	want := map[string]string{
		"unmask_db_up":                       "gauge",
		"unmask_event_total":                 "counter",
		"unmask_verify_score":                "histogram",
		"unmask_captcha_math_no_input_total": "counter",
		"unmask_schema_update_pending":       "gauge",
		"unmask_schema_update_running":       "gauge",
		"unmask_native_failsafe_active":      "gauge",
		"unmask_nginx_config_stale":          "gauge",
		"unmask_ban_file_worker_readable":    "gauge",
		"unmask_nginxlog_dropped_total":      "counter",
		"unmask_events_bad_rows_total":       "counter",
		"unmask_events_dropped_total":        "counter",
		"unmask_db_query_seconds":            "summary",
	}
	for name, typ := range want {
		fam := fams[name]
		if fam == nil {
			t.Errorf("family %s is missing", name)
			continue
		}
		if fam.typ != typ {
			t.Errorf("%s is declared a %s, want %s", name, fam.typ, typ)
		}
	}
	for name, fam := range fams {
		if fam.help != 1 || fam.types != 1 {
			t.Errorf("%s has %d HELP and %d TYPE lines, want one of each", name, fam.help, fam.types)
		}
		if _, known := want[name]; !known && name != "unmask_event_unique_ip" {
			t.Errorf("family %s is exported but not listed here: add it with its type", name)
		}
		if fam.typ == "counter" && !strings.HasSuffix(name, "_total") {
			t.Errorf("counter %s does not end in _total", name)
		}
	}

	// The awkward verdict comes back out of its quotes as it went in.
	found := false
	for _, s := range fams["unmask_event_total"].samples {
		if s.labels["phase"] == "serve" && s.labels["verdict"] == awkward {
			found = true
		}
	}
	if !found {
		t.Errorf("the row's verdict %q did not survive the label escaping", awkward)
	}
	// The summary carries a sum and a count for the op, and nothing else.
	var sum, count bool
	for _, s := range fams["unmask_db_query_seconds"].samples {
		if s.labels["op"] != "exposition_test" {
			continue
		}
		sum = sum || s.name == "unmask_db_query_seconds_sum"
		count = count || s.name == "unmask_db_query_seconds_count"
	}
	if !sum || !count {
		t.Errorf("the timed read has sum=%v count=%v, want both", sum, count)
	}
}

// eventTotal reads one series of unmask_event_total off a scrape; -1 when it
// is not there.
func eventTotal(t *testing.T, h *Handler, phase, verdict string) int {
	t.Helper()
	_, body := scrapeMetrics(h)
	for _, s := range parseExposition(t, body)["unmask_event_total"].samples {
		if s.labels["phase"] == phase && s.labels["verdict"] == verdict {
			var n int
			if _, err := fmt.Sscanf(s.value, "%d", &n); err != nil {
				t.Fatalf("unmask_event_total value %q", s.value)
			}
			return n
		}
	}
	return -1
}

// unmask_event_total is a counter: it counts the rows this daemon wrote and
// does not come down.  It used to be the last 24 hours of the table, grouped
// on each scrape, so it fell as rows left the window -- which increase() and
// rate() read as a reset, adding the whole value back -- and it read a day
// of events from the database to do so.  Here the rows are deleted (as the
// retention prune deletes them) and then the table itself is dropped: the
// value stands both times, because no scrape reads the table.
func TestMetricsEventTotalDoesNotFollowTheTable(t *testing.T) {
	h := newTestHandler(t)
	ctx := context.Background()
	const verdict = "counter_not_window"
	for i := 0; i < 4; i++ {
		if err := events.Insert(ctx, h.DB, &events.Event{
			IPPacked: events.PackIP("192.0.2.20"), Phase: "serve", JA4Verdict: verdict,
		}); err != nil {
			t.Fatal(err)
		}
	}
	if got := eventTotal(t, h, "serve", verdict); got != 4 {
		t.Fatalf("after four rows: %d, want 4", got)
	}
	if _, err := h.DB.Exec(`DELETE FROM unmask_event`); err != nil {
		t.Fatal(err)
	}
	if got := eventTotal(t, h, "serve", verdict); got != 4 {
		t.Errorf("after the rows left the table: %d, want it to stay 4", got)
	}
	if _, err := h.DB.Exec(`DROP TABLE unmask_event`); err != nil {
		t.Fatal(err)
	}
	if code, _ := scrapeMetrics(h); code != 200 {
		t.Fatalf("scrape with no event table: %d", code)
	}
	if got := eventTotal(t, h, "serve", verdict); got != 4 {
		t.Errorf("with no event table to read: %d, want 4", got)
	}
	// A daemon with no database at all exports the same count.
	if got := eventTotal(t, &Handler{}, "serve", verdict); got != 4 {
		t.Errorf("on a daemon without a database: %d, want 4", got)
	}
}

// unmask_event_unique_ip is exported when the rollup can answer and left out
// when it cannot -- never a 0 standing in for "could not read".
func TestMetricsUniqueIPIsAbsentUntilTheRollupAnswers(t *testing.T) {
	h := newTestHandler(t)
	dashboard.ResetHourlyAggReadyForTest()
	t.Cleanup(dashboard.ResetHourlyAggReadyForTest)
	if _, body := scrapeMetrics(h); strings.Contains(body, "unmask_event_unique_ip") {
		t.Errorf("exported before the rollup completed a pass:\n%s", body)
	}
}

// And when the rollup answers, the gauge is its figure: the distinct
// addresses of the window's events, read from the sketches -- once a minute
// at most, and per database, so one daemon's reading is never another's.
func TestMetricsUniqueIPComesFromTheRollup(t *testing.T) {
	h, _ := reconfHandler(t, false) // a migrated database: the rollup's tables are there
	ctx := context.Background()
	add := func(n, from int) {
		t.Helper()
		for i := from; i < from+n; i++ {
			if err := events.Insert(ctx, h.DB, &events.Event{
				IPPacked: events.PackIP(fmt.Sprintf("198.51.100.%d", i)), Phase: "serve",
			}); err != nil {
				t.Fatal(err)
			}
		}
	}
	// gauge is the exported figure; -1 when the family is not exported.
	gauge := func(h *Handler) int {
		t.Helper()
		_, body := scrapeMetrics(h)
		fam := parseExposition(t, body)["unmask_event_unique_ip"]
		if fam == nil || len(fam.samples) != 1 {
			return -1
		}
		if fam.typ != "gauge" {
			t.Errorf("unmask_event_unique_ip is a %s, want a gauge", fam.typ)
		}
		var n int
		if _, err := fmt.Sscanf(fam.samples[0].value, "%d", &n); err != nil {
			t.Fatalf("unmask_event_unique_ip value %q", fam.samples[0].value)
		}
		return n
	}
	// The sketch is an estimate: two addresses in one register read as one.
	about := func(got, want int) bool { return got >= want-3 && got <= want+3 }
	t.Cleanup(dashboard.ResetHourlyAggReadyForTest)

	add(40, 1)
	if err := dashboard.AggregateHourly(ctx, h.DB, nil); err != nil {
		t.Fatal(err)
	}
	first := gauge(h)
	if !about(first, 40) {
		t.Fatalf("unmask_event_unique_ip = %d, want about 40", first)
	}
	// More addresses, folded: the reading stands for its minute.
	add(30, 100)
	if err := dashboard.AggregateHourly(ctx, h.DB, nil); err != nil {
		t.Fatal(err)
	}
	if got := gauge(h); got != first {
		t.Errorf("a second scrape within the minute read the sketches again: %d after %d", got, first)
	}
	// Another database is another reading, not this one's.
	other, _ := reconfHandler(t, false)
	if got := gauge(other); got != 0 {
		t.Errorf("a daemon on an empty database exports %d, want 0 (its own reading)", got)
	}
	// Once the minute is over the gauge moves.
	Metrics.uniqMu.Lock()
	Metrics.uniqAt = time.Now().Add(-2 * uniqueIPKeep)
	Metrics.uniqFor = h.DB
	Metrics.uniqMu.Unlock()
	if got := gauge(h); !about(got, 70) {
		t.Errorf("after the minute: %d, want about 70", got)
	}
}
