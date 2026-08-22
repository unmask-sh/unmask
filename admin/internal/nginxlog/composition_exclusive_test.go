package nginxlog

import (
	"os"
	"strings"
	"testing"
)

// The composition card divides ONE total into four shares, so every request has
// to land in exactly one bucket.  Two overlaps have shipped:
//
//   - a listed crawler fetching a bypassed path counted as both, which drove
//     the human remainder negative in production (fixed in 0.1.18)
//   - a request carrying a pass cookie AND matching a bypass rule counted as
//     both, which is bigger and hid behind the first, on an install serving
//     its own assets from bypassed paths.  The excess tracked each site's
//     bypass-path share exactly -- large where the assets sat under bypassed
//     paths, near zero on a sister site serving them from a CDN -- which is
//     what identified it.
//
// Both are invisible in a unit test that only checks counts, because the
// arithmetic is right and the classification is wrong.  What has to hold is
// structural: one decision, not three independent ifs.
func TestKindCountersAreMutuallyExclusive(t *testing.T) {
	src := readSource(t)

	// One switch decides it.  Independent `if`s are how both overlaps happened:
	// each condition was correct in isolation and nothing stopped two firing.
	dec := strings.Index(src, "switch {")
	if dec < 0 {
		t.Fatal("the crawler_pass / bypass_pass decision is not a single switch; independent ifs let two fire for one request")
	}
	seg := src[dec:]
	if end := strings.Index(seg, "\n\t}"); end > 0 {
		seg = seg[:end]
	}
	for _, want := range []string{`case p.kind != "":`, `bumpKind(p.site, "bypass_pass")`, `bumpKind(p.site, "crawler_pass")`} {
		if !strings.Contains(seg, want) {
			t.Errorf("the classification switch does not contain %q", want)
		}
	}
	// The order is the classification, so it is asserted rather than left to
	// whoever edits the switch next.  Most specific statement about the client
	// first, and "we exempted it from judgement" last, because that is the one
	// case that says nothing about what the traffic was:
	//
	//   pass cookie > challenged > listed crawler > bypassed
	//
	// Bypass ahead of crawler was the 0.1.18 order.  It kept the counters
	// exclusive, which was the bug that mattered, but it filed a listed crawler
	// fetching a bypassed path as "passed through" -- while the crawler funnel
	// further down the same page counted it as a crawler regardless of path.
	// One page, one day, two answers: 239,996 and 775,973.
	cookie := strings.Index(seg, `case p.kind != "":`)
	fired := strings.Index(seg, "case p.fc:")
	crawler := strings.Index(seg, "crawler_pass")
	bypass := strings.Index(seg, "bypass_pass")
	if fired < 0 {
		t.Fatal("a challenged request can still reach crawler_pass / bypass_pass")
	}
	if !(cookie < fired && fired < crawler && crawler < bypass) {
		t.Errorf("classification order is wrong (cookie=%d challenged=%d crawler=%d bypass=%d); "+
			"want pass cookie, then challenged, then listed crawler, then bypassed", cookie, fired, crawler, bypass)
	}
}

// The four figures must come from one table.  The install-wide view used to
// read the benign half from unmask_crawler_minute -- a different table, not
// part of the total's bookkeeping, whose "passed" includes crawlers that hit a
// bypassed path and so double-counts against bypass_pass (535,977 in a day).
// The card then could not compute a human remainder at all and rendered "—".
func TestCompositionReadsOneTable(t *testing.T) {
	src := readFile(t, "../dashboard/queries.go")
	fn := strings.Index(src, "func TrafficRequests(")
	if fn < 0 {
		t.Fatal("TrafficRequests not found")
	}
	body := src[fn:]
	if end := strings.Index(body, "\nfunc "); end > 0 {
		body = body[:end]
	}
	if strings.Contains(body, "unmask_crawler_minute") {
		t.Error("TrafficRequests reads unmask_crawler_minute; the four shares must all come from unmask_cookie_minute or they do not divide one total")
	}
	if !strings.Contains(body, "unmask_cookie_minute") {
		t.Error("TrafficRequests no longer reads unmask_cookie_minute")
	}
}

func readSource(t *testing.T) string { return readFile(t, "nginxlog.go") }

func readFile(t *testing.T, p string) string {
	t.Helper()
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}
