package dashboard

import (
	"context"
	"reflect"
	"testing"
	"time"

	"github.com/unmask-sh/unmask/admin/internal/db"
	"github.com/unmask-sh/unmask/admin/internal/settings"
)

// The detections-by-reason card reads the same numbers from the rollup as
// from the events, declines the rollup when it cannot vouch for the whole
// window, and never counts anything but serves.
func TestServeReasonsMatchTheRawDefinition(t *testing.T) {
	d, err := db.Open(settings.DB{Driver: "sqlite", SQLitePath: t.TempDir() + "/s.sqlite"})
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	if err := db.Migrate(d); err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	now := time.Now().UTC().Format("2006-01-02 15:04:05")
	add := func(site, phase, payload string) {
		t.Helper()
		if _, err := d.Exec(`INSERT INTO unmask_event
			(site, host, ip_address, phase, flags, reload_count, payload_json, date_created)
			VALUES (?, 'h', x'01020304', ?, 0, 0, ?, ?)`, site, phase, payload, now); err != nil {
			t.Fatal(err)
		}
	}
	add("a.example", "serve", `{"force_reason":"ja4_bot","ch_mode":"captcha_only"}`)
	add("a.example", "serve", `{"force_reason":"ja4_bot"}`)
	add("b.example", "serve", `{"force_reason":"none","ch_mode":"pow_only"}`)
	add("a.example", "serve", `{"force_reason":"rate_limit","rl":1}`)  // rate-limited serves count too
	add("b.example", "serve", `{"force_reason":"geo_deny","deny":1}`)  // so do deny pages
	add("a.example", "serve", `{"force_reason":"custom_rule"}`)        // a reason no list names
	add("a.example", "serve", `{}`)                                    // older than the field
	add("a.example", "serve", `{"force_reason":"Not A Reason; DROP"}`) // never a key as written
	add("a.example", "load", `{"force_reason":"ja4_bot"}`)             // not a serve
	add("a.example", "bv_pow_only", `{"force_reason":"none"}`)         // not a serve

	want := map[string]int{"ja4_bot": 2, "none": 1, "rate_limit": 1, "geo_deny": 1, "custom_rule": 1, "unknown": 2}
	wantA := map[string]int{"ja4_bot": 2, "rate_limit": 1, "custom_rule": 1, "unknown": 2}

	defer hourlyReady.Store(false)
	hourlyReady.Store(false)
	got, ok := ServeReasons(ctx, d, "", nil, 24)
	if !ok || !reflect.DeepEqual(got, want) {
		t.Fatalf("raw scan: got %v (ok=%v), want %v", got, ok, want)
	}

	if err := AggregateHourly(ctx, d, nil); err != nil {
		t.Fatalf("aggregate: %v", err)
	}
	if !HourlyAggReady() {
		t.Fatal("the aggregator reported no completed pass")
	}
	if m, ok := serveReasonsRollup(ctx, d, 24); !ok || !reflect.DeepEqual(m, want) {
		t.Fatalf("rollup: got %v (ok=%v), want %v", m, ok, want)
	}
	if got, ok := ServeReasons(ctx, d, "", nil, 24); !ok || !reflect.DeepEqual(got, want) {
		t.Fatalf("ServeReasons on the rollup: got %v (ok=%v), want %v", got, ok, want)
	}
	// A site filter is the scan's: the rollup carries no site.
	if got, ok := ServeReasons(ctx, d, "a.example", nil, 24); !ok || !reflect.DeepEqual(got, wantA) {
		t.Fatalf("site filter: got %v (ok=%v), want %v", got, ok, wantA)
	}

	// The upgrade: hours folded before the kind existed carry serves in ph and
	// nothing in svr.  The rollup must decline, and the scan answers.
	if _, err := d.Exec(`UPDATE unmask_aggregate_hourly SET cnt = cnt + 5
		WHERE bucket_kind = 'ph' AND bucket_key = 'serve'`); err != nil {
		t.Fatal(err)
	}
	if _, ok := serveReasonsRollup(ctx, d, 24); ok {
		t.Fatal("the rollup answered for a window that reaches back past the kind")
	}
	if got, ok := ServeReasons(ctx, d, "", nil, 24); !ok || !reflect.DeepEqual(got, want) {
		t.Fatalf("after declining: got %v (ok=%v), want %v", got, ok, want)
	}
}

func TestServeReasonKey(t *testing.T) {
	for in, want := range map[string]string{
		"ja4_bot":                           "ja4_bot",
		"none":                              "none",
		"custom_rule":                       "custom_rule",
		"":                                  "unknown",
		"Ja4_Bot":                           "unknown",
		"a b":                               "unknown",
		"x;drop":                            "unknown",
		"abcdefghijklmnopqrstuvwxyzabcdefg": "unknown", // 33: past the bound
	} {
		if got := serveReasonKey(in); got != want {
			t.Errorf("serveReasonKey(%q) = %q, want %q", in, got, want)
		}
	}
}
