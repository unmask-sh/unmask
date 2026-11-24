package dashboard

import (
	"context"
	"testing"
	"time"

	"github.com/unmask-sh/unmask/admin/internal/db"
	"github.com/unmask-sh/unmask/admin/internal/events"
	iphll "github.com/unmask-sh/unmask/admin/internal/hll"
)

// letSeed writes one hour's rows the way the access-log reader does.
func letSeedTotal(t *testing.T, d *db.DB, hour int64, site, reason, detail string, cnt int, ips ...string) {
	t.Helper()
	var sk iphll.Sketch
	for _, ip := range ips {
		sk.Add(events.PackIP(ip))
	}
	if _, err := d.Exec(`INSERT INTO unmask_let_hourly (bucket_hour, site, reason, detail, cnt, ips) VALUES (?, ?, ?, ?, ?, ?)`,
		hour, site, reason, detail, cnt, sk.Bytes()); err != nil {
		t.Fatal(err)
	}
}

func letSeedAddr(t *testing.T, d *db.DB, hour int64, site, reason, detail, ip string, cnt int, path string) {
	t.Helper()
	at := time.Unix(hour*3600+60, 0).UTC().Format("2006-01-02 15:04:05.000")
	if _, err := d.Exec(`INSERT INTO unmask_let_ip_hourly (bucket_hour, site, reason, detail, ip, cnt, first_seen, last_seen, ja4, ua, path)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		hour, site, reason, detail, events.PackIP(ip), cnt, at, at, "t13d_x", "ua of "+ip, path); err != nil {
		t.Fatal(err)
	}
}

// TestLetThroughReasons: the window is summed per reason and detail, and an
// address seen in two hours is one address.
func TestLetThroughReasons(t *testing.T) { letReasonsCase(t, openTestDB(t)) }

// letReasonsCase is the test's body, for a database of either kind (the
// MariaDB one runs it too: let_through_mariadb_test.go).
func letReasonsCase(t *testing.T, d *db.DB) {
	ctx := context.Background()
	now := time.Now().Unix() / 3600
	letSeedTotal(t, d, now-1, "a.example", "name", "ExampleBot", 5, "203.0.113.1", "203.0.113.2")
	letSeedTotal(t, d, now, "a.example", "name", "ExampleBot", 7, "203.0.113.2", "203.0.113.3")
	letSeedTotal(t, d, now, "a.example", "cookie", "captcha", 900, "198.51.100.1")
	letSeedTotal(t, d, now, "b.example", "none", "", 2, "192.0.2.9")
	letSeedTotal(t, d, now-200, "a.example", "name", "ExampleBot", 1000, "203.0.113.200") // outside a day

	rows, err := LetThroughReasons(ctx, d, "", 24)
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 3 {
		t.Fatalf("%d rows, want 3: %+v", len(rows), rows)
	}
	want := []LetReasonRow{
		{"cookie", "captcha", 900, 1},
		{"name", "ExampleBot", 12, 3},
		{"none", "", 2, 1},
	}
	for i, w := range want {
		if rows[i] != w {
			t.Errorf("row %d: %+v, want %+v", i, rows[i], w)
		}
	}
	rows, err = LetThroughReasons(ctx, d, "b.example", 24)
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 1 || rows[0].Reason != "none" {
		t.Errorf("for b.example alone: %+v", rows)
	}
}

// TestLetThroughAddresses: the hours of an address fold into one row, the
// latest hour naming its path, and an address nothing shows to have met the
// challenge -- no event, no pass presented -- is listed ahead of busier ones
// that did.
func TestLetThroughAddresses(t *testing.T) { letAddressesCase(t, openTestDB(t)) }

func letAddressesCase(t *testing.T, d *db.DB) {
	ctx := context.Background()
	nowTS := time.Now().Unix()
	now := nowTS / 3600
	letSeedAddr(t, d, now-2, "a.example", "name", "ExampleBot", "203.0.113.1", 40, "/old")
	letSeedAddr(t, d, now, "a.example", "name", "ExampleBot", "203.0.113.1", 60, "/new")
	letSeedAddr(t, d, now, "a.example", "name", "ExampleBot", "203.0.113.2", 500, "/busy")
	letSeedAddr(t, d, now, "a.example", "name", "ExampleBot", "203.0.113.3", 300, "/passed")
	letSeedAddr(t, d, now, "a.example", "name", "ExampleBot", "203.0.113.4", 3, "/quiet")
	letSeedAddr(t, d, now, "a.example", "path", "static-assets", "203.0.113.9", 9, "/robots.txt")

	// 203.0.113.2 was shown a challenge; 203.0.113.3 presented a pass.
	at := time.Unix(nowTS-600, 0).UTC().Format("2006-01-02 15:04:05.000")
	if _, err := d.Exec(`INSERT INTO unmask_event (site, host, ip_address, user_agent, phase, payload_json, date_created)
		VALUES ('a.example', 'h', ?, 'UA', 'serve', '{}', ?)`, events.PackIP("203.0.113.2"), at); err != nil {
		t.Fatal(err)
	}
	if _, err := d.Exec(`INSERT INTO unmask_pass_ip_day (bucket_day, site, ip, cookies, cnt) VALUES (?, 'a.example', ?, 1, 4)`,
		nowTS/86400, events.PackIP("203.0.113.3")); err != nil {
		t.Fatal(err)
	}
	// A pass on another site says nothing about this one.
	if _, err := d.Exec(`INSERT INTO unmask_pass_ip_day (bucket_day, site, ip, cookies, cnt) VALUES (?, 'b.example', ?, 1, 4)`,
		nowTS/86400, events.PackIP("203.0.113.4")); err != nil {
		t.Fatal(err)
	}

	rows, err := LetThroughAddresses(ctx, d, "", 24, "name", 50)
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 4 {
		t.Fatalf("%d rows, want 4: %+v", len(rows), rows)
	}
	var order []string
	for _, r := range rows {
		order = append(order, r.IP)
	}
	if got, want := order, []string{"203.0.113.1", "203.0.113.4", "203.0.113.2", "203.0.113.3"}; !equalStrings(got, want) {
		t.Errorf("order %v, want %v (the unchecked first, then by requests)", got, want)
	}
	first := rows[0]
	if first.Requests != 100 || first.Path != "/new" || first.Site != "a.example" || first.Detail != "ExampleBot" || !first.Unchecked() {
		t.Errorf("the folded row: %+v", first)
	}
	if first.FirstTS >= first.LastTS || first.LastTS == 0 {
		t.Errorf("first %d / last %d: the two hours did not fold", first.FirstTS, first.LastTS)
	}
	for _, r := range rows {
		switch r.IP {
		case "203.0.113.2":
			if !r.Challenged || r.HadPass || r.Unchecked() {
				t.Errorf("the address with an event: %+v", r)
			}
		case "203.0.113.3":
			if r.Challenged || !r.HadPass || r.Unchecked() {
				t.Errorf("the address with a pass: %+v", r)
			}
		case "203.0.113.4":
			if !r.Unchecked() {
				t.Errorf("a pass on another site counted for this one: %+v", r)
			}
		}
	}
	if rows, err = LetThroughAddresses(ctx, d, "", 24, "name", 2); err != nil || len(rows) != 2 {
		t.Errorf("limit 2: %d rows, err %v", len(rows), err)
	}
	if rows, err = LetThroughAddresses(ctx, d, "", 24, "none", 50); err != nil || len(rows) != 0 {
		t.Errorf("a reason with nobody under it: %d rows, err %v", len(rows), err)
	}
}
