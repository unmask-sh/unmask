package main

import (
	"strings"
	"testing"
	"time"

	"github.com/unmask-sh/unmask/admin/internal/db"
	"github.com/unmask-sh/unmask/admin/internal/settings"
)

// With a trusted LB configured, doctor reads the last hour's events to say
// whether nginx restores the client address: addresses inside the LB's own
// ranges are the LB connecting.  All inside is an error, any outside is an
// OK, and no events leave the reminder.  (It used to be a reminder in every
// case, which the assistant took for a finding.)
func TestCheckRealIP(t *testing.T) {
	seed := func(d *db.DB, hex string) {
		t.Helper()
		if _, err := d.Exec(`INSERT INTO unmask_event (site,host,ip_address,user_agent,phase,date_created) VALUES ('','',X'`+hex+`','ua','serve',?)`,
			time.Now().UTC().Add(-10*time.Minute).Format("2006-01-02 15:04:05.000")); err != nil {
			t.Fatal(err)
		}
	}
	run := func(d *db.DB, lb bool) (oks, warns, errs []string) {
		s := settings.Settings{}
		if lb {
			s.Nginx.TrustedLBPresets = []string{"gcp"}
		}
		checkRealIP(d, s, func(_, m string) { oks = append(oks, m) }, func(_, m string) { warns = append(warns, m) }, func(_, m string) { errs = append(errs, m) })
		return
	}

	d := retentionTestDB(t)
	if oks, warns, errs := run(d, false); len(oks)+len(warns)+len(errs) != 0 {
		t.Errorf("no LB configured: nothing to say, got %v %v %v", oks, warns, errs)
	}
	if _, warns, _ := run(d, true); len(warns) != 1 || !strings.Contains(warns[0], "no request of the last hour") {
		t.Errorf("no events: want the reminder, got %v", warns)
	}
	// Two addresses, both from GCP's load-balancer ranges (130.211.0.0/22).
	seed(d, "82D30005")
	seed(d, "82D30006")
	if _, _, errs := run(d, true); len(errs) != 1 || !strings.Contains(errs[0], "NOT restoring") || !strings.Contains(errs[0], "(2 distinct)") {
		t.Errorf("only LB addresses: want the error, got %v", errs)
	}
	// One visitor from outside: the address is restored.
	seed(d, "CB007109")
	if oks, _, errs := run(d, true); len(errs) != 0 || len(oks) != 1 || !strings.Contains(oks[0], "restores the client address: 3 distinct addresses in the last hour, 2 of them") {
		t.Errorf("an outside address: want the OK, got %v / %v", oks, errs)
	}
}
