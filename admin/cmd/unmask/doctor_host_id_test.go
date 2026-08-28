package main

import (
	"context"
	"strings"
	"testing"

	"github.com/unmask-sh/unmask/admin/internal/db"
	"github.com/unmask-sh/unmask/admin/internal/settings"
)

// An install names itself in the events table with server.host_id, and when
// that is unset the name is whatever the OS hostname happens to be.  Rename the
// machine and the daemon starts writing under the new name: the install's
// history becomes two histories, and nothing on any page says they are the same
// install.  That happened on 2026-08-26.
//
// The check has to stay quiet on the ordinary install -- an unset host_id is
// the default and most machines are never renamed -- so it is gated on the
// database already holding more than one name.  These three cases are the whole
// contract: pinned is fine, one name is fine, more than one with nothing pinned
// is the warning.
func TestDoctorHostIDCheck(t *testing.T) {
	open := func(t *testing.T) *db.DB {
		t.Helper()
		d, err := db.Open(settings.DB{Driver: "sqlite", SQLitePath: t.TempDir() + "/d.sqlite"})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { d.Close() })
		if err := db.Migrate(d); err != nil {
			t.Fatal(err)
		}
		return d
	}
	seed := func(t *testing.T, d *db.DB, hosts ...string) {
		t.Helper()
		for _, h := range hosts {
			if _, err := d.ExecContext(context.Background(),
				`INSERT INTO unmask_event (site,host,scheme,port,ip_address,user_agent,ja4,ja4_verdict,
				 ja4_verdict_id,phase,flags,reload_count,cookie_bv,cookie_br,payload_json,date_created)
				 VALUES ('','`+h+`','https',443,x'7f000001','t','','',0,'serve',0,0,'','','{}',
				 datetime('now'))`); err != nil {
				t.Fatal(err)
			}
		}
	}
	// Collect what the check reported, by level.
	run := func(t *testing.T, s settings.Settings, d *db.DB) (ok, warn string) {
		t.Helper()
		checkHostIDCollect(s, d, &ok, &warn)
		return ok, warn
	}

	t.Run("pinned in config is fine whatever the database holds", func(t *testing.T) {
		d := open(t)
		seed(t, d, "old-name", "new-name")
		var s settings.Settings
		s.Server.HostID = "web1"
		ok, warn := run(t, s, d)
		if warn != "" {
			t.Errorf("a pinned host_id must not warn, got: %s", warn)
		}
		if !strings.Contains(ok, `"web1"`) {
			t.Errorf("the OK line should name the pinned id, got: %s", ok)
		}
	})

	t.Run("unset with one name in the database is fine", func(t *testing.T) {
		d := open(t)
		seed(t, d, "only-one")
		ok, warn := run(t, settings.Settings{}, d)
		if warn != "" {
			t.Errorf("one host id is the ordinary install; it must not warn, got: %s", warn)
		}
		if ok == "" {
			t.Error("the check went silent; a check that reports nothing is one nobody can act on")
		}
	})

	t.Run("unset with several names warns and names them", func(t *testing.T) {
		d := open(t)
		seed(t, d, "old-name", "new-name")
		ok, warn := run(t, settings.Settings{}, d)
		if warn == "" {
			t.Fatalf("two host ids with nothing pinned is the case this exists for; got OK: %s", ok)
		}
		for _, want := range []string{"old-name", "new-name", "server.host_id"} {
			if !strings.Contains(warn, want) {
				t.Errorf("the warning must name %q so the operator can act on it, got: %s", want, warn)
			}
		}
	})
}

// checkHostIDCollect drives checkHostIDPinned and captures its one line.
func checkHostIDCollect(s settings.Settings, d *db.DB, ok, warn *string) {
	checkHostIDPinned(s, d, func(_, m string) { *ok = m }, func(_, m string) { *warn = m })
}
