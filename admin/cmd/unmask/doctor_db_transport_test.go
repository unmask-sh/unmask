package main

import (
	"errors"
	"net/netip"
	"strings"
	"testing"

	"github.com/unmask-sh/unmask/admin/internal/db"
	"github.com/unmask-sh/unmask/admin/internal/settings"
)

// A MariaDB on another host is reached over a network, and by default in
// the clear: the database password, the accounts' password hashes and every
// event row cross it as they are.  Doctor said nothing of it.  It now reads
// where the database is and what db.mysql_tls asks for.
func TestDoctorNamesAPlainConnectionToADatabaseElsewhere(t *testing.T) {
	prevLookup, prevLocal := lookupDBHost, localAddrs
	t.Cleanup(func() { lookupDBHost, localAddrs = prevLookup, prevLocal })
	localAddrs = func() []netip.Addr {
		return []netip.Addr{netip.MustParseAddr("192.0.2.10"), netip.MustParseAddr("2001:db8::10")}
	}
	lookupDBHost = func(host string) ([]string, error) {
		switch host {
		case "db.internal.example":
			return []string{"198.51.100.20"}, nil
		case "me.example":
			return []string{"192.0.2.10", "2001:db8::10"}, nil
		case "half.example":
			return []string{"192.0.2.10", "198.51.100.20"}, nil
		}
		return nil, errors.New("no such host")
	}
	run := func(driver, host, tls string) (ok, warn string) {
		t.Helper()
		var s settings.Settings
		s.DB.Driver, s.DB.MariaDB.Host, s.DB.MySQLTLS = driver, host, tls
		var oks, warns []string
		checkDBTransport(s, func(_, m string) { oks = append(oks, m) }, func(_, m string) { warns = append(warns, m) })
		if len(oks)+len(warns) > 1 {
			t.Fatalf("%s %q %q: %d lines", driver, host, tls, len(oks)+len(warns))
		}
		return strings.Join(oks, ""), strings.Join(warns, "")
	}
	for _, c := range []struct {
		driver, host, tls string
		warn, ok          string // a part of the line that is wanted; "" for none
	}{
		// SQLite is a file: nothing to say.
		{"sqlite", "", "", "", ""},
		{"", "", "", "", ""},
		// On this host: no network to be read on.
		{"mariadb", "127.0.0.1", "", "", "on this host"},
		{"mariadb", "localhost", "", "", "on this host"},
		{"mariadb", "LOCALHOST", "", "", "on this host"},
		{"mariadb", "", "", "", "on this host"},
		{"mariadb", "::1", "", "", "on this host"},
		{"mariadb", "[::1]", "", "", "on this host"},
		{"mariadb", "127.8.9.10", "", "", "on this host"},
		{"mariadb", "192.0.2.10", "", "", "on this host"},   // an address of this machine's own
		{"mariadb", "2001:db8::10", "", "", "on this host"}, // likewise
		{"mariadb", "me.example", "", "", "on this host"},   // a name for this machine
		{"mysql", "127.0.0.1", "true", "", "on this host, over TLS"},
		// Elsewhere, in the clear: the finding.
		{"mariadb", "198.51.100.20", "", "is not encrypted (db.mysql_tls is not set)", ""},
		{"mariadb", "db.internal.example", "", "MariaDB at db.internal.example is not encrypted", ""},
		{"mysql", "db.internal.example", "", "is not encrypted", ""},
		{"MariaDB", "db.internal.example", " ", "is not encrypted", ""},
		{"mariadb", "db.internal.example", "false", "is not encrypted", ""},
		{"mariadb", "db.internal.example", "off", "is not encrypted", ""},
		{"mariadb", "half.example", "", "is not encrypted", ""},    // one of its addresses is elsewhere
		{"mariadb", "nowhere.example", "", "is not encrypted", ""}, // does not resolve: taken to be elsewhere
		{"mariadb", "192.0.2.11", "", "is not encrypted", ""},      // next to this machine's address, not it
		// Elsewhere, encrypted only if the server says so.
		{"mariadb", "db.internal.example", "preferred", "only when the server offers it", ""},
		{"mariadb", "db.internal.example", "Preferred", "only when the server offers it", ""},
		// Elsewhere, encrypted.
		{"mariadb", "db.internal.example", "true", "", "the server's certificate verified"},
		{"mariadb", "db.internal.example", "on", "", "the server's certificate verified"},
		{"mariadb", "db.internal.example", "skip-verify", "", "certificate not checked"},
		{"mariadb", "db.internal.example", "/etc/unmask/db-ca.pem", "", "checked against the CA in /etc/unmask/db-ca.pem"},
	} {
		ok, warn := run(c.driver, c.host, c.tls)
		if (c.warn == "") != (warn == "") || !strings.Contains(warn, c.warn) {
			t.Errorf("driver %q host %q mysql_tls %q: warning %q, want one with %q", c.driver, c.host, c.tls, warn, c.warn)
		}
		if (c.ok == "") != (ok == "") || !strings.Contains(ok, c.ok) {
			t.Errorf("driver %q host %q mysql_tls %q: ok line %q, want one with %q", c.driver, c.host, c.tls, ok, c.ok)
		}
	}
	// The warning says what to write.
	if _, warn := run("mariadb", "db.internal.example", ""); !strings.Contains(warn, "db.mysql_tls to true") || !strings.Contains(warn, "skip-verify") {
		t.Errorf("the warning does not say what to set: %q", warn)
	}
}

// What doctor reads db.mysql_tls as is what the connection reads it as: the
// words that mean no TLS, the driver's three, and a path.
func TestMySQLTLSKindIsTheConnectionsReading(t *testing.T) {
	for mode, want := range map[string]string{
		"": db.MySQLTLSNone, " ": db.MySQLTLSNone, "false": db.MySQLTLSNone, "OFF": db.MySQLTLSNone, "no": db.MySQLTLSNone, "0": db.MySQLTLSNone,
		"true": db.MySQLTLSVerified, "On": db.MySQLTLSVerified, "yes": db.MySQLTLSVerified, "1": db.MySQLTLSVerified,
		"skip-verify": db.MySQLTLSSkipVerify, "Skip-Verify": db.MySQLTLSSkipVerify,
		"preferred": db.MySQLTLSPreferred, " PREFERRED ": db.MySQLTLSPreferred,
		"/etc/unmask/ca.pem": db.MySQLTLSCAFile, "ca.pem": db.MySQLTLSCAFile, "tru": db.MySQLTLSCAFile,
	} {
		if got := db.MySQLTLSKind(mode); got != want {
			t.Errorf("MySQLTLSKind(%q) = %q, want %q", mode, got, want)
		}
	}
}
