package main

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"strings"
	"time"

	"github.com/unmask-sh/unmask/admin/internal/db"
	"github.com/unmask-sh/unmask/admin/internal/settings"
)

// lookupDBHost resolves the database's host name; a test puts its own in
// its place.
var lookupDBHost = func(host string) ([]string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	return net.DefaultResolver.LookupHost(ctx, host)
}

// localAddrs: the addresses this host's own interfaces carry; a test puts
// its own in its place.
var localAddrs = func() []netip.Addr {
	var out []netip.Addr
	ifs, err := net.InterfaceAddrs()
	if err != nil {
		return nil
	}
	for _, a := range ifs {
		if p, err := netip.ParsePrefix(a.String()); err == nil {
			out = append(out, p.Addr().Unmap())
		}
	}
	return out
}

// dbHostIsThisHost reports whether a connection to host stays on this
// machine: no host at all, "localhost", a loopback address, or an address one
// of this machine's own interfaces carries -- for a name, every address it
// resolves to.  A name that does not resolve is taken to be elsewhere.
func dbHostIsThisHost(host string) bool {
	host = strings.TrimSpace(host)
	if host == "" || strings.EqualFold(host, "localhost") {
		return true
	}
	own := func(a netip.Addr) bool {
		a = a.Unmap()
		if a.IsLoopback() {
			return true
		}
		for _, l := range localAddrs() {
			if l == a {
				return true
			}
		}
		return false
	}
	if a, err := netip.ParseAddr(strings.Trim(host, "[]")); err == nil {
		return own(a)
	}
	addrs, err := lookupDBHost(host)
	if err != nil || len(addrs) == 0 {
		return false
	}
	for _, s := range addrs {
		a, err := netip.ParseAddr(s)
		if err != nil || !own(a) {
			return false
		}
	}
	return true
}

// checkDBTransport: whether what the daemon says to its database can be read
// on the way.  SQLite is a file and has no way; MariaDB on this host stays
// on it.  MariaDB on another host -- the install several nodes share -- is a
// connection over a network, and db.mysql_tls decides whether it is
// encrypted.  The default is not: every release before the setting connected
// in the clear, and an upgrade must not start refusing a server that has no
// certificate.  So an install that was never told sends the database
// password, the admin accounts' password hashes and every event row with a
// visitor's address across that network as they are, and nothing said so.
func checkDBTransport(s settings.Settings, addOK, addWarn func(t, m string)) {
	if !strings.EqualFold(strings.TrimSpace(s.DB.Driver), string(db.DriverMariaDB)) &&
		!strings.EqualFold(strings.TrimSpace(s.DB.Driver), "mysql") {
		return
	}
	const title = "database connection"
	host := strings.TrimSpace(s.DB.MariaDB.Host)
	kind := db.MySQLTLSKind(s.DB.MySQLTLS)
	if dbHostIsThisHost(host) {
		if kind == db.MySQLTLSNone {
			addOK(title, "MariaDB on this host; the connection does not leave it")
		} else {
			addOK(title, fmt.Sprintf("MariaDB on this host, over TLS (db.mysql_tls: %s)", kind))
		}
		return
	}
	switch kind {
	case db.MySQLTLSNone:
		addWarn(title, fmt.Sprintf(
			"the connection to MariaDB at %s is not encrypted (db.mysql_tls is not set): the database password, the admin accounts' password hashes and every event row — visitors' addresses, user agents — cross the network as they are. In config.yml set db.mysql_tls to true (a certificate the system's roots vouch for), to the path of the CA's PEM file, or to skip-verify for a self-signed server, then restart unmask. Nothing to do if %s is on this machine after all (a container beside this one, on the host's own bridge).",
			host, host))
	case db.MySQLTLSPreferred:
		addWarn(title, fmt.Sprintf(
			"db.mysql_tls is preferred: the connection to MariaDB at %s is encrypted only when the server offers it, and whoever sits on the path can take the offer away. Set it to true, or to the path of the CA's PEM file.",
			host))
	case db.MySQLTLSSkipVerify:
		addOK(title, fmt.Sprintf(
			"MariaDB at %s over TLS, the server's certificate not checked (db.mysql_tls: skip-verify): private from someone listening on the path, not from someone answering in the server's place",
			host))
	case db.MySQLTLSCAFile:
		addOK(title, fmt.Sprintf("MariaDB at %s over TLS, the server checked against the CA in %s", host, strings.TrimSpace(s.DB.MySQLTLS)))
	default:
		addOK(title, fmt.Sprintf("MariaDB at %s over TLS, the server's certificate verified", host))
	}
}
