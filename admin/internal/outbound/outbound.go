// Package outbound is the dialer behind every connection the daemon opens to
// a destination the operator configured -- the alert webhook, the SMTP relay,
// the AI provider, the Community Bans hub, the feeds it pulls, the geo
// database it downloads -- and the policy of where such a connection may go.
//
// Those destinations are set by an authenticated administrator, so this is
// not the guard the Web Bot Auth fetch needs (that one follows a header any
// client can send, and keeps its own stricter dialer).  It is the guard
// against what a settings page should never be able to do even in the right
// hands: make the daemon talk to the cloud's metadata service (169.254.169.254
// and its kin hand out the instance's credentials to whoever asks from the
// instance), or to the host's own loopback services, which answer the daemon
// as a local process and were never meant to be reachable through a webhook
// URL.  A private network is a different matter: an alert receiver on the
// office network is the common case, so private ranges are allowed unless
// the operator says otherwise (Policy.DenyPrivate).
//
// The check runs in the dialer's Control hook, on the address the connection
// is actually about to be made to -- after name resolution, and again on
// every redirect, since each is a new dial.  A name that resolves to a
// refused address is refused whatever it resolved to a moment ago (DNS
// rebinding), and a name with several addresses connects to the ones that
// pass.
//
// Two destinations are local by design and say so when they take their
// client: the SMTP relay, which on most hosts is a postfix on localhost, and
// the AI provider, which may be a model served on the host (ollama).  They
// keep loopback open; the metadata addresses stay refused for them too.
package outbound

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"sync/atomic"
	"syscall"
	"time"
)

// Policy is what the operator may set about outbound destinations
// (settings: outbound.*).  The zero value is the default: private networks
// reachable, loopback and the cloud metadata addresses not.
type Policy struct {
	// DenyPrivate refuses the private ranges too (RFC 1918, the IPv6
	// unique-local block, the carrier-grade NAT block): a host whose alert
	// receivers and relays are all out on the Internet has no reason to let
	// a webhook URL reach the office network.
	DenyPrivate bool
	// AllowLoopback lets a configured destination be the host itself.  Off,
	// the SMTP relay and the AI provider are still reachable on loopback
	// (they ask for it, see Local); a webhook or a feed URL is not.
	AllowLoopback bool
}

var current atomic.Pointer[Policy]

// testLoopback: loopback allowed whatever the policy says, for test suites
// whose servers listen on it (SetLoopbackForTests).  A knob of its own,
// not a policy, because a settings save in the same suite publishes the
// saved settings' policy and would take a plain allowance away again.
var testLoopback atomic.Bool

// SetPolicy publishes the policy every later dial is judged by.  Called at
// startup from the settings and again when they are saved.
func SetPolicy(p Policy) { current.Store(&p) }

// SetLoopbackForTests lets a test suite reach its own servers on loopback
// regardless of the policy in force.  Returns the previous value.
func SetLoopbackForTests(allow bool) (was bool) { return testLoopback.Swap(allow) }

// Current is the policy in force.
func Current() Policy {
	if p := current.Load(); p != nil {
		return *p
	}
	return Policy{}
}

// Error is a connection the policy refused.  It names the address, not the
// destination the operator wrote, and the reason.
type Error struct {
	Addr   netip.Addr
	Reason string
}

func (e *Error) Error() string {
	return fmt.Sprintf("outbound: refusing to connect to %s (%s)", e.Addr, e.Reason)
}

// The addresses that are refused under every policy.
var (
	// The cloud metadata services: every provider answers on the IPv4
	// link-local block (169.254.169.254; the container task endpoints on
	// 169.254.170.2), AWS also on fd00:ec2::254, Alibaba Cloud on a
	// carrier-grade NAT address.
	metadataPrefixes = []netip.Prefix{
		netip.MustParsePrefix("169.254.0.0/16"),
		netip.MustParsePrefix("fe80::/10"),
		netip.MustParsePrefix("fd00:ec2::254/128"),
		netip.MustParsePrefix("100.100.100.200/32"),
	}
	cgnat = netip.MustParsePrefix("100.64.0.0/10")
	// NAT64 (RFC 6052 well-known prefix, RFC 8215 local-use prefix): an IPv4
	// address carried in an IPv6 one, judged as the IPv4 address.
	nat64 = []netip.Prefix{
		netip.MustParsePrefix("64:ff9b::/96"),
		netip.MustParsePrefix("64:ff9b:1::/48"),
	}
)

// Refuse reports why ip must not be connected to under p, "" when it may.
// local is the caller's word that the destination is local by design (see
// the package comment): loopback then passes whatever the policy says.
func (p Policy) Refuse(ip netip.Addr, local bool) string {
	ip = ip.WithZone("").Unmap()
	for _, n := range nat64 {
		if n.Contains(ip) {
			b := ip.As16()
			ip = netip.AddrFrom4([4]byte{b[12], b[13], b[14], b[15]})
			break
		}
	}
	switch {
	case !ip.IsValid(), ip.IsUnspecified():
		return "not an address"
	case ip.IsMulticast(), ip == netip.AddrFrom4([4]byte{255, 255, 255, 255}):
		return "not a unicast address"
	}
	for _, n := range metadataPrefixes {
		if n.Contains(ip) {
			return "cloud metadata address"
		}
	}
	if ip.IsLoopback() && !local && !p.AllowLoopback && !testLoopback.Load() {
		return "loopback address; set outbound.allow_loopback to permit"
	}
	if p.DenyPrivate && !ip.IsLoopback() && (ip.IsPrivate() || cgnat.Contains(ip)) {
		return "private address, refused by outbound.deny_private"
	}
	return ""
}

// control is the dialer hook: judge the resolved address, let unix sockets
// through (their address is a path).
func control(local bool) func(network, address string, _ syscall.RawConn) error {
	return func(network, address string, _ syscall.RawConn) error {
		switch network {
		case "tcp", "tcp4", "tcp6", "udp", "udp4", "udp6":
		default:
			return nil
		}
		ap, err := netip.ParseAddrPort(address)
		if err != nil {
			return fmt.Errorf("outbound: %w", err)
		}
		if why := Current().Refuse(ap.Addr(), local); why != "" {
			return &Error{Addr: ap.Addr().WithZone("").Unmap(), Reason: why}
		}
		return nil
	}
}

// Dialer is a dialer under the policy.  timeout bounds the connect; local
// is the caller's word that loopback is a destination by design.
func Dialer(timeout time.Duration, local bool) *net.Dialer {
	return &net.Dialer{Timeout: timeout, Control: control(local)}
}

// DialContext dials under the policy with the standard dialer's defaults.
func DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	return Dialer(30*time.Second, false).DialContext(ctx, network, addr)
}

// Transport is an HTTP transport whose connections are judged by the
// policy.  Everything else is the standard transport's defaults (proxy from
// the environment, TLS verification, keep-alives).
func Transport(local bool) *http.Transport {
	return &http.Transport{
		Proxy:                 http.ProxyFromEnvironment,
		DialContext:           Dialer(30*time.Second, local).DialContext,
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          8,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: time.Second,
	}
}

// Client is an HTTP client under the policy; timeout 0 leaves the request's
// context to bound it.
func Client(timeout time.Duration) *http.Client {
	return &http.Client{Timeout: timeout, Transport: Transport(false)}
}

// LocalClient is Client for a destination that is local by design (the AI
// provider): loopback passes, the metadata addresses do not.
func LocalClient(timeout time.Duration) *http.Client {
	return &http.Client{Timeout: timeout, Transport: Transport(true)}
}
