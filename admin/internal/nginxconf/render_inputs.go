package nginxconf

import (
	"fmt"
	"net"
	"regexp"
	"strconv"
	"strings"
)

// The values of config.yml the renderer writes into nginx's configuration as
// they stand -- not quoted, not made a map key -- are checked at every
// render, not only by the admin forms that save them.  config.yml has other
// writers: an edit by hand, a configuration manager, `unmask upgrade-review`.
// Since the config watch, the daemon renders such an edit seconds after it is
// made, and a value with a space, a ';', a '}' or a line break in it ended
// the directive it was written into and began another, in a file nginx loads
// as root.
//
//   - the daemon's address in upstream.conf (`server <addr>;`), from
//     nginx.upstream_addr or server.bind: the render is refused;
//   - the log socket (`access_log syslog:server=unix:<path> ...`, and the
//     comments that name it): the render is refused;
//   - the Google Cloud preset with the real_ip block and no load balancer of
//     the operator's own listed: the render is refused (gcpWantsOwnAddress
//     says why);
//   - a trusted load balancer of one's own (nginx.trusted_lb_extra): its id
//     names a variable and a map key, its ranges go into a geo block
//     unquoted; an entry whose id is not a name is left out, and so is a
//     range that is not one (effectiveLBs).
//
// A refused render writes nothing: nginx goes on with the files of the last
// render, and the error says which value to fix.

// hostNameRE: a host name nginx resolves for an upstream server -- letters,
// digits, '-', '_' (a container's service name may carry one) and dots.
var hostNameRE = regexp.MustCompile(`^[A-Za-z0-9_]([A-Za-z0-9_.-]*[A-Za-z0-9_])?$`)

// lbExtraIDRE: an id of nginx.trusted_lb_extra, as the network tab accepts
// it.
var lbExtraIDRE = regexp.MustCompile(`^[A-Za-z0-9_-]+$`)

// upstreamServerOK: is v an address nginx's `server` takes as it is, with
// nothing after it -- "unix:/path", "host:port", "[v6]:port", or a host or an
// IPv4 address alone (port 80)?
func upstreamServerOK(v string) bool {
	if p, ok := strings.CutPrefix(v, "unix:"); ok {
		return socketPathOK(p)
	}
	host, port, err := net.SplitHostPort(v)
	if err != nil {
		// No port: a host name or an IPv4 address, or an IPv6 one in
		// brackets.
		host, port = v, ""
		if strings.HasPrefix(v, "[") && strings.HasSuffix(v, "]") {
			ip := net.ParseIP(v[1 : len(v)-1])
			return ip != nil && ip.To4() == nil
		}
		if strings.Contains(v, ":") {
			return false
		}
	}
	if port != "" {
		n, err := strconv.Atoi(port)
		if err != nil || n < 1 || n > 65535 || strconv.Itoa(n) != port {
			return false
		}
	}
	if ip := net.ParseIP(host); ip != nil {
		// An IPv6 address only in brackets, as SplitHostPort read it.
		return ip.To4() != nil || strings.HasPrefix(v, "[")
	}
	return hostNameRE.MatchString(host)
}

// socketPathOK: is p an absolute path that nginx's configuration can carry
// unquoted -- in `server unix:<p>;`, in `syslog:server=unix:<p>` (whose
// parameters are separated by commas), and on a comment line?
func socketPathOK(p string) bool {
	if !strings.HasPrefix(p, "/") || len(p) > 4096 {
		return false
	}
	for _, c := range p {
		if c <= ' ' || c == 0x7f || strings.ContainsRune(";{}\"'#$\\,", c) {
			return false
		}
	}
	return true
}

// lbCIDROK: is v an address or a range a geo block takes?
func lbCIDROK(v string) bool {
	if _, _, err := net.ParseCIDR(v); err == nil {
		return true
	}
	return net.ParseIP(v) != nil
}

// checkRenderInputs refuses a render whose daemon address or log socket
// nginx could not be given as written (see the top of this file).
func checkRenderInputs(d renderData) error {
	if !upstreamServerOK(d.UpstreamServer) {
		return fmt.Errorf("render refused: the daemon's address %q (nginx.upstream_addr, or server.bind) is not an address nginx's upstream takes as it is -- host:port, [IPv6]:port or unix:/absolute/path, nothing more; fix it in config.yml (the files of the last render are kept)", d.UpstreamServer)
	}
	// The Google Cloud preset with the real_ip block and no address of the
	// operator's own load balancer: rendered, every visitor would be seen as
	// the load balancer's address (gcpWantsOwnAddress).  Until 0.1.57 the
	// preset trusted 35.227.0.0/16 for it; an install that relied on that
	// keeps the files of its last render until the address is listed.
	// The gateway writes its real_ip block from the same set whenever the
	// set is not empty (gateway-proxies.inc), so it is asked the same.
	realIP := d.TrustedLBRealIP || (d.Gateway.Active && len(d.Gateway.TrustedProxies) > 0)
	if realIP && gcpWantsOwnAddress(d.LBIPRanges) {
		return fmt.Errorf("render refused: the Google Cloud load-balancer preset is on, with the visitor's address taken from X-Forwarded-For (nginx.trusted_lb_realip, or the gateway), and no load balancer of your own is listed.  A Google load balancer ends X-Forwarded-For with its own address, and nginx reads past it to the visitor's only when that address is trusted: without it, every visitor is seen as the load balancer.  The preset no longer trusts 35.227.0.0/16 for this (Google assigns that range to customers).  Add your load balancer's own address -- the forwarding rule's IPv4 and IPv6 -- as a trusted LB of your own (nginx.trusted_lb_extra in config.yml, or the network tab), or turn trusted_lb_realip off (on the gateway: take the preset out and list the proxy ranges and the address together as your own) (the files of the last render are kept)")
	}
	if d.NginxLogSocket != "" && !socketPathOK(d.NginxLogSocket) {
		return fmt.Errorf("render refused: nginx_log.socket_path %q is not a path nginx's access_log can be given -- an absolute path without spaces, quotes, commas or any of ; { } # $ \\; fix it in config.yml (the files of the last render are kept)", d.NginxLogSocket)
	}
	return nil
}
