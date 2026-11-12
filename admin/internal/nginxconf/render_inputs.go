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
	if d.NginxLogSocket != "" && !socketPathOK(d.NginxLogSocket) {
		return fmt.Errorf("render refused: nginx_log.socket_path %q is not a path nginx's access_log can be given -- an absolute path without spaces, quotes, commas or any of ; { } # $ \\; fix it in config.yml (the files of the last render are kept)", d.NginxLogSocket)
	}
	return nil
}
