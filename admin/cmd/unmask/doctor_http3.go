package main

import (
	"context"
	"fmt"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// HTTP/3 and JA4.  The module reads the ClientHello from OpenSSL's client
// hello callback.  When nginx is built with an OpenSSL that has no QUIC TLS
// API -- anything before 3.5 -- it serves HTTP/3 through its own QUIC
// compatibility layer, which replaces the handshake callbacks, and the module
// sees no ClientHello on those connections: $client_ja4 is empty and every
// JA4-based decision falls through.  HTTP/1.1 and HTTP/2 on the same server
// are unaffected.  A build with OpenSSL 3.5.1 or newer, or with quictls,
// uses the library's own QUIC handshake and keeps the callback.

// openSSLBuiltRe: the library `nginx -V` says the binary was built with.
var openSSLBuiltRe = regexp.MustCompile(`built with OpenSSL (\d+)\.(\d+)\.(\d+)(\S*)`)

// listenQUICRe: a `listen` directive serving QUIC, as `nginx -T` dumps it.
var listenQUICRe = regexp.MustCompile(`^\s*listen\s+(\S+)\s[^;]*\bquic\b`)

// http3JA4Verdict decides from `nginx -V` (the build) and `nginx -T` (the
// running configuration) whether HTTP/3 connections on this host get no
// JA4.  warn is false when the build cannot serve HTTP/3, the library has the
// QUIC TLS API (OpenSSL 3.5.1+, quictls), or no listen socket takes QUIC --
// and when the configuration could not be dumped (nginx -T needs root), since
// the sockets are then unknown.
func http3JA4Verdict(nginxV, nginxT string) (warn bool, msg string) {
	if !strings.Contains(nginxV, "--with-http_v3_module") {
		return false, ""
	}
	m := openSSLBuiltRe.FindStringSubmatch(nginxV)
	if m == nil {
		return false, "" // BoringSSL, LibreSSL, or no version: not the OpenSSL compatibility case
	}
	if strings.Contains(strings.ToLower(m[4]), "quic") {
		return false, "" // quictls: the library has the QUIC API
	}
	major, _ := strconv.Atoi(m[1])
	minor, _ := strconv.Atoi(m[2])
	patch, _ := strconv.Atoi(m[3])
	if major > 3 || (major == 3 && (minor > 5 || (minor == 5 && patch >= 1))) {
		return false, ""
	}
	var sockets []string
	for _, ln := range strings.Split(nginxT, "\n") {
		if t := strings.TrimSpace(ln); strings.HasPrefix(t, "#") {
			continue
		}
		if lm := listenQUICRe.FindStringSubmatch(ln); lm != nil {
			sockets = append(sockets, lm[1])
		}
	}
	if len(sockets) == 0 {
		return false, ""
	}
	ver := m[1] + "." + m[2] + "." + m[3] + m[4]
	return true, fmt.Sprintf("JA4 is not computed for HTTP/3 connections with this OpenSSL (%s): nginx's QUIC compatibility layer replaces the handshake callback the module reads the ClientHello from, so JA4-based decisions do not apply to HTTP/3 -- %d `listen ... quic` socket(s): %s. HTTP/1.1 and HTTP/2 are unaffected. Build nginx with OpenSSL 3.5.1 or newer, or with quictls.",
		ver, len(sockets), strings.Join(sockets, ", "))
}

// checkHTTP3JA4 runs the verdict against the host nginx.
func checkHTTP3JA4(addWarn func(t, m string)) {
	nginxBin, err := exec.LookPath("nginx")
	if err != nil {
		return // no nginx on this host
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	v, _ := exec.CommandContext(ctx, nginxBin, "-V").CombinedOutput() // -V writes to stderr
	dump, _ := exec.CommandContext(ctx, nginxBin, "-T").CombinedOutput()
	if warn, msg := http3JA4Verdict(string(v), string(dump)); warn {
		addWarn("HTTP/3 JA4", msg)
	}
}
