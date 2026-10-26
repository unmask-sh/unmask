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
// hello callback.  nginx serves HTTP/3 through its own QUIC compatibility
// layer -- which replaces the handshake callbacks, so the module sees no
// ClientHello on those connections, $client_ja4 is empty and every JA4-based
// decision falls through -- unless the library has a QUIC TLS API nginx
// uses: quictls, or OpenSSL 3.5.1 or newer under an nginx that knows that
// API, 1.29.0 or newer.  HTTP/1.1 and HTTP/2 on the same server are
// unaffected.

// nginxVersionRe: the nginx `nginx -V` names.
var nginxVersionRe = regexp.MustCompile(`nginx version: nginx/(\d+)\.(\d+)\.(\d+)`)

// openSSLBuiltRe: the library `nginx -V` says the binary was built with.
var openSSLBuiltRe = regexp.MustCompile(`built with OpenSSL (\d+)\.(\d+)\.(\d+)(\S*)`)

// listenQUICRe: a `listen` directive serving QUIC, as `nginx -T` dumps it.
var listenQUICRe = regexp.MustCompile(`^\s*listen\s+(\S+)\s[^;]*\bquic\b`)

// versionAtLeast compares a dotted X.Y.Z (as three numbers) with a floor.
func versionAtLeast(major, minor, patch, fMajor, fMinor, fPatch int) bool {
	if major != fMajor {
		return major > fMajor
	}
	if minor != fMinor {
		return minor > fMinor
	}
	return patch >= fPatch
}

// http3JA4Verdict decides from `nginx -V` (the build) and `nginx -T` (the
// running configuration) whether HTTP/3 connections on this host get no
// JA4.  warn is false when the build cannot serve HTTP/3, the library's QUIC
// TLS API is in use (quictls; OpenSSL 3.5.1+ under nginx 1.29.0+), the
// library is not OpenSSL at all (BoringSSL, LibreSSL), or no listen socket
// takes QUIC -- and when the configuration could not be dumped (nginx -T
// needs root), since the sockets are then unknown.  An nginx whose version
// cannot be read is judged on the library alone.
func http3JA4Verdict(nginxV, nginxT string) (warn bool, msg string) {
	if !strings.Contains(nginxV, "--with-http_v3_module") {
		return false, ""
	}
	m := openSSLBuiltRe.FindStringSubmatch(nginxV)
	if m == nil {
		return false, "" // BoringSSL, LibreSSL, or no version: not the OpenSSL compatibility case
	}
	if strings.Contains(strings.ToLower(m[4]), "quic") {
		return false, "" // quictls: the library has the QUIC API every nginx uses
	}
	major, _ := strconv.Atoi(m[1])
	minor, _ := strconv.Atoi(m[2])
	patch, _ := strconv.Atoi(m[3])
	libOK := versionAtLeast(major, minor, patch, 3, 5, 1)
	nginxOK := true // unknown version: judged on the library
	nginxVer := ""
	if n := nginxVersionRe.FindStringSubmatch(nginxV); n != nil {
		nMajor, _ := strconv.Atoi(n[1])
		nMinor, _ := strconv.Atoi(n[2])
		nPatch, _ := strconv.Atoi(n[3])
		nginxOK = versionAtLeast(nMajor, nMinor, nPatch, 1, 29, 0)
		nginxVer = n[1] + "." + n[2] + "." + n[3]
	}
	if libOK && nginxOK {
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
	build := "OpenSSL " + ver
	if nginxVer != "" {
		build = "nginx " + nginxVer + " built with OpenSSL " + ver
	}
	return true, fmt.Sprintf("HTTP/3 needs nginx 1.29.0 or newer built with OpenSSL 3.5.1 or newer (or quictls) for the module to see the handshake. This build (%s) serves HTTP/3 through nginx's QUIC compatibility layer, which replaces the handshake callback the module reads the ClientHello from, so JA4-based decisions do not apply to HTTP/3 -- %d `listen ... quic` socket(s): %s. HTTP/1.1 and HTTP/2 are unaffected.",
		build, len(sockets), strings.Join(sockets, ", "))
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
