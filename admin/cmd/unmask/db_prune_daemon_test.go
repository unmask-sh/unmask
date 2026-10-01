package main

import (
	"net"
	"path/filepath"
	"strconv"
	"testing"

	"github.com/unmask-sh/unmask/admin/internal/settings"
)

// The maintenance commands ask whether the daemon is running by connecting
// to where it listens: `db-prune` refuses to work beside it, and `db-vacuum`
// waits for it to hold its writes.  A daemon on a unix socket (`bind:
// unix:/path`, the form the daemon itself takes) must be found like one on
// TCP -- missing it runs the heavy work against a live daemon.
func TestDaemonAnswersOnAUnixSocket(t *testing.T) {
	path := filepath.Join(t.TempDir(), "http.sock")
	srv := settings.Server{Bind: "unix:" + path, Port: 9477, SocketMode: "0660"}
	if daemonAnswers(srv) {
		t.Fatal("a daemon answered on a socket nobody listens on")
	}
	ln, err := net.Listen("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	if !daemonAnswers(srv) {
		t.Errorf("the daemon listening on %s was not found", srv.Bind)
	}
	if got, want := daemonAddr(srv), "unix:"+path; got != want {
		t.Errorf("daemonAddr = %q, want %q", got, want)
	}
	// The mode is the socket file's, and says nothing of how to connect.
	srv.SocketMode = ""
	if !daemonAnswers(srv) {
		t.Error("the daemon on a unix socket was not found without socket_mode")
	}
}

func TestDaemonAnswersOnTCP(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	srv := settings.Server{Bind: "127.0.0.1", Port: port}
	if !daemonAnswers(srv) {
		t.Errorf("the daemon listening on 127.0.0.1:%d was not found", port)
	}
	if got, want := daemonAddr(srv), "127.0.0.1:"+strconv.Itoa(port); got != want {
		t.Errorf("daemonAddr = %q, want %q", got, want)
	}
	// A socket_mode left in the config of a daemon that listens on TCP does
	// not make it a socket.
	srv.SocketMode = "0660"
	if !daemonAnswers(srv) {
		t.Error("a leftover socket_mode hid the daemon listening on TCP")
	}
	// Every address, as the container's config has it: reached over loopback.
	srv = settings.Server{Bind: "0.0.0.0", Port: port}
	if ln2, err := net.Listen("tcp", "0.0.0.0:0"); err == nil {
		srv.Port = ln2.Addr().(*net.TCPAddr).Port
		if !daemonAnswers(srv) {
			t.Error("the daemon listening on every address was not found")
		}
		ln2.Close()
	}
	// An IPv6 bind is written in brackets, as the daemon takes it.
	if ln6, err := net.Listen("tcp", "[::1]:0"); err == nil {
		srv = settings.Server{Bind: "[::1]", Port: ln6.Addr().(*net.TCPAddr).Port}
		if !daemonAnswers(srv) {
			t.Errorf("the daemon listening on %s was not found", daemonAddr(srv))
		}
		ln6.Close()
	}
	ln.Close()
	srv = settings.Server{Bind: "127.0.0.1", Port: port}
	if daemonAnswers(srv) {
		t.Error("a daemon answered on a port nobody listens on")
	}
	// The defaults: 127.0.0.1:9477.
	if got := daemonAddr(settings.Server{}); got != "127.0.0.1:9477" {
		t.Errorf("daemonAddr with nothing set = %q, want 127.0.0.1:9477", got)
	}
}
