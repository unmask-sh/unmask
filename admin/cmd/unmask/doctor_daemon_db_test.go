package main

import (
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/unmask-sh/unmask/admin/internal/settings"
)

// doctor's own database checks are its own connection; whether the running
// daemon has the database is asked of the daemon (readyz).  503 is an error
// that says what is off and that the daemon retries; 200 is a line of its
// own; a daemon that is down or older than the endpoint adds nothing here.
func TestDoctorAsksTheDaemonForItsDatabase(t *testing.T) {
	var status atomic.Int32 // what the daemon answers; the server reads it on its own goroutine
	status.Store(http.StatusOK)
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/unmask/readyz" {
			t.Errorf("doctor asked %s, want /unmask/readyz", r.URL.Path)
		}
		w.WriteHeader(int(status.Load()))
	}))
	defer ts.Close()
	host, portText, err := net.SplitHostPort(strings.TrimPrefix(ts.URL, "http://"))
	if err != nil {
		t.Fatal(err)
	}
	port, _ := strconv.Atoi(portText)
	s := settings.Settings{Server: settings.Server{Bind: host, Port: port, BasePath: "/unmask"}}

	type line struct{ level, title, msg string }
	run := func() []line {
		var got []line
		checkDaemonHasDB(s,
			func(t, m string) { got = append(got, line{"ok", t, m}) },
			func(t, m string) { got = append(got, line{"err", t, m}) })
		return got
	}

	if got := run(); len(got) != 1 || got[0].level != "ok" || got[0].title != "daemon database" {
		t.Errorf("readyz 200: %+v, want one OK line", got)
	}
	status.Store(http.StatusServiceUnavailable)
	got := run()
	if len(got) != 1 || got[0].level != "err" {
		t.Fatalf("readyz 503: %+v, want one ERR line", got)
	}
	for _, want := range []string{"no database", "retries", "admin UI"} {
		if !strings.Contains(got[0].msg, want) {
			t.Errorf("the 503 line does not say %q: %s", want, got[0].msg)
		}
	}
	status.Store(http.StatusNotFound) // a daemon from before /readyz
	if got := run(); len(got) != 0 {
		t.Errorf("readyz 404: %+v, want nothing", got)
	}
	ts.Close() // no daemon: the self-curl's finding, not this check's
	if got := run(); len(got) != 0 {
		t.Errorf("no daemon: %+v, want nothing", got)
	}
}
