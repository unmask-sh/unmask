package main

import (
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// The access-log wrapper must let http.ResponseController reach the
// connection: the assistant's answer and the events stream extend or lift
// the server's write deadline through it.  Without Unwrap the extension
// failed silently and the 60 s WriteTimeout closed the connection under an
// answer that took 61 s -- the page said the question failed, the answer
// was stored.  A real server, since the recorder cannot carry deadlines.
func TestAccessLogWrapperKeepsDeadlines(t *testing.T) {
	var got error
	srv := httptest.NewServer(withAccessLog(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = http.NewResponseController(w).SetWriteDeadline(time.Now().Add(time.Minute))
		_, _ = io.WriteString(w, "ok")
	})))
	defer srv.Close()
	resp, err := http.Get(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	if got != nil {
		t.Fatalf("SetWriteDeadline through the access-log wrapper: %v", got)
	}
}
