package nginxconf

import (
	"strings"
	"testing"
)

// The admin location carries the live-tail SSE stream, and the stream
// heartbeats every five seconds -- yet on a fleet vhost it closed at exactly
// 60.00s, every minute, for as long as the tail was open.  The vhost set
// `proxy_read_timeout 60`, the location inherited it, and the timeout is the
// operator's budget for the whole response: the heartbeat keeps the socket
// from going idle but does not reset that budget.  Each cut made the browser
// reconnect, the tail flicker "(reconnecting)", and the page churn.
//
// The location now sets its own read/send timeout, long enough that a tail
// left open for a working session never sees it.  Pinned here because the
// symptom is invisible in every test environment -- e2e nginx has no vhost
// timeout to inherit -- and was only ever seen on a production vhost.
func TestAdminLocationOutlivesVhostReadTimeout(t *testing.T) {
	server := renderWBA(t, false, "server.inc")
	i := strings.Index(server, "proxy_buffering    off;")
	if i < 0 {
		t.Fatal("the admin proxy location no longer disables buffering; SSE cannot stream through a buffered proxy")
	}
	// The timeouts must sit in the same location as the buffering directive:
	// a value in a different block would not override the vhost's for the
	// stream.  Look within the directives that follow, before the block ends.
	tail := server[i:]
	if end := strings.Index(tail, "\n}"); end > 0 {
		tail = tail[:end]
	}
	for _, want := range []string{"proxy_read_timeout 3600s;", "proxy_send_timeout 3600s;"} {
		if !strings.Contains(tail, want) {
			t.Errorf("the SSE-carrying admin location lacks %q -- a vhost-level proxy_read_timeout (60s is common) "+
				"is inherited and closes the live tail every minute", want)
		}
	}
}
