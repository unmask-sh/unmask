// The challenge page, compressed by the daemon.
//
// The page is the answer a protected site gives most often, and most of the
// clients it is given to run no script: what it weighs on the wire is what
// the protection costs to send.  nginx compresses a proxied page only where
// the operator turned gzip on -- and, for a request that arrived through a
// load balancer or a CDN, said gzip_proxied as well -- and it compresses a
// 403, never a 429 (the status a rate limit's page answers with).  Where it
// does not, the page went out at three times the size it needs.
//
// So the daemon compresses it before nginx sees it, for a client that says
// it reads gzip.  nginx passes an answer that already carries a
// Content-Encoding as it is.  Only for a request that came through the nginx
// module's server.inc: forward-auth is frozen and keeps the page it had, and
// so do Apache and a request made of the daemon directly.  And not where the
// operator said no (challenge_page_gzip: false): an nginx that compresses
// better (brotli), or that rewrites the page on its way out (sub_filter),
// has to be given the page as it is.
package handlers

import (
	"bytes"
	"compress/gzip"
	"io"
	"net/http"
	"runtime"
	"strconv"
	"strings"
	"sync"

	"github.com/unmask-sh/unmask/admin/internal/settings"
)

const (
	// pageGzipLevel: the page with the script's file named is about 33 KB and
	// leaves at 12 KB; the top level takes two and a half times as long for
	// the last 300 bytes.
	pageGzipLevel = 6
	// pageGzipMin: below this the header and trailer of gzip are a
	// noticeable share and there is nothing to save.
	pageGzipMin = 1024
)

// pageGzipWriters: a writer's tables are over half a megabyte, allocated at
// its making; one is made per page being compressed at once, not per page.
var pageGzipWriters = sync.Pool{New: func() any {
	zw, _ := gzip.NewWriterLevel(io.Discard, pageGzipLevel)
	return zw
}}

// pageGzipSlots holds how many pages may be compressed at once: half the
// processors, at least one.  A page costs about a millisecond of one
// processor, which is nothing at the rate a site is visited and everything in
// a flood -- the one time the daemon has to keep answering.  A serve that
// finds no slot free sends the page as it is, as every serve did before.
var pageGzipSlots = make(chan struct{}, pageGzipConcurrency(runtime.GOMAXPROCS(0)))

func pageGzipConcurrency(procs int) int {
	if procs < 2 {
		return 1
	}
	return procs / 2
}

// throughModule reports whether the request came through the nginx module's
// server.inc, which sets X-Unmask-Local-Port on every request it hands the
// daemon.
func throughModule(r *http.Request) bool {
	return strings.TrimSpace(r.Header.Get("X-Unmask-Local-Port")) != ""
}

// writeChallengePage sends the challenge page with its status: compressed
// where the daemon does that (see the top of this file), as it is otherwise.
// The headers of the page are set by the caller; this adds the ones that say
// how the body is encoded.
func writeChallengePage(w http.ResponseWriter, r *http.Request, status int, body []byte, ch settings.ChallengeValues) {
	if throughModule(r) && ch.IsChallengePageGzip() {
		// Compressed or not, by what the client reads: a cache in between
		// has to know (the page is no-store, and says so too).
		w.Header().Add("Vary", "Accept-Encoding")
		if zb, ok := gzipPage(r, body); ok {
			w.Header().Set("Content-Encoding", "gzip")
			w.Header().Set("Content-Length", strconv.Itoa(len(zb)))
			body = zb
		}
	}
	w.WriteHeader(status)
	_, _ = w.Write(body)
}

// gzipPage compresses body for a client that reads gzip.  ok is false when
// the client does not, when the page is too small to gain, when every slot
// is taken, and when the result is no smaller: the caller sends body as it
// is.
func gzipPage(r *http.Request, body []byte) (out []byte, ok bool) {
	if len(body) < pageGzipMin || !acceptsGzip(r) {
		return nil, false
	}
	select {
	case pageGzipSlots <- struct{}{}:
		defer func() { <-pageGzipSlots }()
	default:
		return nil, false
	}
	var buf bytes.Buffer
	buf.Grow(len(body) / 2)
	zw := pageGzipWriters.Get().(*gzip.Writer)
	zw.Reset(&buf)
	_, werr := zw.Write(body)
	cerr := zw.Close()
	pageGzipWriters.Put(zw)
	if werr != nil || cerr != nil || buf.Len() >= len(body) {
		return nil, false
	}
	return buf.Bytes(), true
}
