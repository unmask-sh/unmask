package handlers

import (
	"os"
	"strings"
	"testing"
)

// The proof-of-work must run in a Web Worker, with the UI-thread loop kept
// only as a fallback.
//
// Why this is pinned rather than left as an implementation detail: the
// fallback yields with setTimeout so the page stays responsive, and browsers
// clamp a background tab's setTimeout to one second.  At the default
// difficulty that is ~52 batches, so a visitor who switched tabs waited about
// 52 seconds instead of under one.  Fleet data before the change showed
// exactly that shape -- a cluster of 42 sessions at 41-70s and 28 beyond it,
// against a smooth body where 88.8% finished within 2s.  A worker needs no
// yielding at all, so the clamp never applies.
func TestPoWRunsInAWorker(t *testing.T) {
	b, err := os.ReadFile("../../assets/static/challenge.js")
	if err != nil {
		t.Fatal(err)
	}
	js := string(b)

	if !strings.Contains(js, "new Worker(") {
		t.Error("the solve loop no longer uses a Web Worker; a backgrounded tab would be throttled to ~1s per batch")
	}
	if !strings.Contains(js, "solveInWorker") {
		t.Error("the worker entry point is gone")
	}
	// The fallback must survive too: a browser without workers (or a page CSP
	// that forbids blob:) still has to be able to solve.
	if !strings.Contains(js, "setTimeout(r,0)") {
		t.Error("the UI-thread fallback is gone; a browser without Worker support could not solve at all")
	}

	// One SHA-256 implementation, shared: the worker source is built by
	// stringifying the same functions.  A second, hand-copied implementation
	// inside the worker could drift and produce nonces the server rejects.
	if !strings.Contains(js, "sha256.toString()") || !strings.Contains(js, "leadingZeroBits.toString()") {
		t.Error("the worker no longer reuses the page's own hash functions; a divergent copy would fail server verification")
	}

	// The cookie contract is unchanged by where the work happened: the client
	// still reports only the nonce, and the server recomputes from it.
	if !strings.Contains(js, "'.pow2.'") {
		t.Error("the pow2 cookie marker changed; the server and the C plugin branch on it")
	}
}
