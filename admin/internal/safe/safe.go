// Package safe provides panic-recovery wrappers for goroutines.
//
// net/http only recovers a panic that happens in the request handler's OWN
// goroutine.  A panic in any goroutine the handler spawns -- or in a background
// worker (the hourly aggregate, the events flusher, the nginxlog reader, the
// dashboard card fan-out) -- crashes the whole process.  For a forward-auth
// daemon that gates every request on the site, one stray panic from a bad DB
// row or a malformed log line takes the entire site's bot protection down.
//
// Wrap every goroutine so a single bad input can't kill the daemon.
package safe

import (
	"log"
	"runtime/debug"
)

// Go runs fn in a new goroutine with panic recovery.  Use for one-shot
// goroutines (e.g. a per-request dashboard card query).  A recovered panic is
// logged with a stack trace; the goroutine exits but the process survives.
func Go(name string, fn func()) {
	go Run(name, fn)
}

// Run runs fn synchronously with panic recovery.  Use it INSIDE a loop body so
// one panicking iteration is logged and the loop continues -- e.g.
//
//	for range ticker.C { safe.Run("aggregate-tick", doWork) }
//
// (Wrapping the whole goroutine instead would end the loop on the first panic.)
func Run(name string, fn func()) {
	defer Recover(name)
	fn()
}

// Recover is a deferred panic handler for a caller-managed goroutine:
//
//	go func() { defer safe.Recover("worker"); ... }()
func Recover(name string) {
	if r := recover(); r != nil {
		log.Printf("PANIC recovered in %s: %v\n%s", name, r, debug.Stack())
	}
}
