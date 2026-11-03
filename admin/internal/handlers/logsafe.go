package handlers

import "github.com/unmask-sh/unmask/admin/internal/logsafe"

// LogSafe makes a request-derived value safe to put in a log line.
//
// The daemon logs the path, the Host, the client address and a few other
// values that came in over the wire, and log.Printf writes them as-is.  A
// newline in one of those does not stay inside the message: it ends the line,
// and what follows is a new line that looks exactly like one the daemon wrote.
// r.URL.Path is already percent-decoded by the time a handler sees it, so
// "%0aadmin IP denied: ip=..." is all it takes to write a plausible entry that
// never happened -- which is worth something to whoever wants an operator
// reading the log to reach the wrong conclusion.
//
// The escapes are the Go source ones so a forged line is visible as text rather
// than silently dropped, and the value stays readable: an operator grepping for
// a path still finds it.  Other C0 controls go the same way, since a bare
// escape sequence in a terminal is its own small surprise.
func LogSafe(s string) string { return logsafe.String(s) }

// LogSafeAll applies LogSafe across a slice, for the %v of a host / allowlist.
func LogSafeAll(ss []string) []string { return logsafe.Strings(ss) }
