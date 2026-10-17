//go:build stress && !libc.memgrind

package events

// Without -tags libc.memgrind there is no audit; the stress then relies on
// the fault itself showing (fatal error: fault), as it did in production.
func memAuditStart() {}
