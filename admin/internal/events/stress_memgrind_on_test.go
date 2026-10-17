//go:build stress && libc.memgrind

package events

import "modernc.org/libc"

// memAuditStart turns on libc's allocation audit: from here every free is
// checked against the allocations it knows, and a double free or a free of
// unknown memory panics with both callers.
func memAuditStart() { libc.MemAuditStart() }
