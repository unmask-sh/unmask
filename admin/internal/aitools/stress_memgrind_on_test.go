//go:build stress && libc.memgrind

package aitools

import "modernc.org/libc"

func memAuditStart() { libc.MemAuditStart() }
