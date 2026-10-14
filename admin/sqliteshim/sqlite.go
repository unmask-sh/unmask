// Package sqlite stands in for github.com/glebarez/go-sqlite, the
// database/sql driver the GORM dialector (github.com/glebarez/sqlite) imports.
// admin/go.mod replaces that module with this directory, so the driver behind
// the dialector is modernc.org/sqlite's own, which this package registers (as
// "sqlite", the name the dialector opens) by importing it.  The dialector uses
// one thing from the driver package besides the name: the error type its
// Translate reads Code() from.
//
// Why not the fork: glebarez/go-sqlite stops watching a query's context once
// the statement is prepared, so a deadline never interrupted the work a SELECT
// does -- a count or a GROUP BY runs entirely in its first step, which came
// after.  Every query budget in the admin was therefore advisory: a page waited
// for its slowest query to finish, holding a pooled connection the whole time.
// On a database larger than memory, on a disk that seeks, that was minutes:
// the dashboard stopped answering while its reads had 5 s each (2026-10-14).
// modernc.org/sqlite takes the first step under the context's watch,
// so the deadline interrupts it.  The SQLite library itself is the same: the
// fork already ran modernc.org/sqlite's.
package sqlite

import msqlite "modernc.org/sqlite"

// Error is the driver's error type: the dialector's Translate matches it and
// reads Code() to report duplicate keys and foreign-key violations.
type Error = msqlite.Error
