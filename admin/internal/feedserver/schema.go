package feedserver

import (
	"database/sql"
	"fmt"
)

// migrate: build the SQLite schema idempotently.
//
//   feed_tokens(id, secret_hash, created_at, last_seen_at, abuse_score)
//     secret_hash = sha256(raw_token) hex.  raw_token is never stored.
//   feed_submissions(id, token_id, ip, ja4, reason, comment, submitted_at)
//     Indexes for (ip, ja4) aggregation + submitted_at expiry.
//
// Assumed to live in a separate file from the main admin DB (= settings.FeedServer.DBPath).
func migrate(db *sql.DB) error {
	stmts := []string{
		`CREATE TABLE IF NOT EXISTS feed_tokens (
			id            INTEGER PRIMARY KEY AUTOINCREMENT,
			secret_hash   TEXT    NOT NULL UNIQUE,
			created_at    INTEGER NOT NULL,
			last_seen_at  INTEGER NOT NULL DEFAULT 0,
			abuse_score   INTEGER NOT NULL DEFAULT 0
		)`,
		`CREATE TABLE IF NOT EXISTS feed_submissions (
			id            INTEGER PRIMARY KEY AUTOINCREMENT,
			token_id      INTEGER NOT NULL,
			ip            TEXT    NOT NULL,
			ja4           TEXT    NOT NULL DEFAULT '',
			reason        TEXT    NOT NULL DEFAULT '',
			comment       TEXT    NOT NULL DEFAULT '',
			submitted_at  INTEGER NOT NULL
		)`,
		`CREATE INDEX IF NOT EXISTS idx_feed_submissions_ip_ja4 ON feed_submissions(ip, ja4)`,
		`CREATE INDEX IF NOT EXISTS idx_feed_submissions_submitted_at ON feed_submissions(submitted_at)`,
	}
	for _, q := range stmts {
		if _, err := db.Exec(q); err != nil {
			return fmt.Errorf("migrate: %w: %s", err, q)
		}
	}
	return nil
}
