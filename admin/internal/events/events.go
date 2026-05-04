// Package events: unmask_event テーブルへの INSERT / 集計 helper.
package events

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"log"
	"net"

	"github.com/unmask-sh/unmask/admin/internal/db"
)

type Phase string

const (
	PhaseServe     Phase = "serve"
	PhaseLoad      Phase = "load"
	PhasePoW       Phase = "pow"
	PhaseCaptcha   Phase = "captcha"
	PhaseVerifyOK  Phase = "verify_ok"
	PhaseVerifyNG  Phase = "verify_ng"
	PhaseError     Phase = "error"
	PhaseCookieErr Phase = "cookie_err"
)

var allowedPhases = map[string]bool{
	"serve": true, "load": true, "pow": true, "captcha": true,
	"verify_ok": true, "verify_ng": true, "error": true, "cookie_err": true,
}

func IsValidPhase(p string) bool { return allowedPhases[p] }

// PackIP returns the binary representation of an IPv4 (4B) or IPv6 (16B)
// address, or nil if `s` is not parseable.
func PackIP(s string) []byte {
	if s == "" {
		return nil
	}
	ip := net.ParseIP(s)
	if ip == nil {
		return nil
	}
	if v4 := ip.To4(); v4 != nil {
		out := make([]byte, 4)
		copy(out, v4)
		return out
	}
	out := make([]byte, 16)
	copy(out, ip.To16())
	return out
}

type Event struct {
	Site        string // "" → "default" として INSERT
	IPPacked    []byte
	UserAgent   string
	JA4         string
	JA4Verdict  string
	Phase       string
	Flags       int
	ReloadCount int
	CookieBV    string
	CookieBR    string
	Payload     map[string]any
}

// Insert writes one row into unmask_event.  Best-effort: failures only log.
func Insert(ctx context.Context, d *db.DB, e *Event) error {
	if !IsValidPhase(e.Phase) {
		return errors.New("invalid phase: " + e.Phase)
	}

	ua := truncate(e.UserAgent, 255)
	ja4 := nullIfEmpty(e.JA4)
	verdict := nullIfEmpty(e.JA4Verdict)
	cookieBV := nullIfEmpty(e.CookieBV)
	cookieBR := nullIfEmpty(e.CookieBR)

	var payloadText sql.NullString
	if e.Payload != nil {
		buf, err := json.Marshal(e.Payload)
		if err == nil {
			s := string(buf)
			if len(s) > 4000 {
				s = s[:4000]
			}
			payloadText = sql.NullString{String: s, Valid: true}
		}
	}

	site := e.Site
	if site == "" {
		site = "default"
	}

	const stmt = `INSERT INTO unmask_event
        (site, ip_address, user_agent, ja4, ja4_verdict, phase, flags, reload_count,
         cookie_bv, cookie_br, payload_json)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
	_, err := d.ExecContext(ctx, stmt,
		site, e.IPPacked, sqlStr(ua), ja4, verdict, e.Phase,
		e.Flags, e.ReloadCount, cookieBV, cookieBR, payloadText,
	)
	if err != nil {
		log.Printf("unmask_event insert failed: %v", err)
		return err
	}
	return nil
}

// CountRecentByIP returns how many events from `ipPacked` happened in the
// last `minutes` minutes.  Used to enforce per-IP debug rate limit.
func CountRecentByIP(ctx context.Context, d *db.DB, ipPacked []byte, minutes int) (int, error) {
	stmt := `SELECT COUNT(*) FROM unmask_event WHERE ip_address = ? AND date_created > ` +
		d.NowMinusMinutes(minutes)
	row := d.QueryRowContext(ctx, stmt, ipPacked)
	var n int
	if err := row.Scan(&n); err != nil {
		return 0, err
	}
	return n, nil
}

func truncate(s string, n int) string {
	if len(s) > n {
		return s[:n]
	}
	return s
}

func nullIfEmpty(s string) sql.NullString {
	if s == "" {
		return sql.NullString{}
	}
	return sql.NullString{String: s, Valid: true}
}

// sqlStr is like nullIfEmpty but for UA where empty string is also allowed.
func sqlStr(s string) sql.NullString { return nullIfEmpty(s) }
