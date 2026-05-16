package feedserver

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"strings"
	"time"
)

// ServeSubmit: POST /api/feed/submit
//
//   header:  Authorization: Bearer <token>
//   request: {"ip":"...", "ja4":"...", "reason":"...", "comment":"..."}
//   response: 204 No Content (= accepted.  Judgment runs later via cron)
//
// Auth: sha256 of token compared to feed_tokens.secret_hash.  On match,
// appends a row to feed_submissions and updates tokens.last_seen_at.
func (s *Server) ServeSubmit(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	tok := bearerToken(r.Header.Get("Authorization"))
	if tok == "" {
		http.Error(w, "missing bearer", http.StatusUnauthorized)
		return
	}
	sum := sha256.Sum256([]byte(tok))
	hash := hex.EncodeToString(sum[:])

	var tokenID int64
	err := s.db.QueryRowContext(r.Context(),
		`SELECT id FROM feed_tokens WHERE secret_hash = ?`, hash).Scan(&tokenID)
	if err != nil {
		// No hit → 401 (= treat sql.ErrNoRows and other errors the same).
		http.Error(w, "invalid token", http.StatusUnauthorized)
		return
	}

	body, err := io.ReadAll(io.LimitReader(r.Body, 8*1024))
	if err != nil {
		http.Error(w, "read body", http.StatusBadRequest)
		return
	}
	var req SubmitRequest
	if err := json.Unmarshal(body, &req); err != nil {
		http.Error(w, "bad json", http.StatusBadRequest)
		return
	}

	ip := strings.TrimSpace(req.IP)
	if ip == "" || net.ParseIP(ip) == nil {
		http.Error(w, "invalid ip", http.StatusBadRequest)
		return
	}
	if len(ip) > MaxIPLen {
		http.Error(w, "ip too long", http.StatusBadRequest)
		return
	}
	ja4 := truncate(strings.TrimSpace(req.JA4), MaxJA4Len)
	reason := truncate(strings.TrimSpace(req.Reason), MaxReasonLen)
	comment := clamp(strings.TrimSpace(req.Comment), MaxCommentLen)

	now := time.Now().Unix()
	if _, err := s.db.ExecContext(r.Context(),
		`INSERT INTO feed_submissions (token_id, ip, ja4, reason, comment, submitted_at) VALUES (?,?,?,?,?,?)`,
		tokenID, ip, ja4, reason, comment, now); err != nil {
		s.logf("feedserver: insert submission: %v", err)
		http.Error(w, "db", http.StatusInternalServerError)
		return
	}
	_, _ = s.db.ExecContext(r.Context(),
		`UPDATE feed_tokens SET last_seen_at = ? WHERE id = ?`, now, tokenID)
	w.WriteHeader(http.StatusNoContent)
}

// bearerToken: split "Bearer <tok>".  Empty string is invalid.
func bearerToken(h string) string {
	const prefix = "Bearer "
	if !strings.HasPrefix(h, prefix) {
		return ""
	}
	return strings.TrimSpace(h[len(prefix):])
}

// clientIP: leftmost IP from X-Forwarded-For if present, else the host part
// of RemoteAddr.  Hub is expected to run behind nginx (= XFF trusted).  Same
// applies to hubs not running on unmask.sh (= direct exposure not recommended).
func clientIP(r *http.Request) string {
	if v := r.Header.Get("X-Forwarded-For"); v != "" {
		if i := strings.IndexByte(v, ','); i > 0 {
			return strings.TrimSpace(v[:i])
		}
		return strings.TrimSpace(v)
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

// truncate: head-truncate by byte length (= for ASCII-only fields).
func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}

// clamp: truncate at rune boundaries (= avoids cutting multibyte / emoji
// comments mid-codepoint).
func clamp(s string, n int) string {
	if len(s) <= n {
		return s
	}
	r := []rune(s)
	if len(r) > n {
		r = r[:n]
	}
	return string(r)
}
