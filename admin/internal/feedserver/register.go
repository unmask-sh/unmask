package feedserver

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"time"
)

// ServeRegister: POST /api/feed/register
//
//	request:  {"unmask_version":"..."}  ← body unused (= stats only)
//	response: {"token":"<hex 64 char>"}  ← raw token. client stores in config.yml.
//
// Repeated registers from the same source IP within RegisterRateMu seconds are
// rejected (= 429).  IP = leftmost X-Forwarded-For if present, else RemoteAddr.
//
// The raw secret token is never stored on the server (= sha256 hash only).
// Clients that lose the token just register again.
func (s *Server) ServeRegister(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	ip := clientIP(r)
	if !s.checkRegisterRate(ip) {
		http.Error(w, "rate limited", http.StatusTooManyRequests)
		return
	}

	// Body can be ignored, but we still decode it to reject malformed JSON with 400.
	var req RegisterRequest
	if r.ContentLength > 0 {
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "bad json", http.StatusBadRequest)
			return
		}
	}

	raw := make([]byte, TokenByteLen)
	if _, err := rand.Read(raw); err != nil {
		http.Error(w, "rand", http.StatusInternalServerError)
		return
	}
	rawHex := hex.EncodeToString(raw)
	sum := sha256.Sum256([]byte(rawHex))
	hash := hex.EncodeToString(sum[:])

	now := time.Now().Unix()
	_, err := s.db.ExecContext(r.Context(),
		`INSERT INTO feed_tokens (secret_hash, created_at, last_seen_at) VALUES (?,?,?)`,
		hash, now, now)
	if err != nil {
		s.logf("feedserver: insert token: %v", err)
		http.Error(w, "db", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(RegisterResponse{Token: rawHex})
}

// checkRegisterRate: per-IP rate limit (= 1 entry per RegisterRateMu seconds).
// Holds the last register time in a map; returns true + updates if stale.
// Concurrent access protected by s.mu.  Purges old entries once the map
// exceeds 10,000.
func (s *Server) checkRegisterRate(ip string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now()
	if last, ok := s.regByIP[ip]; ok {
		if now.Sub(last) < time.Duration(RegisterRateMu)*time.Second {
			return false
		}
	}
	s.regByIP[ip] = now
	if len(s.regByIP) > 10000 {
		cut := now.Add(-time.Hour)
		for k, v := range s.regByIP {
			if v.Before(cut) {
				delete(s.regByIP, k)
			}
		}
	}
	return true
}
