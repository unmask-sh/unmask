// Ephemeral logo preview store for the settings "Page design" tab.
//
// When the operator picks a logo file the browser uploads it here BEFORE
// saving, gets back a short-lived token, and points the challenge / deny
// preview iframes at it (?_preview_logo=<token>).  This lets the previews
// reflect the not-yet-saved image immediately; the real Save button still
// persists it to disk via applyBrandingForm.  Nothing here touches the
// config or the on-disk logo -- entries live in memory, are capped, and
// expire on their own.
package handlers

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"
)

const (
	previewLogoMaxBytes = 4 << 20          // 4 MiB, matching the real logo upload cap
	previewLogoTTL      = 10 * time.Minute // an editing session is short; evict aggressively
	previewLogoMaxEntry = 32               // bound memory: drop the oldest past this many
	previewLogoTokenLen = 16               // bytes -> 32 hex chars
)

// previewLogoEntry is one uploaded image held in memory for the live preview.
type previewLogoEntry struct {
	data []byte
	ct   string // resolved Content-Type (image/png, image/svg+xml, ...)
	ts   time.Time
}

// previewLogoStore is a tiny token->image map with age + count eviction.  Safe
// for concurrent use (the upload and serve handlers run on different requests).
type previewLogoStore struct {
	mu sync.Mutex
	m  map[string]previewLogoEntry
}

// previewLogoStoreOf lazily creates the per-Handler store.  Uses the atomic
// pointer (no extra "sync" import on Handler) with a CAS so a race loses at
// most one empty map allocation.
func (h *Handler) previewLogoStoreOf() *previewLogoStore {
	if s := h.previewLogos.Load(); s != nil {
		return s
	}
	s := &previewLogoStore{m: make(map[string]previewLogoEntry)}
	if h.previewLogos.CompareAndSwap(nil, s) {
		return s
	}
	return h.previewLogos.Load()
}

// put stores data under token, first evicting anything expired and then the
// oldest entry if the store is still at capacity.
func (s *previewLogoStore) put(token string, data []byte, ct string, now time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for k, e := range s.m {
		if now.Sub(e.ts) > previewLogoTTL {
			delete(s.m, k)
		}
	}
	if len(s.m) >= previewLogoMaxEntry {
		var oldestK string
		var oldestT time.Time
		for k, e := range s.m {
			if oldestK == "" || e.ts.Before(oldestT) {
				oldestK, oldestT = k, e.ts
			}
		}
		if oldestK != "" {
			delete(s.m, oldestK)
		}
	}
	s.m[token] = previewLogoEntry{data: data, ct: ct, ts: now}
}

// get returns the entry for token, treating an expired one as absent (and
// reaping it).
func (s *previewLogoStore) get(token string, now time.Time) (previewLogoEntry, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	e, ok := s.m[token]
	if !ok {
		return previewLogoEntry{}, false
	}
	if now.Sub(e.ts) > previewLogoTTL {
		delete(s.m, token)
		return previewLogoEntry{}, false
	}
	return e, true
}

// newPreviewLogoToken mints an unguessable hex token.  Only the auth-gated
// upload endpoint can hand one out, so a token implies an authenticated origin.
func newPreviewLogoToken() (string, error) {
	var b [previewLogoTokenLen]byte
	if _, err := io.ReadFull(rand.Reader, b[:]); err != nil {
		return "", err
	}
	return hex.EncodeToString(b[:]), nil
}

// isPreviewLogoToken validates the token shape (exactly the hex we mint) so an
// operator-supplied ?_preview_logo value is never interpolated raw into a URL.
func isPreviewLogoToken(s string) bool {
	if len(s) != previewLogoTokenLen*2 {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
}

// logoContentType maps a (lowercased) file extension to the image Content-Type
// the allowlist serves; "" for anything not allowed.
func logoContentType(ext string) string {
	switch strings.ToLower(ext) {
	case ".svg":
		return "image/svg+xml"
	case ".png":
		return "image/png"
	case ".jpg", ".jpeg":
		return "image/jpeg"
	case ".webp":
		return "image/webp"
	case ".gif":
		return "image/gif"
	}
	return ""
}

// previewLogoURL builds the URL that serves a preview token, given the admin
// base path.  Centralized so the challenge + deny render paths agree.
func (h *Handler) previewLogoURL(token string) string {
	return h.basePath() + "/admin/test/preview-logo?t=" + token
}

// PreviewLogoUpload: POST {base}/admin/test/preview-logo
//
// Accepts a multipart "branding_logo_file", validates + sanitizes it exactly
// like the real branding save (extension allowlist, 4 MiB cap, SVG script
// strip), stashes it in memory under a fresh token, and returns
// {"token","url"} JSON.  Admin-only + CSRF (the init_csrf fetch shim supplies
// the header).  Nothing is written to disk or config -- this is preview only.
func (h *Handler) PreviewLogoUpload(w http.ResponseWriter, r *http.Request) {
	// Cap the whole multipart body so an oversized upload can't balloon memory or
	// spill to disk inside ParseMultipartForm before the per-file 4 MiB read; the
	// envelope (boundaries / field names) needs a little headroom over the cap.
	r.Body = http.MaxBytesReader(w, r.Body, previewLogoMaxBytes+(1<<20))
	f, fh, err := r.FormFile("branding_logo_file")
	if err != nil || f == nil {
		http.Error(w, "no file", http.StatusBadRequest)
		return
	}
	defer func() { _ = f.Close() }()
	ext, ok := pickLogoExt(fh.Filename)
	if !ok {
		http.Error(w, "unsupported extension", http.StatusBadRequest)
		return
	}
	ct := logoContentType(ext)
	if ct == "" {
		http.Error(w, "unsupported extension", http.StatusBadRequest)
		return
	}
	data, err := io.ReadAll(io.LimitReader(f, previewLogoMaxBytes))
	if err != nil {
		http.Error(w, "read failed", http.StatusBadRequest)
		return
	}
	if ext == ".svg" {
		data = sanitizeSVG(data)
	}
	token, err := newPreviewLogoToken()
	if err != nil {
		http.Error(w, "token mint failed", http.StatusInternalServerError)
		return
	}
	h.previewLogoStoreOf().put(token, data, ct, time.Now())
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	_ = json.NewEncoder(w).Encode(map[string]string{
		"token": token,
		"url":   h.previewLogoURL(token),
	})
}

// PreviewLogoServe: GET {base}/admin/test/preview-logo?t=<token>
//
// Streams a previously-uploaded preview image.  Admin-only.  404 for an
// unknown / expired token.  An uploaded SVG is locked down with the same CSP
// the real logo route uses, so it cannot run script when fetched as a document.
func (h *Handler) PreviewLogoServe(w http.ResponseWriter, r *http.Request) {
	token := strings.TrimSpace(r.URL.Query().Get("t"))
	if !isPreviewLogoToken(token) {
		http.NotFound(w, r)
		return
	}
	e, ok := h.previewLogoStoreOf().get(token, time.Now())
	if !ok {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", e.ct)
	// Never let the browser MIME-sniff the bytes (a raster extension could carry
	// HTML); and sandbox every preview, not just SVG, so a polyglot stays inert.
	w.Header().Set("X-Content-Type-Options", "nosniff")
	csp := "default-src 'none'; sandbox"
	if e.ct == "image/svg+xml" {
		csp = "default-src 'none'; style-src 'unsafe-inline'; sandbox"
	}
	w.Header().Set("Content-Security-Policy", csp)
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Robots-Tag", "noindex, nofollow, noarchive")
	_, _ = w.Write(e.data)
}
