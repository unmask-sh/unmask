package handlers

import (
	"crypto/rand"
	"encoding/hex"
	"net/url"
	"strings"
	"sync"
	"time"
)

// A rejected settings save hands the operator's rows to the page it redirects
// to (setSectionDraft) in a flash cookie.  A browser keeps a cookie of about
// 4 KB, name and attributes included, so a long list -- a few dozen bypass
// addresses with notes -- did not fit: the draft was dropped and the error
// page showed the saved list, the operator's input gone.  A draft that does
// not fit is kept here instead, and the cookie carries its id.  One that fits
// still travels in the cookie, which also reaches a redirect another node
// serves.
const (
	// draftCookieMax: the most bytes of escaped value a draft cookie may
	// carry, leaving room for its name and attributes under the browser's
	// limit.  The escaped size is what counts: a 4004-byte draft escaped to
	// 4448 bytes and was dropped.
	draftCookieMax = 3800
	// draftStoreMaxBytes: no draft larger than this is kept (the form that
	// produced it is a single settings tab).
	draftStoreMaxBytes = 1 << 20
	draftStoreTTL      = 5 * time.Minute
	draftStoreMax      = 128
	draftStorePrefix   = "id:"
)

type storedDraft struct {
	data    string
	expires time.Time
}

var draftStore = struct {
	sync.Mutex
	m map[string]storedDraft
}{m: map[string]storedDraft{}}

// draftFlashValue returns what the flash cookie carries for a draft: the
// draft itself when it fits, else the id of a copy kept in draftStore ("" when
// it cannot be kept either).
func draftFlashValue(draft string) string {
	if len(url.QueryEscape(draft)) <= draftCookieMax {
		return draft
	}
	if len(draft) > draftStoreMaxBytes {
		return ""
	}
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return ""
	}
	id := hex.EncodeToString(b[:])
	now := time.Now()
	draftStore.Lock()
	defer draftStore.Unlock()
	for k, d := range draftStore.m {
		if now.After(d.expires) {
			delete(draftStore.m, k)
		}
	}
	for len(draftStore.m) >= draftStoreMax {
		oldest, first := "", time.Time{}
		for k, d := range draftStore.m {
			if oldest == "" || d.expires.Before(first) {
				oldest, first = k, d.expires
			}
		}
		delete(draftStore.m, oldest)
	}
	draftStore.m[id] = storedDraft{data: draft, expires: now.Add(draftStoreTTL)}
	return draftStorePrefix + id
}

// draftFromFlash turns what the flash cookie carried back into the draft: the
// value itself, or the kept copy its id names (taken once: a second read
// finds nothing, as the cookie is shown once).
func draftFromFlash(raw string) string {
	id, kept := strings.CutPrefix(raw, draftStorePrefix)
	if !kept {
		return raw
	}
	draftStore.Lock()
	defer draftStore.Unlock()
	d, ok := draftStore.m[id]
	delete(draftStore.m, id)
	if !ok || time.Now().After(d.expires) {
		return ""
	}
	return d.data
}
