// The challenge script as it goes out: beside the page, under a name that
// carries its hash, or inside the page.
//
// The page used to carry the script whole on every serve.  Most serves go to
// clients that run no script -- they take the page and leave -- and the script
// was four fifths of what each of them was sent.  It now goes out once per
// browser, from a file a browser may keep for a year; the page names it.
//
// What the page-with-the-script-inside gave is kept by other means:
//
//   - The script and the page are of one build.  The file's name is the hash
//     of its content and the daemon answers for its own script's name alone,
//     so a page can only ever load the script it was written with; a node of
//     another build, or a file left over from one, answers 404.
//   - A browser that cannot get the file is not left on a challenge that never
//     runs.  The page's own small script watches the load: when it fails, or
//     nothing has started after a wait, it sets scriptInPageCookie and asks for
//     the page again, and the daemon answers a request that carries the cookie
//     with the script inside the page, as before.
package handlers

import (
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"log"
	"net/http"
	"strconv"
	"strings"

	"github.com/unmask-sh/unmask/admin/internal/jsstrip"
	"github.com/unmask-sh/unmask/admin/internal/settings"
)

const (
	// scriptInPageCookie is the cookie the page's own script sets before it
	// asks for the page again: the browser could not get the script as a
	// file, so this serve, and the ones of the hour after it, carry it
	// inside the page.  A request, never a credential: a client that sends
	// it gets the larger page.
	scriptInPageCookie = "_bvi"
	// jsInlinePlaceholder is where challenge.html's window.UNMASK says
	// whether this page carries the script (1) or names a file (0).  The
	// HTML's own 1 is what an unsubstituted page says: its script then never
	// asks for another page.  A page without the placeholder -- an
	// operator's copy from before it -- has no script that would ask, and
	// is served with challenge.js inside, as it always was.
	jsInlinePlaceholder = `/*__JS_INLINE__*/1`
	// challengeScriptID marks the <script> of the file, for the page's own
	// script to tell its load from any other's.
	challengeScriptID = "unmask-js"
)

// servedScript is challenge.js in the form it is served in.
type servedScript struct {
	src    []byte // as loaded: an operator's file is compared against it
	custom bool   // the operator's own file (challenge_js_path)
	body   []byte // as served
	inline []byte // body, safe between <script> tags
	gz     []byte // body, gzip
	name   string // its file name under /static/: challenge.<hash>.js
}

func newServedScript(src []byte, custom bool) *servedScript {
	body := src
	if !custom {
		// The built-in script goes out without its comments (jsstrip): they
		// are close to half of it on the wire.  An operator's own file is
		// served as written -- it is theirs, and this build has not read it.
		if out, ok := jsstrip.LineComments(src); ok {
			body = out
		} else {
			log.Printf("challenge.js: served with its comments (the pass that removes them could not read the script)")
		}
	}
	sum := sha256.Sum256(body)
	var gz bytes.Buffer
	zw, _ := gzip.NewWriterLevel(&gz, gzip.BestCompression)
	_, _ = zw.Write(body)
	_ = zw.Close()
	return &servedScript{
		src:    src,
		custom: custom,
		body:   body,
		// "</script" inside the script would end the inline block early.
		inline: bytes.ReplaceAll(body, []byte("</script"), []byte(`<\/script`)),
		gz:     gz.Bytes(),
		name:   "challenge." + hex.EncodeToString(sum[:8]) + ".js",
	}
}

// challengeScript returns the script as served.  The built-in one is worked
// out once; an operator's file is read on every call, as loadChallengeJS
// always did, and worked out again when it has changed.
func (h *Handler) challengeScript() (*servedScript, error) {
	custom := h.cfg().Challenge.Default.ChallengeJSPath != ""
	cur := h.chScript.Load()
	if cur != nil && !custom && !cur.custom {
		return cur, nil
	}
	src, err := h.loadChallengeJS()
	if err != nil {
		return nil, err
	}
	if cur != nil && cur.custom == custom && bytes.Equal(cur.src, src) {
		return cur, nil
	}
	s := newServedScript(src, custom)
	h.chScript.Store(s)
	return s, nil
}

// scriptInPage reports whether this serve carries challenge.js inside the
// page rather than naming the file, and whether that is the browser's asking
// (the serve event says so: how often is what tells whether the file reaches
// the browsers it is sent to).
func (h *Handler) scriptInPage(r *http.Request, page []byte, ch settings.ChallengeValues) (inPage, asked bool) {
	switch {
	case ch.IsChallengeJSInline():
		// The operator's choice (challenge_js_inline).
		return true, false
	case !bytes.Contains(page, []byte(jsInlinePlaceholder)):
		// A copy of the page from before the file: nothing in it would ask
		// for the script another way.
		return true, false
	case !throughModule(r):
		// Not through the module's server.inc, which sets its header on
		// every request it hands the daemon.  Forward-auth is frozen and
		// keeps the page it had, and so do Apache and a request made of
		// the daemon directly.
		return true, false
	}
	if c, err := r.Cookie(scriptInPageCookie); err == nil && c.Value != "" {
		// The browser asked: it could not get the file.
		return true, true
	}
	return false, false
}

// ServeChallengeJS: GET {base}/static/challenge.js
//
// The script under its plain name, for a copy of the page that names it so
// (an operator's, from before the hashed name).  Cached for ten minutes: the
// name does not change with the content.
func (h *Handler) ServeChallengeJS(w http.ResponseWriter, r *http.Request) {
	s, err := h.challengeScript()
	if err != nil {
		log.Printf("challenge.js load failed: %v", err)
		http.Error(w, "challenge.js unavailable", http.StatusInternalServerError)
		return
	}
	s.write(w, r, "public, max-age=600")
}

// ServeChallengeJSNamed: GET {base}/static/{asset}
//
// The script under the name the page gave it, challenge.<hash>.js.  The name
// is the content, so the answer never changes and a browser or a CDN may keep
// it.  Any other name -- another build's script, asked of this node while a
// fleet is half upgraded -- is not here: 404, uncached, and the page that
// asked falls back to the script inside the page.
func (h *Handler) ServeChallengeJSNamed(w http.ResponseWriter, r *http.Request) {
	s, err := h.challengeScript()
	if err != nil || r.PathValue("asset") != s.name {
		if err != nil {
			log.Printf("challenge.js load failed: %v", err)
		}
		w.Header().Set("Cache-Control", "no-store")
		http.NotFound(w, r)
		return
	}
	s.write(w, r, "public, max-age=31536000, immutable")
}

// write sends the script, compressed when the client takes gzip.  The daemon
// compresses it itself, once: nginx compresses text/html out of the box and a
// script only where the operator listed its type (gzip_types), so the file
// would have gone out several times the size the page-with-script did.
func (s *servedScript) write(w http.ResponseWriter, r *http.Request, cache string) {
	hd := w.Header()
	hd.Set("Content-Type", "application/javascript; charset=utf-8")
	hd.Set("Cache-Control", cache)
	hd.Set("X-Content-Type-Options", "nosniff")
	hd.Set("Vary", "Accept-Encoding")
	body := s.body
	if acceptsGzip(r) {
		hd.Set("Content-Encoding", "gzip")
		body = s.gz
	}
	hd.Set("Content-Length", strconv.Itoa(len(body)))
	_, _ = w.Write(body)
}

// acceptsGzip reports whether the request's Accept-Encoding takes gzip.
func acceptsGzip(r *http.Request) bool {
	for _, part := range strings.Split(r.Header.Get("Accept-Encoding"), ",") {
		name, params, _ := strings.Cut(part, ";")
		if !strings.EqualFold(strings.TrimSpace(name), "gzip") {
			continue
		}
		if q, ok := strings.CutPrefix(strings.ToLower(strings.TrimSpace(params)), "q="); ok {
			if v, err := strconv.ParseFloat(strings.TrimSpace(q), 64); err == nil && v <= 0 {
				return false
			}
		}
		return true
	}
	return false
}
