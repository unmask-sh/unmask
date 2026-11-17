package events

import (
	"net/url"
	"path"
	"strings"
	"sync/atomic"
)

// defaultOwnAdminPath is the admin UI's path on an install that keeps the
// shipped base path.
const defaultOwnAdminPath = "/unmask/admin"

// ownAdminPath is the path the admin UI is served under: the base path plus
// "/admin" (SetOwnAdminPath).
var ownAdminPath atomic.Pointer[string]

// SetOwnAdminPath names the path of the admin UI, base path included
// ("/unmask/admin"), for scrubOwnAdminURLs.  The daemon sets it once at
// startup -- the base path is read when it starts -- and until then the
// shipped one stands.
func SetOwnAdminPath(p string) {
	p = strings.TrimRight(strings.TrimSpace(p), "/")
	if p == "" {
		p = defaultOwnAdminPath
	}
	ownAdminPath.Store(&p)
}

// urlPayloadKeys: the payload fields that carry a page's address with its
// query -- the page the visitor asked for (orig_path, and uri on a
// forward-auth check), the address the challenge page reports (url) and the
// page the visitor came from (referer).
var urlPayloadKeys = []string{"orig_path", "uri", "url", "referer"}

// scrubOwnAdminURLs cuts the query off every address in the payload that
// names a page of unmask's own admin UI.
//
// The admin UI is a protected path by default, so a browser without a pass
// meets the challenge on its way to it, and the row of that serve carries
// the address it asked for.  A password-reset or account-setup link has its
// token in the query, and the token alone sets the password: every role
// reads the event log -- the hunt page, the live tail, the AI tools -- so a
// viewer could read an invited superadmin's token there and set the password
// first.  Nothing the log is read for needs the query of unmask's own pages,
// so it is not stored, whichever handler writes the row.
//
// Every writer goes through Insert or InsertAsync, which call this before
// anything else sees the event.
func scrubOwnAdminURLs(e *Event) {
	if e == nil || len(e.Payload) == 0 {
		return
	}
	admin := defaultOwnAdminPath
	if p := ownAdminPath.Load(); p != nil {
		admin = *p
	}
	for _, k := range urlPayloadKeys {
		v, ok := e.Payload[k].(string)
		if !ok || v == "" {
			continue
		}
		if s := withoutOwnAdminQuery(v, admin); s != v {
			e.Payload[k] = s
		}
	}
}

// withoutOwnAdminQuery returns v without its query and fragment when it
// names a page of the admin UI served under admin: as its own path, or --
// where the web server redirects to the challenge page, which then stands at
// <base>/challenge/?_orig=<the page asked for> -- in the query of another of
// unmask's pages.  v is a path with its query or a whole URL (the Referer).
// Any other address comes back as it is.
func withoutOwnAdminQuery(v, admin string) string {
	i := strings.IndexAny(v, "?#")
	if i < 0 {
		return v
	}
	p := v[:i]
	if j := strings.Index(p, "://"); j >= 0 {
		// A whole URL: the path starts at the first slash after the host.
		p = p[j+3:]
		if k := strings.IndexByte(p, '/'); k >= 0 {
			p = p[k:]
		} else {
			p = "/"
		}
	}
	if pathUnder(p, admin) {
		return v[:i]
	}
	if base := strings.TrimSuffix(admin, "/admin"); base != admin && pathUnder(p, base) && queryNamesPath(v[i:], admin) {
		return v[:i]
	}
	return v
}

// pathUnder reports whether p is dir or a page under it, read the way nginx
// reads a path to pick the location that serves it: percent-decoded, with
// the dot segments resolved and repeated slashes merged.  The address in a
// row is the one the client sent, so "/unmask//admin/x" and
// "/unmask/%61dmin/x" reach the admin UI like "/unmask/admin/x" does.
func pathUnder(p, dir string) bool {
	if d, err := url.PathUnescape(p); err == nil {
		p = d
	}
	p = path.Clean("/" + p)
	return p == dir || strings.HasPrefix(p, dir+"/")
}

// queryNamesPath reports whether the query q carries dir, escaped up to twice
// (an _orig the web server escaped, in a Referer the browser escaped again).
// A plain substring: under unmask's own pages nothing else starts like the
// admin UI's path, and a query cut for nothing costs nothing.
func queryNamesPath(q, dir string) bool {
	for n := 0; n < 3; n++ {
		if strings.Contains(q, dir) {
			return true
		}
		d, err := url.QueryUnescape(q)
		if err != nil || d == q {
			return false
		}
		q = d
	}
	return false
}
