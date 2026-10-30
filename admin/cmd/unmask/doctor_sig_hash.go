package main

import (
	"fmt"
	"strings"
	"time"

	"github.com/unmask-sh/unmask/admin/internal/renderwatch"
	"github.com/unmask-sh/unmask/admin/internal/settings"
)

// checkSigHashModule: an install that signs with HMAC-SHA256
// (secret.sig_hash) needs every nginx to run a module that verifies it, the
// 0.1.53 module or newer -- one from before verifies HMAC-SHA1 alone, so it
// refuses every cookie and proof-of-work pass issued now, and visitors are
// challenged again on every page.  The daemon cannot look at nginx's
// processes (ProtectProc=invisible), but the access log tells: a line from a
// module that verifies both carries the module's id (mo=, the render watch
// keeps when each id was last logged), and a line without one is an older
// module -- or an older configuration still running on a new one; the cure,
// a restart, is the same, and the admin's notice says which.  Silence (no
// state, no lines) says nothing.
func checkSigHashModule(s settings.Settings, addOK, addWarn func(t, m string)) {
	if strings.TrimSpace(s.Secret.SigHash) != "sha256" {
		return
	}
	dir := strings.TrimSpace(s.Nginx.OutputDir)
	if dir == "" {
		dir = "/var/lib/unmask/nginx"
	}
	seen, err := renderwatch.LoadModuleSeen(dir)
	if err != nil || len(seen) == 0 {
		return
	}
	var lastNone, lastID time.Time
	for id, at := range seen {
		if id == "" {
			lastNone = at
		} else if at.After(lastID) {
			lastID = at
		}
	}
	if !lastNone.IsZero() && lastNone.After(lastID) {
		addWarn("cookie signature", fmt.Sprintf(
			"secret.sig_hash is sha256, but nginx last logged a line without a module id at %s -- "+
				"a module from before 0.1.53, which verifies HMAC-SHA1 alone and refuses every cookie "+
				"and proof-of-work pass issued now (visitors are challenged again on every page), or a "+
				"configuration from before this release still running. Restart nginx onto the 0.1.53 "+
				"module (the admin's notice says which it is), or set sig_hash back to sha1 until then.",
			lastNone.UTC().Format("2006-01-02 15:04:05 UTC")))
		return
	}
	addOK("cookie signature", "sha256, and nginx logs a module that verifies it")
}
