package handlers

import (
	"net/http"
	"strconv"
	"strings"

	"github.com/unmask-sh/unmask/admin/internal/settings"
)

// The proof-of-work difficulty a request is to be answered at.
//
// With the nginx module, the plugin verifies a PoW cookie at the difficulty
// nginx loaded for the host ($unmask_pow_difficulty in http.inc), which moves
// only when nginx reloads; the daemon's configured value moves the moment
// the setting is saved.  Between the two the page used to ask for the new
// value: after the difficulty was lowered, the plugin refused every answer
// and the visitor was sent back to the challenge, again and again, until
// nginx reloaded.  server.inc hands the daemon the value nginx holds, and on
// a request through the module the page, and every check the daemon makes of
// a PoW cookie on that request, use it -- so a change of difficulty takes
// effect at the reload, up or down, as the reload notice says.  Elsewhere
// (forward-auth, Apache, a request straight to the daemon) the daemon is the
// verifier, and its configured value is the one.
//
// A client can send the header to the daemon only where it reaches the
// daemon directly; nginx overwrites it.  What it buys there is a page whose
// answer its verifier refuses.

// powDifficultyHeader carries $unmask_pow_difficulty from server.inc.
const powDifficultyHeader = "X-Unmask-Pow-Difficulty"

// powDifficultyFor is the difficulty to serve and check r at: the one nginx
// verifies at, on a request through the module that names a valid one, and
// configured otherwise.
func powDifficultyFor(r *http.Request, configured int) int {
	if r == nil || !throughModule(r) {
		return configured
	}
	v, err := strconv.Atoi(strings.TrimSpace(r.Header.Get(powDifficultyHeader)))
	if err != nil || v < settings.PowDifficultyMin || v > settings.PowDifficultyMax {
		return configured
	}
	return v
}
