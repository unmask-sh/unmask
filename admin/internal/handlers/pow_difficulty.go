package handlers

import (
	"net/http"
	"strconv"
	"strings"

	"github.com/unmask-sh/unmask/admin/internal/settings"
)

// The proof-of-work difficulty the challenge page asks for.
//
// With the nginx module, the plugin verifies a PoW cookie at the difficulty
// nginx loaded for the host ($unmask_pow_difficulty in http.inc), which moves
// only when nginx reloads; the daemon's configured value moves the moment
// the setting is saved.  Between the two the page used to ask for the new
// value: after the difficulty was lowered, the plugin refused every answer
// and the visitor was sent back to the challenge, again and again, until
// nginx reloaded.  server.inc hands the daemon the value nginx holds, and the
// page asks for the stricter of the two -- an answer both accept: the plugin
// at its loaded value, and the daemon, which checks a proof at the configured
// one (the _bvj's _bv, a chain's proof, the beacon's pass).  So a lowered
// setting waits for the reload, and a raised one is asked for at once, as it
// always was.
//
// The header only ever raises what the page asks for, and the daemon's own
// checks do not read it.  They did, in the first cut: forward-auth and Apache
// fronts pass a client's X-Unmask-Local-Port and X-Unmask-Pow-Difficulty
// through, so a client there named a difficulty of its own, answered an
// 8-bit proof, and POST /api/bvj minted the credential a re-bind turns into
// a pass.  Sent now, the two headers buy the sender a harder page.

// powDifficultyHeader carries $unmask_pow_difficulty from server.inc.
const powDifficultyHeader = "X-Unmask-Pow-Difficulty"

// pagePowDifficulty is the difficulty the page served for r asks for: the
// stricter of configured and the one nginx verifies at, when the request
// came through the module and names one in range; configured otherwise.
func pagePowDifficulty(r *http.Request, configured int) int {
	if r == nil || !throughModule(r) {
		return configured
	}
	v, err := strconv.Atoi(strings.TrimSpace(r.Header.Get(powDifficultyHeader)))
	if err != nil || v < settings.PowDifficultyMin || v > settings.PowDifficultyMax {
		return configured
	}
	return max(v, configured)
}
