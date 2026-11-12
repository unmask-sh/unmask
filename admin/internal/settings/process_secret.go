package settings

import "sync"

// processSecrets holds what this process generated for a secret that neither
// config.yml nor a sidecar file supplied, by what it is for.  Load runs more
// than once in a daemon -- inside every settings save, and whenever
// config.yml changes on disk -- and each run used to draw a new random
// value: where the sidecar could not be read or written, the first save
// swapped the admin's key and the _bv key under everyone (every session
// ended, every pass issued stopped verifying), and the CAPTCHA key, which has
// no sidecar at all, moved on every load until a save wrote it down.  A
// value that cannot be persisted is at least the same one for as long as the
// process lives.
var processSecrets = struct {
	sync.Mutex
	m map[string]string
}{m: map[string]string{}}

// processSecret returns the process's generated secret for key, drawing it
// on first use.
func processSecret(key string) string {
	processSecrets.Lock()
	defer processSecrets.Unlock()
	if v, ok := processSecrets.m[key]; ok {
		return v
	}
	v := randomHex(24)
	processSecrets.m[key] = v
	return v
}
