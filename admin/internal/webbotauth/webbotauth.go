// Web Bot Auth verification (= RFC 9421 HTTP Message Signatures applied to
// bot traffic).  Lets a request prove its bot identity cryptographically
// instead of via easily-spoofed User-Agent and rDNS lookups.
//
// Wire shape (= per draft-meunier-web-bot-auth-architecture-05):
//
//	Signature:        sig1=:<base64 signature>:
//	Signature-Input:  sig1=("@authority" "signature-agent";key="agent1")
//	                   ;created=<unix>;expires=<unix>
//	                   ;keyid="<base64url-jwk-thumbprint>"
//	                   ;alg="ed25519";nonce="<base64url-random>"
//	                   ;tag="web-bot-auth"
//	Signature-Agent:  agent1="https://operator.example/"
//
// Verification:
//
//  1. Parse Signature{-Input,-Agent}.  Reject when tag != "web-bot-auth"
//     or now ∉ [created, expires].
//  2. Fetch <agent>/.well-known/http-message-signatures-directory once
//     (cached for CacheTTL).  Pick the key whose JWK thumbprint matches
//     the signature's keyid.
//  3. Recompute the signature base from the covered components and verify
//     with ed25519 or rsa-pss-sha512 (the two algorithms named in the spec).
//
// We intentionally keep this self-contained (no third-party deps) so the
// admin binary stays pure-Go static.  Other Web Bot Auth implementations
// (Cloudflare Caddy plugin, Castle.io blog walkthrough) were used as
// cross-references for the wire shape; no code was copied from them.
package webbotauth

import (
	"context"
	"crypto"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

// DefaultCacheTTL: in-memory directory cache lifetime.  An hour is a good
// compromise — keys rotate weekly-ish and we'd rather not hammer operator
// directories on every request.
const DefaultCacheTTL = time.Hour

// NonceGCInterval: how often the seen-nonces map is swept for expired
// entries.  GC is inline on the Verify hot path, throttled so most calls
// pay only a single map lookup + insert.
const NonceGCInterval = time.Minute

// NonceFallbackHorizon: storage horizon for nonces whose signature didn't
// carry an `expires` parameter.  Anything older is fair game for re-use,
// matching the Web Bot Auth spec's 24h max recommendation.
const NonceFallbackHorizon = 24 * time.Hour

// DefaultHTTPTimeout: per-directory-fetch timeout.
const DefaultHTTPTimeout = 5 * time.Second

// MaxDirectoryBytes: response-size ceiling for a directory.  Keys are tiny;
// this cap is here to refuse pathological responses, not to bound legit data.
const MaxDirectoryBytes = 256 * 1024

// WellKnownPath: per draft-meunier-http-message-signatures-directory-05.
const WellKnownPath = "/.well-known/http-message-signatures-directory"

// Result: outcome of one Verify call.  OK==false carries a human-readable
// Reason so the event log can show why a candidate signature was rejected
// (= useful when an operator misconfigures their directory).
type Result struct {
	OK        bool
	Operator  string // = agent URL host (when verified)
	KeyID     string // = JWK thumbprint that matched
	Algorithm string // = "ed25519" (only one shipped)
	Reason    string // = empty on success
}

// Verifier: stateful checker.  Construct via New(); Verify is goroutine-safe.
type Verifier struct {
	HTTPClient *http.Client
	CacheTTL   time.Duration
	Now        func() time.Time
	Logger     interface {
		Printf(format string, args ...any)
	}

	// AllowOperator, when non-nil, gates the directory fetch: a
	// Signature-Agent whose host is not allowlisted never triggers an
	// outbound request.  The fetch runs before signature verification, so
	// without this gate an unauthenticated caller can point the fetch at
	// arbitrary URLs (SSRF).  nil disables the gate (used by tests only;
	// production wires it to the operator allowlist).
	AllowOperator func(host string) bool

	// AllowPrivateDial drops the non-public-address dial refusal from the
	// default client, for operators whose key directory lives on a private
	// network (= settings web_bot_auth.allow_private_networks).  Every other
	// hardening stays: https-only agent URLs, no redirects, TLS verification
	// against the system roots, timeouts.  Ignored when HTTPClient is set.
	AllowPrivateDial bool

	mu    sync.RWMutex
	cache map[string]cachedDir // key = agent URL string

	// nonceMu guards both seenNonces and lastNonceGC.  Single mutex is fine
	// — Verify's hot path is dominated by HTTP fetch + ed25519 verify, not
	// by this hashtable.  In a multi-admin (= shared MariaDB) deployment
	// each host has its own map and a determined attacker could replay
	// against a sibling host within a window; cross-host nonce sharing is
	// v0.3+ work.
	nonceMu     sync.Mutex
	seenNonces  map[string]int64 // key=nonce, value=expires unix sec
	lastNonceGC time.Time
}

type cachedDir struct {
	keys      []directoryKey
	fetchedAt time.Time
}

// directoryKey: subset of JWK we care about.  Covers RFC 8037 OKP/Ed25519
// (kty / crv / x) and RFC 7517 RSA (kty / n / e).  The two algorithm
// families share the same directory shape; the verifier dispatches on kty.
type directoryKey struct {
	Kty string `json:"kty"`
	Crv string `json:"crv,omitempty"` // Ed25519
	Kid string `json:"kid"`
	X   string `json:"x,omitempty"` // Ed25519 public-key bytes (base64url)
	N   string `json:"n,omitempty"` // RSA modulus (base64url big-endian)
	E   string `json:"e,omitempty"` // RSA public exponent (base64url big-endian)
	Use string `json:"use"`
	Nbf int64  `json:"nbf,omitempty"`
	Exp int64  `json:"exp,omitempty"`
}

// matchedKey carries whichever algorithm-family parsed cleanly out of a
// directory entry.  Used by findKeyByID + Verify to dispatch.
type matchedKey struct {
	ed25519Pub ed25519.PublicKey
	rsaPub     *rsa.PublicKey
}

// canHandle reports whether this key supports the given alg.
func (m matchedKey) canHandle(alg string) bool {
	switch alg {
	case "ed25519":
		return m.ed25519Pub != nil
	case "rsa-pss-sha512":
		return m.rsaPub != nil
	}
	return false
}

// verify dispatches into the correct algorithm.
func (m matchedKey) verify(alg string, base, sig []byte) bool {
	switch alg {
	case "ed25519":
		if m.ed25519Pub == nil {
			return false
		}
		return ed25519.Verify(m.ed25519Pub, base, sig)
	case "rsa-pss-sha512":
		if m.rsaPub == nil {
			return false
		}
		// RFC 9421 §3.3.4: rsa-pss-sha512 uses MGF1-SHA512 and salt length
		// equal to the digest length (= 64).  crypto/rsa's
		// PSSSaltLengthEqualsHash matches that.
		sum := sha512.Sum512(base)
		opts := &rsa.PSSOptions{
			SaltLength: rsa.PSSSaltLengthEqualsHash,
			Hash:       crypto.SHA512,
		}
		return rsa.VerifyPSS(m.rsaPub, crypto.SHA512, sum[:], sig, opts) == nil
	}
	return false
}

// directoryDoc: the published JSON shape.  The current draft is loose about
// whether "keys" is a single object or an array; we accept both.
type directoryDoc struct {
	Keys json.RawMessage `json:"keys"`
}

// New returns a Verifier with default knobs.
func New() *Verifier { return &Verifier{cache: map[string]cachedDir{}} }

func (v *Verifier) httpClient() *http.Client {
	if v.HTTPClient != nil {
		return v.HTTPClient
	}
	// The directory URL is attacker-influenced (Signature-Agent header), so
	// the default client is hardened against SSRF: it refuses redirects and
	// refuses to dial any non-public address (loopback / private / link-local
	// incl. the 169.254.169.254 cloud-metadata endpoint / CGNAT).  The dial
	// guard runs on the resolved IP, so DNS-rebinding is covered too.
	// AllowPrivateDial (= web_bot_auth.allow_private_networks) drops only the
	// address refusal; redirects, TLS verification, and timeouts stay.
	dial := safeDialContext
	if v.AllowPrivateDial {
		dial = (&net.Dialer{Timeout: DefaultHTTPTimeout}).DialContext
	}
	return &http.Client{
		Timeout: DefaultHTTPTimeout,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return errors.New("directory fetch must not redirect")
		},
		Transport: &http.Transport{
			DialContext:           dial,
			TLSHandshakeTimeout:   DefaultHTTPTimeout,
			ResponseHeaderTimeout: DefaultHTTPTimeout,
			DisableKeepAlives:     true,
		},
	}
}

// cgnatNet is the RFC 6598 shared-address (carrier-grade NAT) range, which
// net.IP.IsPrivate does not cover but which is still non-public.
var cgnatNet = func() *net.IPNet {
	_, n, _ := net.ParseCIDR("100.64.0.0/10")
	return n
}()

// isBlockedDialIP reports whether an IP must not be dialed for a directory
// fetch (= anything that is not a public address).
func isBlockedDialIP(ip net.IP) bool {
	return ip == nil ||
		ip.IsLoopback() ||
		ip.IsPrivate() ||
		ip.IsLinkLocalUnicast() ||
		ip.IsLinkLocalMulticast() ||
		ip.IsInterfaceLocalMulticast() ||
		ip.IsMulticast() ||
		ip.IsUnspecified() ||
		cgnatNet.Contains(ip)
}

// safeDialContext refuses to connect to non-public addresses.  The check sits
// in Dialer.Control, so it runs on the actual resolved IP right before connect
// (= after DNS resolution), which defeats DNS-rebinding.
func safeDialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	d := &net.Dialer{
		Timeout: DefaultHTTPTimeout,
		Control: func(_, address string, _ syscall.RawConn) error {
			host, _, err := net.SplitHostPort(address)
			if err != nil {
				return err
			}
			if isBlockedDialIP(net.ParseIP(host)) {
				return fmt.Errorf("refusing to dial non-public address %s", address)
			}
			return nil
		},
	}
	return d.DialContext(ctx, network, addr)
}

func (v *Verifier) cacheTTL() time.Duration {
	if v.CacheTTL > 0 {
		return v.CacheTTL
	}
	return DefaultCacheTTL
}

func (v *Verifier) now() time.Time {
	if v.Now != nil {
		return v.Now()
	}
	return time.Now()
}

// Verify checks the request's signature headers.  No headers → Result{}
// (zero value; OK=false).  Any error path yields OK=false with a Reason
// the caller can log without leaking key material.
func (v *Verifier) Verify(ctx context.Context, req *http.Request) Result {
	sigHdr := req.Header.Get("Signature")
	inputHdr := req.Header.Get("Signature-Input")
	agentHdr := req.Header.Get("Signature-Agent")
	if sigHdr == "" || inputHdr == "" {
		return Result{}
	}

	// Label discovery: pick the first label in Signature-Input.  Bots in
	// practice send a single label, and the spec doesn't require multi.
	label, inputParams, components, err := parseSignatureInput(inputHdr)
	if err != nil {
		return Result{Reason: "signature-input parse: " + err.Error()}
	}

	sigBytes, err := parseSignatureForLabel(sigHdr, label)
	if err != nil {
		return Result{Reason: "signature parse: " + err.Error()}
	}

	// tag must be "web-bot-auth" — this is what makes the signature a bot
	// authentication signal and not, say, an API gateway HMAC.
	if inputParams.Tag != "web-bot-auth" {
		return Result{Reason: "tag is not web-bot-auth"}
	}

	now := v.now().Unix()
	if inputParams.Created > 0 && inputParams.Created > now+300 {
		// 5-minute slack for clock skew in the future direction.
		return Result{Reason: "created is in the future"}
	}
	if inputParams.Expires > 0 && inputParams.Expires < now {
		return Result{Reason: "signature expired"}
	}
	// Freshness floor: the checks above only bound the FUTURE, so a signature
	// with neither `expires` nor a `nonce` could be captured and replayed
	// forever on a stale `created`.  Require at least one anti-replay anchor --
	// an unexpired `expires`, a `nonce` (single-use, recorded below), or a
	// `created` within the skew window (bounds replay to ~5 min).
	if inputParams.Expires <= 0 && inputParams.Nonce == "" {
		if inputParams.Created <= 0 || inputParams.Created < now-300 {
			return Result{Reason: "no freshness bound (expires, nonce, or recent created required)"}
		}
	}

	if inputParams.KeyID == "" {
		return Result{Reason: "keyid missing"}
	}
	alg := inputParams.Alg
	if alg == "" {
		// `alg` is RECOMMENDED rather than REQUIRED — default to ed25519,
		// which is what every signed agent ships today.
		alg = "ed25519"
	}
	if alg != "ed25519" && alg != "rsa-pss-sha512" {
		return Result{Reason: "unsupported alg: " + alg}
	}

	agentURL := extractAgentURLForLabel(agentHdr, label)
	if agentURL == "" {
		return Result{Reason: "signature-agent missing for label " + label}
	}
	host, err := agentURLHost(agentURL)
	if err != nil {
		return Result{Reason: "signature-agent url: " + err.Error()}
	}
	// SSRF gate: the fetch below runs before signature verification, so refuse
	// to fetch from a host the operator hasn't allowlisted.  Combined with the
	// fail-closed empty-list policy, an unconfigured allowlist fetches nothing.
	if v.AllowOperator != nil && !v.AllowOperator(host) {
		return Result{Reason: "operator not allowlisted: " + host}
	}

	keys, err := v.fetchDirectory(ctx, agentURL)
	if err != nil {
		return Result{Reason: "directory fetch: " + err.Error()}
	}
	matched, foundKey := findKeyByID(keys, inputParams.KeyID, v.now())
	if !foundKey {
		return Result{Reason: "keyid not found in operator directory"}
	}
	if !matched.canHandle(alg) {
		// Misadvertised directory (= ed25519 key listed under rsa-pss alg
		// or vice-versa).  Reject before we waste a verify.
		return Result{Reason: "alg / key kty mismatch"}
	}

	// Build the signature base from the components the operator covered.
	base, err := buildSignatureBase(req, components, inputParams.RawParams, label, agentHdr)
	if err != nil {
		return Result{Reason: "signature base: " + err.Error()}
	}

	if !matched.verify(alg, []byte(base), sigBytes) {
		return Result{Reason: "signature mismatch"}
	}

	// Replay defence: a fresh, valid-looking signature with a nonce we've
	// already accepted within its expires window is a replay attempt.
	// Empty nonces skip the check — the spec marks nonce RECOMMENDED, so
	// operators that omit it lose this layer but still get signature
	// verification.
	if inputParams.Nonce != "" && !v.recordNonce(inputParams.Nonce, inputParams.Expires) {
		return Result{Reason: "nonce replay"}
	}

	return Result{
		OK:        true,
		Operator:  host,
		KeyID:     inputParams.KeyID,
		Algorithm: alg,
	}
}

// recordNonce returns true when this nonce is being seen for the first time
// within its expires window, false when it's a replay.  The map is GC'd
// inline at most once per NonceGCInterval to keep amortised cost low.
func (v *Verifier) recordNonce(nonce string, expires int64) bool {
	v.nonceMu.Lock()
	defer v.nonceMu.Unlock()

	if v.seenNonces == nil {
		v.seenNonces = map[string]int64{}
	}

	now := v.now()
	if now.Sub(v.lastNonceGC) >= NonceGCInterval {
		v.lastNonceGC = now
		nowU := now.Unix()
		for n, exp := range v.seenNonces {
			if exp <= nowU {
				delete(v.seenNonces, n)
			}
		}
	}

	if _, dup := v.seenNonces[nonce]; dup {
		return false
	}
	deadline := expires
	if deadline == 0 {
		deadline = now.Add(NonceFallbackHorizon).Unix()
	}
	v.seenNonces[nonce] = deadline
	return true
}

// ----- parsing -----

// inputMetadata: the per-label parameters carried in Signature-Input.
type inputMetadata struct {
	Created   int64
	Expires   int64
	KeyID     string
	Alg       string
	Nonce     string
	Tag       string
	RawParams string // = the original ";k=v;..." tail, used in the signature base
}

// parseSignatureInput pulls out the first label and its covered-components
// + parameters.  Input shape:
//
//	sig1=("@authority" "signature-agent";key="agent1");created=1;keyid="abc";tag="web-bot-auth"
//
// Returns the label, the parsed metadata, and the raw component tokens
// (each preserved as its quoted form so buildSignatureBase can render them
// identically to what the signer signed over).
func parseSignatureInput(h string) (label string, meta inputMetadata, components []string, err error) {
	// Find the first '=' to split label.
	eq := strings.Index(h, "=")
	if eq < 0 {
		return "", inputMetadata{}, nil, errors.New("no '='")
	}
	label = strings.TrimSpace(h[:eq])
	rest := strings.TrimSpace(h[eq+1:])
	if !strings.HasPrefix(rest, "(") {
		return "", inputMetadata{}, nil, errors.New("missing '('")
	}
	close := strings.Index(rest, ")")
	if close < 0 {
		return "", inputMetadata{}, nil, errors.New("missing ')'")
	}
	inside := rest[1:close]
	params := strings.TrimSpace(rest[close+1:])

	components, err = splitComponentList(inside)
	if err != nil {
		return "", inputMetadata{}, nil, err
	}

	meta, err = parseInputParams(params)
	if err != nil {
		return "", inputMetadata{}, nil, err
	}
	return label, meta, components, nil
}

// splitComponentList preserves each entry (e.g. `"@authority"` or
// `"signature-agent";key="agent1"`) verbatim so we can reproduce the
// signer's serialisation.
func splitComponentList(s string) ([]string, error) {
	var out []string
	i := 0
	for i < len(s) {
		// Skip whitespace.
		for i < len(s) && (s[i] == ' ' || s[i] == '\t') {
			i++
		}
		if i >= len(s) {
			break
		}
		if s[i] != '"' {
			return nil, errors.New("component does not start with '\"'")
		}
		// Read quoted string.
		start := i
		i++
		for i < len(s) && s[i] != '"' {
			i++
		}
		if i >= len(s) {
			return nil, errors.New("unterminated component string")
		}
		i++ // closing quote
		// Optional ";k=v" parameters until next space.
		for i < len(s) && s[i] == ';' {
			// Param: name=value, value may be quoted.
			i++
			for i < len(s) && s[i] != '=' {
				i++
			}
			if i >= len(s) {
				return nil, errors.New("malformed component param")
			}
			i++ // '='
			if i < len(s) && s[i] == '"' {
				i++
				for i < len(s) && s[i] != '"' {
					i++
				}
				if i < len(s) {
					i++
				}
			} else {
				for i < len(s) && s[i] != ' ' && s[i] != ';' {
					i++
				}
			}
		}
		out = append(out, s[start:i])
	}
	return out, nil
}

// parseInputParams reads ";k=v;k2=\"v2\";..." into the metadata struct.
func parseInputParams(s string) (inputMetadata, error) {
	meta := inputMetadata{RawParams: s}
	for {
		s = strings.TrimSpace(s)
		if !strings.HasPrefix(s, ";") {
			break
		}
		s = strings.TrimSpace(s[1:])
		eq := strings.Index(s, "=")
		if eq < 0 {
			return meta, errors.New("param without '='")
		}
		name := strings.TrimSpace(s[:eq])
		s = s[eq+1:]
		var val string
		if strings.HasPrefix(s, `"`) {
			s = s[1:]
			end := strings.Index(s, `"`)
			if end < 0 {
				return meta, errors.New("unterminated quoted param")
			}
			val = s[:end]
			s = s[end+1:]
		} else {
			// Unquoted (numeric or token).
			end := len(s)
			for i, c := range s {
				if c == ';' || c == ' ' {
					end = i
					break
				}
			}
			val = s[:end]
			s = s[end:]
		}
		switch name {
		case "created":
			n, _ := strconv.ParseInt(val, 10, 64)
			meta.Created = n
		case "expires":
			n, _ := strconv.ParseInt(val, 10, 64)
			meta.Expires = n
		case "keyid":
			meta.KeyID = val
		case "alg":
			meta.Alg = val
		case "nonce":
			meta.Nonce = val
		case "tag":
			meta.Tag = val
		}
	}
	return meta, nil
}

// parseSignatureForLabel extracts the byte signature for `label` out of a
// `Signature: label1=:b64:, label2=:b64:` style header.
func parseSignatureForLabel(h, label string) ([]byte, error) {
	// Simple state machine — we don't need general structured-field parsing
	// for what is always `<label>=:<b64>:` per label.
	for _, part := range splitTopLevel(h, ',') {
		part = strings.TrimSpace(part)
		eq := strings.Index(part, "=")
		if eq < 0 {
			continue
		}
		if strings.TrimSpace(part[:eq]) != label {
			continue
		}
		val := strings.TrimSpace(part[eq+1:])
		// len(val) >= 2 guard: a single ":" satisfies BOTH HasPrefix and
		// HasSuffix, so val[1:len-1] becomes val[1:0] -> slice-bounds panic.  An
		// unauthenticated `Signature: sig1=:` triggers this before any signature
		// / allowlist check; with the shipped fail-open snippet the panic'd
		// subrequest 502s and bypasses the challenge.  RFC 9421 wants a malformed
		// structured field treated as a verification failure, not a crash.
		if len(val) < 2 || !strings.HasPrefix(val, ":") || !strings.HasSuffix(val, ":") {
			return nil, errors.New("byte sequence not delimited by ':'")
		}
		val = val[1 : len(val)-1]
		out, err := base64.StdEncoding.DecodeString(val)
		if err != nil {
			return nil, err
		}
		return out, nil
	}
	return nil, errors.New("label not found")
}

// splitTopLevel splits s on `sep` while respecting `"..."` quoting.  Lets
// `parseSignatureForLabel` split on `,` without breaking inside a base64
// value that happens to be the same character (= shouldn't occur for `:`
// but better safe).
func splitTopLevel(s string, sep byte) []string {
	var out []string
	depth := 0
	inQ := false
	start := 0
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c == '"' && (i == 0 || s[i-1] != '\\'):
			inQ = !inQ
		case c == '(' && !inQ:
			depth++
		case c == ')' && !inQ:
			depth--
		case c == sep && !inQ && depth == 0:
			out = append(out, s[start:i])
			start = i + 1
		}
	}
	out = append(out, s[start:])
	return out
}

// extractAgentURLForLabel pulls the URL whose dictionary key matches `label`
// out of a Signature-Agent header.  Example header:
//
//	Signature-Agent: agent1="https://operator.example/", agent2="https://other.example/"
//
// Returns "" when the header is missing or the label isn't represented.
func extractAgentURLForLabel(h, label string) string {
	if h == "" {
		return ""
	}
	for _, part := range splitTopLevel(h, ',') {
		part = strings.TrimSpace(part)
		eq := strings.Index(part, "=")
		if eq < 0 {
			continue
		}
		if strings.TrimSpace(part[:eq]) != label {
			continue
		}
		val := strings.TrimSpace(part[eq+1:])
		// len(val) >= 2 guard: a single `"` satisfies both prefix+suffix and
		// val[1:len-1] would panic (see parseSignatureForLabel).
		if len(val) < 2 || !strings.HasPrefix(val, `"`) || !strings.HasSuffix(val, `"`) {
			return ""
		}
		return val[1 : len(val)-1]
	}
	return ""
}

func agentURLHost(raw string) (string, error) {
	u, err := url.Parse(raw)
	if err != nil {
		return "", err
	}
	if u.Scheme != "https" {
		return "", errors.New("agent URL must be https")
	}
	if u.Host == "" {
		return "", errors.New("agent URL has no host")
	}
	return u.Host, nil
}

// ----- signature base reconstruction -----

// buildSignatureBase recomputes the bytes that the signer signed over,
// per RFC 9421 §2.5.  We only handle the components the spec mandates for
// Web Bot Auth: @authority, @target-uri, signature-agent, and the trailing
// @signature-params.
func buildSignatureBase(req *http.Request, components []string, params, label, agentHdr string) (string, error) {
	var sb strings.Builder
	for _, c := range components {
		name, paramKey, err := splitComponentNameAndKey(c)
		if err != nil {
			return "", err
		}
		val, err := componentValue(req, name, paramKey, agentHdr)
		if err != nil {
			return "", err
		}
		sb.WriteString(c)
		sb.WriteString(": ")
		sb.WriteString(val)
		sb.WriteString("\n")
	}
	// Trailing @signature-params line — required by RFC 9421.
	sb.WriteString(`"@signature-params": (`)
	for i, c := range components {
		if i > 0 {
			sb.WriteString(" ")
		}
		sb.WriteString(c)
	}
	sb.WriteString(")")
	sb.WriteString(params)
	return sb.String(), nil
}

// splitComponentNameAndKey turns `"signature-agent";key="agent1"` into
// (`"signature-agent"`, `agent1`).  Plain components (no `;key=`) return
// the second value empty.
func splitComponentNameAndKey(c string) (name, key string, err error) {
	idx := strings.Index(c, `";`)
	if idx < 0 {
		return c, "", nil
	}
	name = c[:idx+1] // include closing quote
	rest := c[idx+1:]
	if !strings.HasPrefix(rest, `;key="`) {
		// Other params (req, sf, ...) are not used by Web Bot Auth today.
		return name, "", nil
	}
	rest = rest[len(`;key="`):]
	end := strings.Index(rest, `"`)
	if end < 0 {
		return name, "", errors.New("unterminated component key")
	}
	return name, rest[:end], nil
}

// componentValue returns the string that should appear after the colon on
// a component line in the signature base.  See RFC 9421 §2.2 / §2.4.
func componentValue(req *http.Request, name, key, agentHdr string) (string, error) {
	switch name {
	case `"@authority"`:
		// RFC 9421 §2.2.3: lowercased.
		h := req.Host
		if h == "" {
			h = req.URL.Host
		}
		return strings.ToLower(h), nil
	case `"@target-uri"`:
		return req.URL.String(), nil
	case `"@method"`:
		return strings.ToUpper(req.Method), nil
	case `"@path"`:
		return req.URL.Path, nil
	case `"@scheme"`:
		if req.URL.Scheme != "" {
			return req.URL.Scheme, nil
		}
		if req.TLS != nil {
			return "https", nil
		}
		return "http", nil
	case `"signature-agent"`:
		// Dictionary member selection: agent_hdr is `label="url", label2="url2"`.
		// We need to render either the whole header (no key) or the value
		// of the given key in serialized form (= a quoted URL).
		if key == "" {
			return agentHdr, nil
		}
		val := extractAgentURLForLabel(agentHdr, key)
		if val == "" {
			return "", fmt.Errorf("signature-agent key %q missing", key)
		}
		return `"` + val + `"`, nil
	}
	// Plain header: lowercase + value (RFC 9421 §2.1).
	hname := strings.Trim(name, `"`)
	if v := req.Header.Get(hname); v != "" {
		return v, nil
	}
	return "", fmt.Errorf("component %q not present", name)
}

// ----- directory fetch + key lookup -----

// fetchDirectory pulls (and caches) the operator's
// .well-known/http-message-signatures-directory.  Cache eviction is lazy:
// we just check fetchedAt + CacheTTL on each read.
func (v *Verifier) fetchDirectory(ctx context.Context, agentURL string) ([]directoryKey, error) {
	v.mu.RLock()
	c, ok := v.cache[agentURL]
	v.mu.RUnlock()
	if ok && v.now().Sub(c.fetchedAt) < v.cacheTTL() {
		return c.keys, nil
	}

	u, err := url.Parse(agentURL)
	if err != nil {
		return nil, err
	}
	u.Path = WellKnownPath
	u.RawQuery = ""

	// agentURL is allowlist-gated (fail-closed empty list) + https-only, and the
	// httpClient's dialer refuses private / loopback / link-local / cloud-metadata
	// addresses -- so the SSRF taint gosec flags here is defended, not open.
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil) //nolint:gosec
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/http-message-signatures-directory")

	resp, err := v.httpClient().Do(req) //nolint:gosec
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("directory status %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, MaxDirectoryBytes))
	if err != nil {
		return nil, err
	}

	keys, err := parseDirectoryKeys(body)
	if err != nil {
		return nil, err
	}

	v.mu.Lock()
	v.cache[agentURL] = cachedDir{keys: keys, fetchedAt: v.now()}
	v.mu.Unlock()
	return keys, nil
}

// parseDirectoryKeys accepts both shapes the current draft hints at:
//
//	{ "keys": { ...single key... } }
//	{ "keys": [ {...}, {...} ] }
func parseDirectoryKeys(body []byte) ([]directoryKey, error) {
	var doc directoryDoc
	if err := json.Unmarshal(body, &doc); err != nil {
		return nil, err
	}
	if len(doc.Keys) == 0 {
		return nil, errors.New("directory has no keys")
	}
	switch doc.Keys[0] {
	case '[':
		var ks []directoryKey
		if err := json.Unmarshal(doc.Keys, &ks); err != nil {
			return nil, err
		}
		return ks, nil
	case '{':
		var k directoryKey
		if err := json.Unmarshal(doc.Keys, &k); err != nil {
			return nil, err
		}
		return []directoryKey{k}, nil
	}
	return nil, errors.New("directory keys: unexpected JSON shape")
}

// findKeyByID matches the directory key whose JWK thumbprint equals keyid.
// Returns a matchedKey carrying whichever algorithm-family parsed cleanly
// (ed25519 or RSA).  Keys with an nbf/exp window are skipped when now is
// outside it; entries with an unknown kty are silently skipped.
func findKeyByID(keys []directoryKey, keyid string, now time.Time) (matchedKey, bool) {
	nowU := now.Unix()
	for _, k := range keys {
		if k.Nbf > 0 && nowU < k.Nbf {
			continue
		}
		if k.Exp > 0 && nowU > k.Exp {
			continue
		}
		switch k.Kty {
		case "OKP":
			if k.Crv != "Ed25519" {
				continue
			}
			raw, err := base64.RawURLEncoding.DecodeString(k.X)
			if err != nil || len(raw) != ed25519.PublicKeySize {
				continue
			}
			if jwkThumbprintEd25519(k.X) != keyid {
				continue
			}
			return matchedKey{ed25519Pub: ed25519.PublicKey(raw)}, true
		case "RSA":
			pub, err := parseRSAJWK(k.N, k.E)
			if err != nil {
				continue
			}
			if jwkThumbprintRSA(k.N, k.E) != keyid {
				continue
			}
			return matchedKey{rsaPub: pub}, true
		}
	}
	return matchedKey{}, false
}

// parseRSAJWK turns the base64url n / e JWK members into a usable
// rsa.PublicKey.  RSA JWKs are spec'd in RFC 7518 §6.3.
func parseRSAJWK(nStr, eStr string) (*rsa.PublicKey, error) {
	if nStr == "" || eStr == "" {
		return nil, errors.New("missing n or e")
	}
	nBytes, err := base64.RawURLEncoding.DecodeString(nStr)
	if err != nil {
		return nil, err
	}
	eBytes, err := base64.RawURLEncoding.DecodeString(eStr)
	if err != nil {
		return nil, err
	}
	// e is a positive big-endian integer.  Left-pad to 4 bytes so we can
	// read it via binary.BigEndian.Uint32 — exponents are commonly 65537
	// (3 bytes) or 3 (1 byte), well within int range.
	if len(eBytes) == 0 || len(eBytes) > 4 {
		return nil, errors.New("e out of range")
	}
	var ePadded [4]byte
	copy(ePadded[4-len(eBytes):], eBytes)
	e := int(binary.BigEndian.Uint32(ePadded[:]))
	if e <= 0 {
		return nil, errors.New("e must be positive")
	}
	return &rsa.PublicKey{N: new(big.Int).SetBytes(nBytes), E: e}, nil
}

// jwkThumbprintEd25519 computes RFC 8037 Appendix A.3 / RFC 7638 §3 over
// {crv, kty, x} for an OKP/Ed25519 key.  Keys passed in as base64url x.
func jwkThumbprintEd25519(x string) string {
	// JSON object with members in lexicographic order, no whitespace.
	type canonical struct {
		Crv string `json:"crv"`
		Kty string `json:"kty"`
		X   string `json:"x"`
	}
	b, _ := json.Marshal(canonical{Crv: "Ed25519", Kty: "OKP", X: x})
	sum := sha256.Sum256(b)
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

// jwkThumbprintRSA computes RFC 7638 §3.2 over {e, kty, n} for an RSA key.
// Both n and e are the base64url-encoded JWK members as they appear in the
// directory document.
func jwkThumbprintRSA(n, e string) string {
	type canonical struct {
		E   string `json:"e"`
		Kty string `json:"kty"`
		N   string `json:"n"`
	}
	b, _ := json.Marshal(canonical{E: e, Kty: "RSA", N: n})
	sum := sha256.Sum256(b)
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

// SortedOperators returns the set of cached operator hosts, used by the
// settings UI to show "directories we've seen recently".  Order is stable
// for stable templates.
func (v *Verifier) SortedOperators() []string {
	v.mu.RLock()
	defer v.mu.RUnlock()
	out := make([]string, 0, len(v.cache))
	for k := range v.cache {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
