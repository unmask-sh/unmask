// Package privacypass verifies Privacy Pass tokens (the RFC 9577 HTTP
// authentication scheme + RFC 9578 issuance protocols) so an attested real
// client -- most commonly an Apple device presenting a Private Access Token --
// can be passed through the bot challenge with no PoW / CAPTCHA.
//
// unmask is the *origin* (token verifier), never the issuer or attester.  Only
// the publicly verifiable token type 0x0002 ("Blind RSA (2048-bit)",
// RFC 9578 Section 8.2) is supported: its authenticator is a finalized
// RSASSA-PSS signature the origin checks with the issuer's public key, no issuer
// secret involved.  The privately verifiable type 0x0001 (VOPRF) needs the
// issuer's key and is intentionally out of scope.
//
// Phase A (this file): token parsing + RSASSA-PSS verification + challenge
// binding, against a caller-supplied set of trusted issuer keys.  Issuer-key
// discovery (a key-directory fetch/cache like the webbotauth verifier), the
// WWW-Authenticate challenge emission, spent-nonce replay tracking, and the
// auth_check / native-mode wiring land in later phases.
package privacypass

import (
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"math/big"
	"net/http"
	"strings"
	"sync"
	"time"
)

const (
	// TokenTypeBlindRSA is the publicly verifiable Blind RSA (2048-bit) type.
	TokenTypeBlindRSA = 0x0002

	nonceLen        = 32
	digestLen       = 32
	keyIDLen        = 32
	blindRSAAuthLen = 256                                                   // Nk for RSA-2048
	blindRSATokLen  = 2 + nonceLen + digestLen + keyIDLen + blindRSAAuthLen // = 354
)

// oidRSASSAPSS is id-RSASSA-PSS (RFC 8017).  A token-key SPKI MUST carry it
// (RFC 9578 Section 6.5).
var oidRSASSAPSS = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 10}

// IssuerKey is a trusted issuer public key (a Privacy Pass "token-key").
type IssuerKey struct {
	Name  string         // issuer name, surfaced in Result.Issuer
	KeyID [keyIDLen]byte // SHA-256 of the DER SPKI; matched against token_key_id
	Pub   *rsa.PublicKey
}

// Token is a parsed type-0x0002 Privacy Pass token (RFC 9578 Section 6.3).
type Token struct {
	Type            uint16
	Nonce           [nonceLen]byte
	ChallengeDigest [digestLen]byte
	KeyID           [keyIDLen]byte
	Authenticator   []byte // Nk = 256 bytes
}

// Result is the verification outcome.  Nonce is exposed so a later phase can
// reject a replayed token (spent-nonce tracking).
type Result struct {
	OK     bool
	Issuer string
	Reason string
	Nonce  [nonceLen]byte
}

// DefaultDirCacheTTL caps how long a fetched issuer-key directory is cached
// before the verifier re-fetches it (issuer keys rotate -- Cloudflare ~daily,
// Fastly ~weekly).
const DefaultDirCacheTTL = time.Hour

// Verifier holds the trusted issuer keys.  Safe for concurrent use.
type Verifier struct {
	mu       sync.RWMutex
	keys     []IssuerKey           // static keys (SetIssuerKeys path; unused when load != nil)
	load     func() []IssuerConfig // optional live config source
	dirCache map[string]cachedDir  // preset DirectoryURL -> fetched keys + expiry
	httpc    *http.Client
	ttl      time.Duration
	clock    func() time.Time // injectable for tests; nil = time.Now
}

type cachedDir struct {
	keys    []IssuerKey
	expires time.Time
}

// New returns an empty Verifier.  Populate it with SetIssuerKeys or SetLoader.
func New() *Verifier { return &Verifier{} }

// SetIssuerKeys installs a fixed trusted key set and clears any loader.  Used by
// tests and callers that resolve keys themselves.
func (v *Verifier) SetIssuerKeys(keys []IssuerKey) {
	v.mu.Lock()
	v.keys = append([]IssuerKey(nil), keys...)
	v.load = nil
	v.mu.Unlock()
}

// IssuerConfig is a raw, settings-shaped trusted issuer entry.  The package
// stays settings-free; the daemon adapts its config into these.  A config is
// either a CUSTOM issuer (Name + SPKIB64, a single static key) or a PRESET
// issuer (Name + DirectoryURL + SnapshotKeys: the verifier fetches the issuer's
// current token-keys from the directory and caches them, falling back to the
// embedded snapshot when the fetch fails).
type IssuerConfig struct {
	Name         string
	SPKIB64      string   // custom: one base64 DER SubjectPublicKeyInfo (id-RSASSA-PSS)
	DirectoryURL string   // preset: RFC 9578 token-key directory to fetch
	SnapshotKeys []string // preset: base64 DER SPKI fallback when the fetch fails
}

// SetLoader installs a callback returning the current trusted issuer configs.
// Custom issuers are parsed per resolve (cheap, and PAT verifies are rare);
// preset issuers are fetched from their directory and cached with a TTL, so an
// admin edit takes effect without a restart and key rotation is followed.
func (v *Verifier) SetLoader(load func() []IssuerConfig) {
	v.mu.Lock()
	v.load = load
	v.mu.Unlock()
}

func (v *Verifier) now() time.Time {
	if v.clock != nil {
		return v.clock()
	}
	return time.Now()
}

func (v *Verifier) cacheTTL() time.Duration {
	if v.ttl > 0 {
		return v.ttl
	}
	return DefaultDirCacheTTL
}

func (v *Verifier) httpClient() *http.Client {
	if v.httpc != nil {
		return v.httpc
	}
	return &http.Client{Timeout: 5 * time.Second}
}

// resolve returns the currently trusted keys: the static set when no loader is
// installed, otherwise the loader's custom issuers (parsed) + preset issuers
// (fetched-and-cached, snapshot on failure).
func (v *Verifier) resolve() []IssuerKey {
	v.mu.RLock()
	load, static := v.load, v.keys
	v.mu.RUnlock()
	if load == nil {
		return static
	}
	var out []IssuerKey
	for _, c := range load() {
		if c.DirectoryURL != "" {
			out = append(out, v.presetKeys(c)...)
			continue
		}
		if c.Name == "" || c.SPKIB64 == "" {
			continue
		}
		der, err := decodeB64Any(c.SPKIB64)
		if err != nil {
			continue
		}
		if key, err := IssuerKeyFromSPKI(c.Name, der); err == nil {
			out = append(out, key)
		}
	}
	return out
}

// presetKeys returns a preset issuer's keys from the directory cache, fetching
// (and caching) when the entry is missing or expired, and falling back to the
// last good keys or the embedded snapshot when the fetch fails.
func (v *Verifier) presetKeys(c IssuerConfig) []IssuerKey {
	now := v.now()
	v.mu.RLock()
	cd, ok := v.dirCache[c.DirectoryURL]
	v.mu.RUnlock()
	if ok && now.Before(cd.expires) {
		return cd.keys
	}

	keys, err := v.fetchDirectory(c.Name, c.DirectoryURL)
	if err == nil && len(keys) > 0 {
		v.storeDir(c.DirectoryURL, keys, now.Add(v.cacheTTL()))
		return keys
	}
	// Fetch failed.  Prefer the last good keys (even if expired) so a transient
	// outage doesn't drop a working issuer; else use the embedded snapshot.  A
	// short re-try window avoids hammering the directory on every verify.
	log.Printf("unmask: privacy-pass: issuer %q: directory fetch failed, using fallback: %v", c.Name, err)
	if ok && len(cd.keys) > 0 {
		v.storeDir(c.DirectoryURL, cd.keys, now.Add(v.cacheTTL()/4))
		return cd.keys
	}
	snap := parseSnapshot(c.Name, c.SnapshotKeys)
	v.storeDir(c.DirectoryURL, snap, now.Add(v.cacheTTL()/4))
	return snap
}

func (v *Verifier) storeDir(url string, keys []IssuerKey, expires time.Time) {
	v.mu.Lock()
	if v.dirCache == nil {
		v.dirCache = map[string]cachedDir{}
	}
	v.dirCache[url] = cachedDir{keys: keys, expires: expires}
	v.mu.Unlock()
}

// fetchDirectory GETs an issuer's token-key directory (RFC 9578) and parses its
// publicly verifiable (type 0x0002) token-keys into IssuerKeys under issuerName.
// The DirectoryURL comes from a built-in preset (never operator-supplied), so no
// SSRF guard is needed.
func (v *Verifier) fetchDirectory(issuerName, url string) ([]IssuerKey, error) {
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	resp, err := v.httpClient().Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("directory status %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 256*1024))
	if err != nil {
		return nil, err
	}
	var doc struct {
		TokenKeys []struct {
			TokenType int    `json:"token-type"`
			TokenKey  string `json:"token-key"`
		} `json:"token-keys"`
	}
	if err := json.Unmarshal(body, &doc); err != nil {
		return nil, err
	}
	var keys []IssuerKey
	for _, tk := range doc.TokenKeys {
		if tk.TokenType != TokenTypeBlindRSA {
			continue
		}
		der, derr := decodeB64Any(tk.TokenKey)
		if derr != nil {
			continue
		}
		if k, kerr := IssuerKeyFromSPKI(issuerName, der); kerr == nil {
			keys = append(keys, k)
		}
	}
	if len(keys) == 0 {
		return nil, errors.New("directory had no usable token-keys")
	}
	return keys, nil
}

// parseSnapshot turns a preset's embedded base64 keys into IssuerKeys.
func parseSnapshot(issuerName string, snapshot []string) []IssuerKey {
	out := make([]IssuerKey, 0, len(snapshot))
	for _, s := range snapshot {
		der, err := decodeB64Any(s)
		if err != nil {
			continue
		}
		if k, kerr := IssuerKeyFromSPKI(issuerName, der); kerr == nil {
			out = append(out, k)
		}
	}
	return out
}

func decodeB64Any(s string) ([]byte, error) {
	s = strings.TrimSpace(s)
	for _, enc := range []*base64.Encoding{
		base64.StdEncoding, base64.RawStdEncoding,
		base64.URLEncoding, base64.RawURLEncoding,
	} {
		if b, err := enc.DecodeString(s); err == nil {
			return b, nil
		}
	}
	return nil, errors.New("not valid base64")
}

// IssuerKeyFromSPKI parses a DER SubjectPublicKeyInfo carrying an id-RSASSA-PSS
// RSA key (the token-key format, RFC 9578 Section 6.5) into an IssuerKey.  KeyID
// is SHA-256 over the exact DER bytes, matching how the issuer derives
// token_key_id, so callers must pass the bytes verbatim as published.
func IssuerKeyFromSPKI(name string, der []byte) (IssuerKey, error) {
	var spki struct {
		Algorithm pkix.AlgorithmIdentifier
		PublicKey asn1.BitString
	}
	rest, err := asn1.Unmarshal(der, &spki)
	if err != nil {
		return IssuerKey{}, err
	}
	if len(rest) != 0 {
		return IssuerKey{}, errors.New("trailing bytes after SubjectPublicKeyInfo")
	}
	if !spki.Algorithm.Algorithm.Equal(oidRSASSAPSS) {
		return IssuerKey{}, errors.New("SPKI algorithm is not id-RSASSA-PSS")
	}
	var rsaPub struct {
		N *big.Int
		E int
	}
	if _, err := asn1.Unmarshal(spki.PublicKey.Bytes, &rsaPub); err != nil {
		return IssuerKey{}, err
	}
	if rsaPub.N == nil || rsaPub.N.Sign() <= 0 || rsaPub.E <= 0 {
		return IssuerKey{}, errors.New("invalid RSA public key")
	}
	return IssuerKey{
		Name:  name,
		KeyID: sha256.Sum256(der),
		Pub:   &rsa.PublicKey{N: rsaPub.N, E: rsaPub.E},
	}, nil
}

// ParseToken decodes a 354-byte type-0x0002 token (RFC 9578 Section 6.3).
func ParseToken(b []byte) (Token, error) {
	if len(b) != blindRSATokLen {
		return Token{}, errors.New("bad token length")
	}
	var t Token
	t.Type = binary.BigEndian.Uint16(b[0:2])
	off := 2
	copy(t.Nonce[:], b[off:off+nonceLen])
	off += nonceLen
	copy(t.ChallengeDigest[:], b[off:off+digestLen])
	off += digestLen
	copy(t.KeyID[:], b[off:off+keyIDLen])
	off += keyIDLen
	t.Authenticator = append([]byte(nil), b[off:off+blindRSAAuthLen]...)
	return t, nil
}

// authenticatorInput rebuilds the 98-byte token_authenticator_input that the
// issuer signed: token_type || nonce || challenge_digest || token_key_id
// (RFC 9578 Section 6.4).
func (t Token) authenticatorInput() []byte {
	out := make([]byte, 0, 2+nonceLen+digestLen+keyIDLen)
	out = binary.BigEndian.AppendUint16(out, t.Type)
	out = append(out, t.Nonce[:]...)
	out = append(out, t.ChallengeDigest[:]...)
	out = append(out, t.KeyID[:]...)
	return out
}

// ParseAuthorization extracts and decodes the token from an
//
//	Authorization: PrivateToken token="<base64url>"
//
// header value (RFC 9577 Section 2.2).  Accepts the value quoted or bare, with
// or without base64 padding.
func ParseAuthorization(header string) (Token, error) {
	header = strings.TrimSpace(header)
	const scheme = "PrivateToken"
	if len(header) < len(scheme) || !strings.EqualFold(header[:len(scheme)], scheme) {
		return Token{}, errors.New("not a PrivateToken Authorization")
	}
	params := strings.TrimSpace(header[len(scheme):])
	var val string
	for _, p := range strings.Split(params, ",") {
		p = strings.TrimSpace(p)
		if k, v, ok := strings.Cut(p, "="); ok && strings.EqualFold(strings.TrimSpace(k), "token") {
			val = strings.Trim(strings.TrimSpace(v), `"`)
			break
		}
	}
	if val == "" {
		return Token{}, errors.New("no token parameter")
	}
	raw, err := decodeB64URL(val)
	if err != nil {
		return Token{}, err
	}
	return ParseToken(raw)
}

func decodeB64URL(s string) ([]byte, error) {
	if b, err := base64.RawURLEncoding.DecodeString(s); err == nil {
		return b, nil
	}
	return base64.URLEncoding.DecodeString(s)
}

// Verify checks the Authorization header's token against the trusted issuer
// keys and the expected challenge digest (SHA-256 of the TokenChallenge the
// origin issued).  A pass requires: type 0x0002, a known issuer key whose KeyID
// equals token_key_id, challenge_digest == expectedDigest, and a valid
// RSASSA-PSS authenticator.
func (v *Verifier) Verify(authzHeader string, expectedDigest [digestLen]byte) Result {
	t, err := ParseAuthorization(authzHeader)
	if err != nil {
		return Result{Reason: "parse: " + err.Error()}
	}
	res := Result{Nonce: t.Nonce}
	if t.Type != TokenTypeBlindRSA {
		res.Reason = "unsupported token type"
		return res
	}
	key, ok := v.keyByID(t.KeyID)
	if !ok {
		res.Reason = "unknown token_key_id"
		return res
	}
	return v.verifyTokenWithKey(t, key, expectedDigest)
}

// VerifyForOrigin verifies a token against the trusted issuers, binding it to
// originHost: the expected challenge digest is recomputed from the matched
// issuer's name + this origin, so a token minted for another origin (or another
// issuer) cannot pass here.  originHost is the public host name, no port.
func (v *Verifier) VerifyForOrigin(authzHeader, originHost string) Result {
	t, err := ParseAuthorization(authzHeader)
	if err != nil {
		return Result{Reason: "parse: " + err.Error()}
	}
	res := Result{Nonce: t.Nonce}
	if t.Type != TokenTypeBlindRSA {
		res.Reason = "unsupported token type"
		return res
	}
	key, ok := v.keyByID(t.KeyID)
	if !ok {
		res.Reason = "unknown token_key_id"
		return res
	}
	expected, err := TokenChallenge{
		TokenType:  TokenTypeBlindRSA,
		IssuerName: key.Name,
		OriginInfo: originHost,
	}.Digest()
	if err != nil {
		res.Reason = "challenge: " + err.Error()
		return res
	}
	return v.verifyTokenWithKey(t, key, expected)
}

func (v *Verifier) verifyTokenWithKey(t Token, key IssuerKey, expectedDigest [digestLen]byte) Result {
	res := Result{Nonce: t.Nonce}
	// Bind the token to the challenge this origin issued: a token minted for a
	// different challenge (e.g. another origin) must not pass here.
	if t.ChallengeDigest != expectedDigest {
		res.Reason = "challenge digest mismatch"
		return res
	}
	// RFC 9578 Section 6.4: RSASSA-PSS with SHA-384, MGF1-SHA-384, salt length
	// 48.  SHA-384's digest length is 48, so PSSSaltLengthEqualsHash matches.
	sum := sha512.Sum384(t.authenticatorInput())
	opts := &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash, Hash: crypto.SHA384}
	if err := rsa.VerifyPSS(key.Pub, crypto.SHA384, sum[:], t.Authenticator, opts); err != nil {
		res.Reason = "bad authenticator"
		return res
	}
	res.OK = true
	res.Issuer = key.Name
	res.Reason = "ok"
	return res
}

func (v *Verifier) keyByID(id [keyIDLen]byte) (IssuerKey, bool) {
	for _, k := range v.resolve() {
		if k.KeyID == id {
			return k, true
		}
	}
	return IssuerKey{}, false
}

// TokenChallenge is the origin's WWW-Authenticate challenge (RFC 9577
// Section 2.1).  Its SHA-256 digest is the value a valid token's
// challenge_digest field must equal.
type TokenChallenge struct {
	TokenType         uint16
	IssuerName        string
	RedemptionContext []byte // 0 or 32 bytes
	OriginInfo        string
}

// Marshal serializes the TokenChallenge in TLS presentation form (RFC 9577
// Section 2.1): token_type || len16(issuer_name) || issuer_name ||
// len8(redemption_context) || redemption_context || len16(origin_info) ||
// origin_info.
func (c TokenChallenge) Marshal() ([]byte, error) {
	if len(c.RedemptionContext) != 0 && len(c.RedemptionContext) != 32 {
		return nil, errors.New("redemption_context must be 0 or 32 bytes")
	}
	if len(c.IssuerName) > 0xffff || len(c.OriginInfo) > 0xffff {
		return nil, errors.New("issuer_name / origin_info too long")
	}
	out := make([]byte, 0, 2+2+len(c.IssuerName)+1+len(c.RedemptionContext)+2+len(c.OriginInfo))
	out = binary.BigEndian.AppendUint16(out, c.TokenType)
	out = binary.BigEndian.AppendUint16(out, uint16(len(c.IssuerName)))
	out = append(out, c.IssuerName...)
	out = append(out, byte(len(c.RedemptionContext)))
	out = append(out, c.RedemptionContext...)
	out = binary.BigEndian.AppendUint16(out, uint16(len(c.OriginInfo)))
	out = append(out, c.OriginInfo...)
	return out, nil
}

// Digest is SHA-256 of the marshaled challenge.
func (c TokenChallenge) Digest() ([digestLen]byte, error) {
	b, err := c.Marshal()
	if err != nil {
		return [digestLen]byte{}, err
	}
	return sha256.Sum256(b), nil
}

// BuildChallengeHeader builds the WWW-Authenticate response value advertising a
// PrivateToken challenge for each issuer, bound to originHost (RFC 9577 §2.2).
// Multiple issuers become comma-separated "PrivateToken" entries in one header.
// challenge / token-key are base64url WITH padding, quoted (padding '=' is not a
// token char).  Issuers whose SPKI can't be decoded are skipped; returns "" if
// none yield a usable challenge, so the caller can decide not to switch to 401.
func BuildChallengeHeader(issuers []IssuerConfig, originHost string) string {
	parts := make([]string, 0, len(issuers))
	for _, is := range issuers {
		if is.Name == "" {
			continue
		}
		chal, err := TokenChallenge{
			TokenType:  TokenTypeBlindRSA,
			IssuerName: is.Name,
			OriginInfo: originHost,
		}.Marshal()
		if err != nil {
			continue
		}
		entry := `PrivateToken challenge="` + base64.URLEncoding.EncodeToString(chal) + `"`
		switch {
		case is.SPKIB64 != "":
			// Custom issuer: advertise the configured token-key, but only if it
			// parses -- never hand a client a challenge for a key we'd reject.
			der, derr := decodeB64Any(is.SPKIB64)
			if derr != nil {
				continue
			}
			if _, kerr := IssuerKeyFromSPKI(is.Name, der); kerr != nil {
				continue
			}
			entry += `, token-key="` + base64.URLEncoding.EncodeToString(der) + `"`
		case is.DirectoryURL != "":
			// Preset issuer: omit token-key.  RFC 9577 lets the client fetch the
			// issuer key out-of-band (from the directory), which also avoids
			// advertising a key that has since rotated out.
		default:
			continue // neither a usable custom key nor a preset
		}
		parts = append(parts, entry)
	}
	return strings.Join(parts, ", ")
}
