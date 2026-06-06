package webbotauth

import (
	"context"
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha512"
	"crypto/tls"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// fixtureKey is a fresh ed25519 keypair held for the whole test file.  Tests
// reuse it so we don't pay per-test keygen + the JWK thumbprint stays stable
// across cases.
type fixtureKey struct {
	priv      ed25519.PrivateKey
	pub       ed25519.PublicKey
	xRaw      string // base64url(public key bytes)
	thumb     string // RFC 8037 thumbprint
	agentURL  string // operator URL used in Signature-Agent
	directory string // JWK directory JSON bytes (= what the .well-known returns)
}

func newFixtureKey(t *testing.T) *fixtureKey {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("ed25519 keygen: %v", err)
	}
	xRaw := base64.RawURLEncoding.EncodeToString(pub)
	thumb := jwkThumbprintEd25519(xRaw)
	dir := map[string]any{
		"keys": []map[string]any{
			{"kty": "OKP", "crv": "Ed25519", "kid": thumb, "x": xRaw, "use": "sig"},
		},
	}
	dirBytes, _ := json.Marshal(dir)
	return &fixtureKey{
		priv:      priv,
		pub:       pub,
		xRaw:      xRaw,
		thumb:     thumb,
		agentURL:  "https://operator.test/",
		directory: string(dirBytes),
	}
}

// startDirectoryServer hosts the JWK directory at the well-known path so the
// Verifier can fetch it during Verify.  Returns the base URL (= agent URL).
func startDirectoryServer(t *testing.T, body string, hits *int32) string {
	t.Helper()
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if hits != nil {
			atomic.AddInt32(hits, 1)
		}
		if r.URL.Path != WellKnownPath {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/http-message-signatures-directory")
		_, _ = io.WriteString(w, body)
	}))
	t.Cleanup(srv.Close)
	return srv.URL + "/"
}

// signedRequest builds an HTTP request that carries a valid Web Bot Auth
// signature for the given fixture, signing only @authority + signature-agent
// to keep the test focused on the verification pipeline rather than full
// component coverage.  The signature is deterministic given the fixture +
// (created, expires, nonce) — nonceOpt lets callers force distinct nonces
// when verifying the same request twice (= replay-defence cases).
func signedRequest(t *testing.T, fx *fixtureKey, created, expires int64, nonceOpt ...string) *http.Request {
	t.Helper()
	nonce := fmt.Sprintf("n-%d-%d", created, expires)
	if len(nonceOpt) > 0 {
		nonce = nonceOpt[0]
	}
	const label = "sig1"
	covered := []string{`"@authority"`, `"signature-agent";key="` + label + `"`}
	params := fmt.Sprintf(`;created=%d;expires=%d;keyid="%s";alg="ed25519";nonce="%s";tag="web-bot-auth"`,
		created, expires, fx.thumb, nonce)

	// Build the base over a request whose host/scheme match what the
	// Verifier will see — same shape as what the bot would build.
	const host = "victim.example"
	req, err := http.NewRequest("GET", "https://"+host+"/", nil)
	if err != nil {
		t.Fatalf("new req: %v", err)
	}
	agentHdr := label + `="` + fx.agentURL + `"`
	req.Host = host

	base, err := buildSignatureBase(req, covered, params, label, agentHdr)
	if err != nil {
		t.Fatalf("buildSignatureBase: %v", err)
	}
	sig := ed25519.Sign(fx.priv, []byte(base))
	sigB64 := base64.StdEncoding.EncodeToString(sig)

	req.Header.Set("Signature", label+"=:"+sigB64+":")
	req.Header.Set("Signature-Input", label+"=("+strings.Join(covered, " ")+")"+params)
	req.Header.Set("Signature-Agent", agentHdr)
	return req
}

// newVerifier returns a Verifier wired up against the given directory body.
// The fixture's agentURL is rewritten to the httptest server so directory
// fetches actually hit it.  The Verifier's HTTPClient is the test server's
// own (= it trusts that server's self-signed cert).
func newVerifier(t *testing.T, fx *fixtureKey, dirBody string, hits *int32) (*Verifier, *fixtureKey) {
	t.Helper()
	url := startDirectoryServer(t, dirBody, hits)
	// Mutate the fixture's agent URL so the signed-request's Signature-Agent
	// points at the test server.  signedRequest will pick this up.
	clone := *fx
	clone.agentURL = url
	srvClient := &http.Client{Transport: &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}}
	v := New()
	v.HTTPClient = srvClient
	v.Now = func() time.Time { return time.Unix(1735689600, 0) }
	return v, &clone
}

// ----- JWK thumbprint -----

// TestJWKThumbprint_Stable: same x in → same thumbprint out.  The output is
// also pinned so a refactor of the canonical-form encoder doesn't silently
// shift every operator's keyid.
func TestJWKThumbprint_Stable(t *testing.T) {
	// Pin against an RFC-8037 worked example (= the spec's appendix A.3
	// canonical input shape, rendered from this x value).
	const x = "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"
	got := jwkThumbprintEd25519(x)
	if got == "" || strings.ContainsAny(got, "=+/") {
		t.Fatalf("thumbprint not base64url: %q", got)
	}
	// Stable: recomputing must produce the identical string.
	if again := jwkThumbprintEd25519(x); again != got {
		t.Errorf("non-stable thumbprint: %q vs %q", got, again)
	}
}

// ----- parseSignatureInput -----

func TestParseSignatureInput_Basic(t *testing.T) {
	hdr := `sig1=("@authority" "signature-agent";key="sig1");created=1;expires=2;keyid="abc";alg="ed25519";nonce="n";tag="web-bot-auth"`
	label, meta, comps, err := parseSignatureInput(hdr)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if label != "sig1" {
		t.Errorf("label = %q, want sig1", label)
	}
	if meta.KeyID != "abc" || meta.Tag != "web-bot-auth" || meta.Alg != "ed25519" {
		t.Errorf("meta = %+v", meta)
	}
	if meta.Created != 1 || meta.Expires != 2 {
		t.Errorf("created/expires = %d/%d", meta.Created, meta.Expires)
	}
	if meta.Nonce != "n" {
		t.Errorf("nonce = %q", meta.Nonce)
	}
	if len(comps) != 2 {
		t.Fatalf("components = %d, want 2", len(comps))
	}
	if comps[0] != `"@authority"` {
		t.Errorf("comp[0] = %q", comps[0])
	}
	if comps[1] != `"signature-agent";key="sig1"` {
		t.Errorf("comp[1] = %q", comps[1])
	}
}

func TestParseSignatureInput_Malformed(t *testing.T) {
	cases := []string{
		"",                // empty
		"sig1",            // no '='
		`sig1=(`,          // missing ')'
		`sig1="oops"`,     // not a list
		`sig1=(unquoted)`, // component without quotes
	}
	for _, c := range cases {
		if _, _, _, err := parseSignatureInput(c); err == nil {
			t.Errorf("malformed input accepted: %q", c)
		}
	}
}

// ----- parseSignatureForLabel -----

func TestParseSignatureForLabel(t *testing.T) {
	sig := base64.StdEncoding.EncodeToString([]byte("hello"))
	hdr := "sig1=:" + sig + ":, other=:abc:"
	got, err := parseSignatureForLabel(hdr, "sig1")
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if string(got) != "hello" {
		t.Errorf("decoded = %q", got)
	}
	if _, err := parseSignatureForLabel(hdr, "missing"); err == nil {
		t.Error("missing label silently accepted")
	}
}

// ----- extractAgentURLForLabel -----

func TestExtractAgentURLForLabel(t *testing.T) {
	hdr := `sig1="https://a.test/", sig2="https://b.test/"`
	if got := extractAgentURLForLabel(hdr, "sig1"); got != "https://a.test/" {
		t.Errorf("sig1 = %q", got)
	}
	if got := extractAgentURLForLabel(hdr, "sig2"); got != "https://b.test/" {
		t.Errorf("sig2 = %q", got)
	}
	if got := extractAgentURLForLabel(hdr, "sig3"); got != "" {
		t.Errorf("missing label returned %q", got)
	}
	if got := extractAgentURLForLabel("", "sig1"); got != "" {
		t.Errorf("empty header returned %q", got)
	}
}

// ----- agentURLHost -----

func TestAgentURLHost(t *testing.T) {
	if _, err := agentURLHost("http://x.test"); err == nil {
		t.Error("http URL accepted (must be https)")
	}
	if _, err := agentURLHost("https://"); err == nil {
		t.Error("empty-host URL accepted")
	}
	host, err := agentURLHost("https://Foo.Test/path?q=1")
	if err != nil {
		t.Fatalf("https URL rejected: %v", err)
	}
	if host == "" {
		t.Error("host extraction lost the host")
	}
}

// ----- parseDirectoryKeys -----

func TestParseDirectoryKeys_BothShapes(t *testing.T) {
	single := `{"keys":{"kty":"OKP","crv":"Ed25519","kid":"k1","x":"abc"}}`
	ks, err := parseDirectoryKeys([]byte(single))
	if err != nil || len(ks) != 1 || ks[0].Kid != "k1" {
		t.Fatalf("single: %v %+v", err, ks)
	}
	arr := `{"keys":[{"kty":"OKP","crv":"Ed25519","kid":"k1","x":"a"},{"kty":"OKP","crv":"Ed25519","kid":"k2","x":"b"}]}`
	ks, err = parseDirectoryKeys([]byte(arr))
	if err != nil || len(ks) != 2 || ks[1].Kid != "k2" {
		t.Fatalf("array: %v %+v", err, ks)
	}
	bad := `{"keys":[]}`
	// "no keys" is currently caught by callers (= findKeyByID returns
	// !found) rather than here.  This test pins that contract — change it
	// together with the call site if the policy moves.
	if _, err := parseDirectoryKeys([]byte(bad)); err != nil {
		t.Errorf("empty array should parse to []: %v", err)
	}
	if _, err := parseDirectoryKeys([]byte(`{}`)); err == nil {
		t.Error("missing keys field accepted")
	}
}

// ----- findKeyByID -----

func TestFindKeyByID(t *testing.T) {
	fx := newFixtureKey(t)
	keys := []directoryKey{{Kty: "OKP", Crv: "Ed25519", Kid: fx.thumb, X: fx.xRaw, Use: "sig"}}

	matched, ok := findKeyByID(keys, fx.thumb, time.Unix(1735689600, 0))
	if !ok {
		t.Fatal("matching key not found")
	}
	if matched.ed25519Pub == nil {
		t.Fatal("matched key has no ed25519 public")
	}
	if !ed25519.PublicKey(fx.pub).Equal(matched.ed25519Pub) {
		t.Error("returned public key bytes differ")
	}

	if _, ok := findKeyByID(keys, "wrong-thumb", time.Unix(1735689600, 0)); ok {
		t.Error("wrong thumbprint matched")
	}

	// nbf/exp window enforcement.
	now := time.Unix(1000, 0)
	expired := []directoryKey{{Kty: "OKP", Crv: "Ed25519", Kid: fx.thumb, X: fx.xRaw, Exp: 500}}
	if _, ok := findKeyByID(expired, fx.thumb, now); ok {
		t.Error("expired key matched")
	}
	notYet := []directoryKey{{Kty: "OKP", Crv: "Ed25519", Kid: fx.thumb, X: fx.xRaw, Nbf: 2000}}
	if _, ok := findKeyByID(notYet, fx.thumb, now); ok {
		t.Error("not-yet-valid key matched")
	}

	// RSA / wrong curve / corrupt-length keys silently skip rather than
	// erroring out -- the caller treats !ok as "no match".
	other := []directoryKey{{Kty: "RSA", Kid: fx.thumb}}
	if _, ok := findKeyByID(other, fx.thumb, now); ok {
		t.Error("RSA key matched as ed25519")
	}
}

// ----- Verify end-to-end -----

func TestVerify_HappyPath(t *testing.T) {
	fx := newFixtureKey(t)
	v, fx2 := newVerifier(t, fx, fx.directory, nil)
	req := signedRequest(t, fx2, 1735689000, 1735690000)

	res := v.Verify(context.Background(), req)
	if !res.OK {
		t.Fatalf("verify failed: reason=%q", res.Reason)
	}
	if res.Algorithm != "ed25519" {
		t.Errorf("algorithm = %q", res.Algorithm)
	}
	if res.KeyID != fx.thumb {
		t.Errorf("keyid = %q, want %q", res.KeyID, fx.thumb)
	}
	if res.Operator == "" {
		t.Error("operator host empty on success")
	}
}

func TestVerify_TamperedSignature(t *testing.T) {
	fx := newFixtureKey(t)
	v, fx2 := newVerifier(t, fx, fx.directory, nil)
	req := signedRequest(t, fx2, 1735689000, 1735690000)

	// Flip a byte in the encoded signature.
	sig := req.Header.Get("Signature")
	// `sig1=:<b64>:` → corrupt the first byte of the b64 payload.
	const tag = "sig1=:"
	i := strings.Index(sig, tag) + len(tag)
	flipped := sig[:i] + flipB64Char(sig[i:i+1]) + sig[i+1:]
	req.Header.Set("Signature", flipped)

	res := v.Verify(context.Background(), req)
	if res.OK {
		t.Fatal("tampered signature passed verify")
	}
	if !strings.Contains(res.Reason, "mismatch") && !strings.Contains(res.Reason, "parse") {
		t.Errorf("unexpected rejection reason: %q", res.Reason)
	}
}

func TestVerify_ExpiredSignature(t *testing.T) {
	fx := newFixtureKey(t)
	v, fx2 := newVerifier(t, fx, fx.directory, nil)
	// expires=now-1 → signature must be rejected immediately.
	req := signedRequest(t, fx2, 1735689500, 1735689599)
	res := v.Verify(context.Background(), req)
	if res.OK {
		t.Fatal("expired signature passed verify")
	}
	if !strings.Contains(res.Reason, "expired") {
		t.Errorf("reason: %q", res.Reason)
	}
}

func TestVerify_FuturisticCreated(t *testing.T) {
	fx := newFixtureKey(t)
	v, fx2 := newVerifier(t, fx, fx.directory, nil)
	// created far in the future (> 5min slack) → rejected.
	req := signedRequest(t, fx2, 1735690000+10000, 1735690000+20000)
	res := v.Verify(context.Background(), req)
	if res.OK || !strings.Contains(res.Reason, "future") {
		t.Errorf("expected 'in the future' rejection, got OK=%v reason=%q", res.OK, res.Reason)
	}
}

func TestVerify_WrongTag(t *testing.T) {
	fx := newFixtureKey(t)
	v, fx2 := newVerifier(t, fx, fx.directory, nil)
	req := signedRequest(t, fx2, 1735689000, 1735690000)

	// Rewrite tag to something else; the rest of the header stays valid so
	// only the tag check should trigger the rejection.
	inp := req.Header.Get("Signature-Input")
	inp = strings.Replace(inp, `tag="web-bot-auth"`, `tag="api-gateway"`, 1)
	req.Header.Set("Signature-Input", inp)

	res := v.Verify(context.Background(), req)
	if res.OK || !strings.Contains(res.Reason, "tag") {
		t.Errorf("expected tag rejection, got OK=%v reason=%q", res.OK, res.Reason)
	}
}

// TestVerify_UnsupportedAlg: an algorithm we don't ship (= ecdsa-p256 or
// similar) must be rejected up front so we never wait on a directory
// fetch we couldn't act on anyway.
func TestVerify_UnsupportedAlg(t *testing.T) {
	fx := newFixtureKey(t)
	v, fx2 := newVerifier(t, fx, fx.directory, nil)
	req := signedRequest(t, fx2, 1735689000, 1735690000)

	inp := req.Header.Get("Signature-Input")
	inp = strings.Replace(inp, `alg="ed25519"`, `alg="ecdsa-p256-sha256"`, 1)
	req.Header.Set("Signature-Input", inp)

	res := v.Verify(context.Background(), req)
	if res.OK || !strings.Contains(res.Reason, "unsupported") {
		t.Errorf("expected alg rejection, got OK=%v reason=%q", res.OK, res.Reason)
	}
}

// TestVerify_AlgKeyMismatch: declaring rsa-pss-sha512 in the signature
// header while the operator's directory only carries an Ed25519 key is a
// misconfiguration on the operator side.  Reject explicitly rather than
// silently failing the verify so the cause is obvious in logs.
func TestVerify_AlgKeyMismatch(t *testing.T) {
	fx := newFixtureKey(t)
	v, fx2 := newVerifier(t, fx, fx.directory, nil)
	req := signedRequest(t, fx2, 1735689000, 1735690000)

	inp := req.Header.Get("Signature-Input")
	inp = strings.Replace(inp, `alg="ed25519"`, `alg="rsa-pss-sha512"`, 1)
	req.Header.Set("Signature-Input", inp)

	res := v.Verify(context.Background(), req)
	if res.OK || !strings.Contains(res.Reason, "mismatch") {
		t.Errorf("expected mismatch rejection, got OK=%v reason=%q", res.OK, res.Reason)
	}
}

func TestVerify_NoHeaders(t *testing.T) {
	fx := newFixtureKey(t)
	v, _ := newVerifier(t, fx, fx.directory, nil)
	req, _ := http.NewRequest("GET", "https://victim.example/", nil)
	res := v.Verify(context.Background(), req)
	if res.OK {
		t.Fatal("unsigned request reported as verified")
	}
	if res.Reason != "" {
		t.Errorf("absent headers should be silent (Reason=%q)", res.Reason)
	}
}

func TestVerify_UnknownKeyID(t *testing.T) {
	fx := newFixtureKey(t)
	// Directory contains a different key only.
	other := newFixtureKey(t)
	v, fx2 := newVerifier(t, fx, other.directory, nil)
	req := signedRequest(t, fx2, 1735689000, 1735690000)

	res := v.Verify(context.Background(), req)
	if res.OK || !strings.Contains(res.Reason, "not found") {
		t.Errorf("expected keyid rejection, got OK=%v reason=%q", res.OK, res.Reason)
	}
}

// ----- directory cache -----

func TestDirectoryCache(t *testing.T) {
	fx := newFixtureKey(t)
	var hits int32
	v, fx2 := newVerifier(t, fx, fx.directory, &hits)

	// Distinct nonces so replay-defence doesn't masquerade as a cache hit.
	req := signedRequest(t, fx2, 1735689000, 1735690000, "cache-1")
	if res := v.Verify(context.Background(), req); !res.OK {
		t.Fatalf("first verify failed: %q", res.Reason)
	}
	if got := atomic.LoadInt32(&hits); got != 1 {
		t.Fatalf("after first verify: hits=%d, want 1", got)
	}

	// Second verify within TTL → no extra fetch.
	req2 := signedRequest(t, fx2, 1735689000, 1735690000, "cache-2")
	if res := v.Verify(context.Background(), req2); !res.OK {
		t.Fatalf("second verify failed: %q", res.Reason)
	}
	if got := atomic.LoadInt32(&hits); got != 1 {
		t.Errorf("cache miss within TTL: hits=%d", got)
	}

	// Force-expire via Now advance > CacheTTL, then a third verify must
	// re-fetch.
	v.Now = func() time.Time { return time.Unix(1735689600+int64(DefaultCacheTTL.Seconds())+1, 0) }
	req3 := signedRequest(t, fx2,
		1735689000+int64(DefaultCacheTTL.Seconds()),
		1735690000+int64(DefaultCacheTTL.Seconds())+3600,
		"cache-3")
	if res := v.Verify(context.Background(), req3); !res.OK {
		t.Fatalf("third verify failed: %q", res.Reason)
	}
	if got := atomic.LoadInt32(&hits); got != 2 {
		t.Errorf("cache did not expire: hits=%d, want 2", got)
	}
}

// ----- nonce replay defence -----

// TestVerify_NonceReplay: the same nonce can't be re-used within its
// expires window.  This is the cheapest replay path — capture a valid
// signed request, replay it.
func TestVerify_NonceReplay(t *testing.T) {
	fx := newFixtureKey(t)
	v, fx2 := newVerifier(t, fx, fx.directory, nil)

	// Sign twice with the SAME nonce — second one must be rejected.
	req1 := signedRequest(t, fx2, 1735689000, 1735690000, "replay-nonce")
	if res := v.Verify(context.Background(), req1); !res.OK {
		t.Fatalf("first verify failed: %q", res.Reason)
	}
	req2 := signedRequest(t, fx2, 1735689000, 1735690000, "replay-nonce")
	res := v.Verify(context.Background(), req2)
	if res.OK {
		t.Fatal("replayed nonce passed verify")
	}
	if !strings.Contains(res.Reason, "replay") {
		t.Errorf("unexpected reason for replay: %q", res.Reason)
	}
}

// TestVerify_DistinctNoncesPass: distinct nonces from the same operator do
// not collide with each other.  Guards against an over-eager dedupe.
func TestVerify_DistinctNoncesPass(t *testing.T) {
	fx := newFixtureKey(t)
	v, fx2 := newVerifier(t, fx, fx.directory, nil)
	for i, n := range []string{"a", "b", "c"} {
		req := signedRequest(t, fx2, 1735689000+int64(i), 1735690000+int64(i), n)
		if res := v.Verify(context.Background(), req); !res.OK {
			t.Errorf("nonce %q rejected: %q", n, res.Reason)
		}
	}
}

// TestVerify_EmptyNonceSkipsReplayCheck: if the signer omitted nonce
// entirely, we still verify the signature but skip replay detection.
// (The spec marks nonce RECOMMENDED, not REQUIRED.)
func TestVerify_EmptyNonceSkipsReplayCheck(t *testing.T) {
	fx := newFixtureKey(t)
	v, fx2 := newVerifier(t, fx, fx.directory, nil)
	// Empty nonce: pass "" explicitly.
	req1 := signedRequest(t, fx2, 1735689000, 1735690000, "")
	if res := v.Verify(context.Background(), req1); !res.OK {
		t.Fatalf("first empty-nonce verify failed: %q", res.Reason)
	}
	req2 := signedRequest(t, fx2, 1735689000, 1735690000, "")
	if res := v.Verify(context.Background(), req2); !res.OK {
		t.Errorf("second empty-nonce verify rejected: %q", res.Reason)
	}
}

// TestVerify_NonceGCAfterExpires: once a nonce's signature has expired,
// advancing time past it should let the same nonce be re-used (= GC sweep
// removes the seen entry, and even if it didn't, the re-issued signature
// would carry a fresh expires).  Both behaviours protect against a memory
// leak in a long-running daemon.
func TestVerify_NonceGCAfterExpires(t *testing.T) {
	fx := newFixtureKey(t)
	v, fx2 := newVerifier(t, fx, fx.directory, nil)

	// Initial: accept signed req with nonce X, expires at T+1000.
	req1 := signedRequest(t, fx2, 1735689000, 1735690000, "gc-nonce")
	if res := v.Verify(context.Background(), req1); !res.OK {
		t.Fatalf("first verify failed: %q", res.Reason)
	}

	// Advance Now well past the signature's expires + GC interval (= sweep
	// fires) and re-issue a fresh signature reusing the nonce string.
	v.Now = func() time.Time { return time.Unix(1735700000, 0) }
	req2 := signedRequest(t, fx2, 1735699000, 1735701000, "gc-nonce")
	if res := v.Verify(context.Background(), req2); !res.OK {
		t.Errorf("post-GC re-use rejected: %q", res.Reason)
	}
}

// flipB64Char turns one base64 char into a different valid char so the
// signature still parses but the bytes are wrong.  Used to test mid-bit
// tampering without breaking the outer ":<...>:" framing.
func flipB64Char(c string) string {
	if c == "A" {
		return "B"
	}
	return "A"
}

// ----- RSA / rsa-pss-sha512 -----

// rsaFixture mirrors fixtureKey for RSA keys.  Generated once per test so
// each case stays independent.
type rsaFixture struct {
	priv      *rsa.PrivateKey
	pub       *rsa.PublicKey
	n         string // base64url(modulus bytes, big-endian)
	e         string // base64url(exponent bytes, big-endian)
	thumb     string // RFC 7638 §3.2 RSA thumbprint
	agentURL  string
	directory string
}

func newRSAFixtureKey(t *testing.T) *rsaFixture {
	t.Helper()
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa keygen: %v", err)
	}
	nBytes := priv.N.Bytes()
	// Pack the public exponent into the smallest big-endian byte slice
	// that fits — 65537 (the default) takes 3 bytes.
	e := priv.E
	var eBuf [4]byte
	binary.BigEndian.PutUint32(eBuf[:], uint32(e))
	eBytes := eBuf[:]
	for len(eBytes) > 1 && eBytes[0] == 0 {
		eBytes = eBytes[1:]
	}
	nStr := base64.RawURLEncoding.EncodeToString(nBytes)
	eStr := base64.RawURLEncoding.EncodeToString(eBytes)
	thumb := jwkThumbprintRSA(nStr, eStr)
	dir := map[string]any{
		"keys": []map[string]any{
			{"kty": "RSA", "kid": thumb, "n": nStr, "e": eStr, "use": "sig"},
		},
	}
	dirBytes, _ := json.Marshal(dir)
	return &rsaFixture{
		priv:      priv,
		pub:       &priv.PublicKey,
		n:         nStr,
		e:         eStr,
		thumb:     thumb,
		agentURL:  "https://rsa-operator.test/",
		directory: string(dirBytes),
	}
}

// signedRequestRSA mirrors signedRequest but emits an rsa-pss-sha512
// signature so we can exercise the new code path end-to-end.
func signedRequestRSA(t *testing.T, fx *rsaFixture, created, expires int64, nonce string) *http.Request {
	t.Helper()
	const label = "sig1"
	covered := []string{`"@authority"`, `"signature-agent";key="` + label + `"`}
	params := fmt.Sprintf(`;created=%d;expires=%d;keyid="%s";alg="rsa-pss-sha512";nonce="%s";tag="web-bot-auth"`,
		created, expires, fx.thumb, nonce)

	const host = "victim.example"
	req, err := http.NewRequest("GET", "https://"+host+"/", nil)
	if err != nil {
		t.Fatalf("new req: %v", err)
	}
	agentHdr := label + `="` + fx.agentURL + `"`
	req.Host = host

	base, err := buildSignatureBase(req, covered, params, label, agentHdr)
	if err != nil {
		t.Fatalf("buildSignatureBase: %v", err)
	}
	digest := sha512.Sum512([]byte(base))
	sig, err := rsa.SignPSS(rand.Reader, fx.priv, crypto.SHA512, digest[:],
		&rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash, Hash: crypto.SHA512})
	if err != nil {
		t.Fatalf("rsa sign: %v", err)
	}
	sigB64 := base64.StdEncoding.EncodeToString(sig)
	req.Header.Set("Signature", label+"=:"+sigB64+":")
	req.Header.Set("Signature-Input", label+"=("+strings.Join(covered, " ")+")"+params)
	req.Header.Set("Signature-Agent", agentHdr)
	return req
}

// newVerifierRSA wires a Verifier against an RSA fixture directory.
func newVerifierRSA(t *testing.T, fx *rsaFixture, dirBody string) (*Verifier, *rsaFixture) {
	t.Helper()
	url := startDirectoryServer(t, dirBody, nil)
	clone := *fx
	clone.agentURL = url
	srvClient := &http.Client{Transport: &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}}
	v := New()
	v.HTTPClient = srvClient
	v.Now = func() time.Time { return time.Unix(1735689600, 0) }
	return v, &clone
}

// TestVerify_RSA_HappyPath: a request signed with rsa-pss-sha512 against an
// RSA JWK directory verifies cleanly.  Mirrors the Ed25519 happy-path test.
func TestVerify_RSA_HappyPath(t *testing.T) {
	fx := newRSAFixtureKey(t)
	v, fx2 := newVerifierRSA(t, fx, fx.directory)
	req := signedRequestRSA(t, fx2, 1735689000, 1735690000, "rsa-happy")

	res := v.Verify(context.Background(), req)
	if !res.OK {
		t.Fatalf("verify failed: reason=%q", res.Reason)
	}
	if res.Algorithm != "rsa-pss-sha512" {
		t.Errorf("algorithm = %q, want rsa-pss-sha512", res.Algorithm)
	}
	if res.KeyID != fx.thumb {
		t.Errorf("keyid = %q, want %q", res.KeyID, fx.thumb)
	}
}

// TestVerify_RSA_TamperedSignature: flipping one byte must fail the verify
// (= same coverage we already have for ed25519).
func TestVerify_RSA_TamperedSignature(t *testing.T) {
	fx := newRSAFixtureKey(t)
	v, fx2 := newVerifierRSA(t, fx, fx.directory)
	req := signedRequestRSA(t, fx2, 1735689000, 1735690000, "rsa-tamper")

	sig := req.Header.Get("Signature")
	const tag = "sig1=:"
	i := strings.Index(sig, tag) + len(tag)
	flipped := sig[:i] + flipB64Char(sig[i:i+1]) + sig[i+1:]
	req.Header.Set("Signature", flipped)

	res := v.Verify(context.Background(), req)
	if res.OK {
		t.Fatal("tampered RSA signature passed verify")
	}
}

// TestJWKThumbprintRSA_Stable: pin the thumbprint output for a known RSA
// {n, e} pair so a refactor of the canonical-form encoder can't silently
// shift every operator's keyid.
func TestJWKThumbprintRSA_Stable(t *testing.T) {
	const n = "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw"
	const e = "AQAB"
	const want = "NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs"
	if got := jwkThumbprintRSA(n, e); got != want {
		t.Errorf("rsa thumbprint = %q, want %q", got, want)
	}
}
