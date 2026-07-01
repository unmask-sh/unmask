package privacypass

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"encoding/binary"
	"math/big"
	"strings"
	"testing"
)

// --- test issuer: build a token-key SPKI + mint type-0x0002 tokens, acting as
// the issuer/attester so the verifier has something real to check.

type testIssuer struct {
	priv    *rsa.PrivateKey
	spkiDER []byte
	keyID   [keyIDLen]byte
}

// rsassaPSSSPKI encodes an RSA public key as a DER SubjectPublicKeyInfo carrying
// the id-RSASSA-PSS OID, matching the token-key format (RFC 9578 Section 6.5).
func rsassaPSSSPKI(t *testing.T, pub *rsa.PublicKey) []byte {
	t.Helper()
	rsaDER, err := asn1.Marshal(struct {
		N *big.Int
		E int
	}{pub.N, pub.E})
	if err != nil {
		t.Fatalf("marshal RSAPublicKey: %v", err)
	}
	spki, err := asn1.Marshal(struct {
		Algorithm pkix.AlgorithmIdentifier
		PublicKey asn1.BitString
	}{
		Algorithm: pkix.AlgorithmIdentifier{Algorithm: oidRSASSAPSS, Parameters: asn1.NullRawValue},
		PublicKey: asn1.BitString{Bytes: rsaDER, BitLength: len(rsaDER) * 8},
	})
	if err != nil {
		t.Fatalf("marshal SPKI: %v", err)
	}
	return spki
}

func newTestIssuer(t *testing.T) testIssuer {
	t.Helper()
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	spki := rsassaPSSSPKI(t, &priv.PublicKey)
	return testIssuer{priv: priv, spkiDER: spki, keyID: sha256.Sum256(spki)}
}

// mint produces a valid 354-byte token bound to challengeDigest.
func (ti testIssuer) mint(t *testing.T, tokenType uint16, nonce [nonceLen]byte, challengeDigest [digestLen]byte) []byte {
	t.Helper()
	input := make([]byte, 0, 98)
	input = binary.BigEndian.AppendUint16(input, tokenType)
	input = append(input, nonce[:]...)
	input = append(input, challengeDigest[:]...)
	input = append(input, ti.keyID[:]...)

	sum := sha512.Sum384(input)
	sig, err := rsa.SignPSS(rand.Reader, ti.priv, crypto.SHA384, sum[:],
		&rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash, Hash: crypto.SHA384})
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	if len(sig) != blindRSAAuthLen {
		t.Fatalf("authenticator len = %d, want %d", len(sig), blindRSAAuthLen)
	}

	tok := make([]byte, 0, blindRSATokLen)
	tok = binary.BigEndian.AppendUint16(tok, tokenType)
	tok = append(tok, nonce[:]...)
	tok = append(tok, challengeDigest[:]...)
	tok = append(tok, ti.keyID[:]...)
	tok = append(tok, sig...)
	if len(tok) != blindRSATokLen {
		t.Fatalf("token len = %d, want %d", len(tok), blindRSATokLen)
	}
	return tok
}

func authzHeader(tok []byte) string {
	return `PrivateToken token="` + base64.RawURLEncoding.EncodeToString(tok) + `"`
}

func testChallengeDigest(t *testing.T) [digestLen]byte {
	t.Helper()
	d, err := TokenChallenge{
		TokenType:  TokenTypeBlindRSA,
		IssuerName: "issuer.example",
		OriginInfo: "site.example",
	}.Digest()
	if err != nil {
		t.Fatalf("challenge digest: %v", err)
	}
	return d
}

func verifierWith(ti testIssuer) *Verifier {
	v := New()
	v.SetIssuerKeys([]IssuerKey{{
		Name:  "test-issuer",
		KeyID: ti.keyID,
		Pub:   &ti.priv.PublicKey,
	}})
	return v
}

func TestVerify_HappyPath(t *testing.T) {
	ti := newTestIssuer(t)
	v := verifierWith(ti)
	digest := testChallengeDigest(t)
	var nonce [nonceLen]byte
	nonce[0], nonce[31] = 0xab, 0xcd

	res := v.Verify(authzHeader(ti.mint(t, TokenTypeBlindRSA, nonce, digest)), digest)
	if !res.OK {
		t.Fatalf("expected OK, got reason=%q", res.Reason)
	}
	if res.Issuer != "test-issuer" {
		t.Errorf("issuer = %q, want test-issuer", res.Issuer)
	}
	if res.Nonce != nonce {
		t.Errorf("nonce not surfaced: %x", res.Nonce)
	}
}

func TestVerifyForOrigin_Binding(t *testing.T) {
	ti := newTestIssuer(t)
	v := New()
	v.SetIssuerKeys([]IssuerKey{{Name: "issuer.example", KeyID: ti.keyID, Pub: &ti.priv.PublicKey}})

	const host = "site.example"
	// The token is minted against the challenge VerifyForOrigin recomputes:
	// issuer_name = the key's Name, origin_info = host.
	digest, err := TokenChallenge{TokenType: TokenTypeBlindRSA, IssuerName: "issuer.example", OriginInfo: host}.Digest()
	if err != nil {
		t.Fatal(err)
	}
	var nonce [nonceLen]byte
	tok := ti.mint(t, TokenTypeBlindRSA, nonce, digest)

	if res := v.VerifyForOrigin(authzHeader(tok), host); !res.OK {
		t.Fatalf("expected OK, reason=%q", res.Reason)
	}
	// Same token presented at a different origin: the digest is recomputed for
	// the wrong host, so the binding check fails (no cross-origin replay).
	if res := v.VerifyForOrigin(authzHeader(tok), "evil.example"); res.OK {
		t.Fatal("token bound to site.example passed for evil.example")
	}
}

func TestSetLoader_ReparseOnChange(t *testing.T) {
	ti := newTestIssuer(t)
	cfgs := []IssuerConfig{{Name: "issuer.example", SPKIB64: base64.StdEncoding.EncodeToString(ti.spkiDER)}}
	v := New()
	v.SetLoader(func() []IssuerConfig { return cfgs })

	const host = "site.example"
	digest, err := TokenChallenge{TokenType: TokenTypeBlindRSA, IssuerName: "issuer.example", OriginInfo: host}.Digest()
	if err != nil {
		t.Fatal(err)
	}
	var nonce [nonceLen]byte
	tok := ti.mint(t, TokenTypeBlindRSA, nonce, digest)

	if res := v.VerifyForOrigin(authzHeader(tok), host); !res.OK {
		t.Fatalf("loader-backed verify failed: %q", res.Reason)
	}
	// Drop the issuer from config: the next verify re-parses (fingerprint
	// changed) and the key is no longer trusted.
	cfgs = nil
	if res := v.VerifyForOrigin(authzHeader(tok), host); res.OK {
		t.Fatal("verify passed after issuer removed from config")
	}
}

func TestVerify_TamperedAuthenticator(t *testing.T) {
	ti := newTestIssuer(t)
	v := verifierWith(ti)
	digest := testChallengeDigest(t)
	var nonce [nonceLen]byte
	tok := ti.mint(t, TokenTypeBlindRSA, nonce, digest)
	tok[len(tok)-1] ^= 0xff // flip a byte in the authenticator

	if res := v.Verify(authzHeader(tok), digest); res.OK {
		t.Fatal("tampered authenticator passed")
	} else if res.Reason != "bad authenticator" {
		t.Errorf("reason = %q, want bad authenticator", res.Reason)
	}
}

func TestVerify_NonceForgeryRejected(t *testing.T) {
	// Flipping the signed nonce must invalidate the authenticator (the nonce is
	// part of token_authenticator_input).
	ti := newTestIssuer(t)
	v := verifierWith(ti)
	digest := testChallengeDigest(t)
	var nonce [nonceLen]byte
	tok := ti.mint(t, TokenTypeBlindRSA, nonce, digest)
	tok[2] ^= 0x01 // first nonce byte sits right after the 2-byte type

	if res := v.Verify(authzHeader(tok), digest); res.OK {
		t.Fatal("forged nonce passed")
	}
}

func TestVerify_UnknownKeyID(t *testing.T) {
	ti := newTestIssuer(t)
	other := newTestIssuer(t) // verifier trusts a different key
	v := verifierWith(other)
	digest := testChallengeDigest(t)
	var nonce [nonceLen]byte

	if res := v.Verify(authzHeader(ti.mint(t, TokenTypeBlindRSA, nonce, digest)), digest); res.OK {
		t.Fatal("token from untrusted issuer passed")
	} else if res.Reason != "unknown token_key_id" {
		t.Errorf("reason = %q, want unknown token_key_id", res.Reason)
	}
}

func TestVerify_ChallengeDigestMismatch(t *testing.T) {
	ti := newTestIssuer(t)
	v := verifierWith(ti)
	digest := testChallengeDigest(t)
	var nonce [nonceLen]byte
	tok := ti.mint(t, TokenTypeBlindRSA, nonce, digest)

	var wrong [digestLen]byte // all zeros, != the real challenge
	if res := v.Verify(authzHeader(tok), wrong); res.OK {
		t.Fatal("token for a different challenge passed")
	} else if res.Reason != "challenge digest mismatch" {
		t.Errorf("reason = %q, want challenge digest mismatch", res.Reason)
	}
}

func TestVerify_UnsupportedTokenType(t *testing.T) {
	ti := newTestIssuer(t)
	v := verifierWith(ti)
	digest := testChallengeDigest(t)
	var nonce [nonceLen]byte
	// type 0x0001 (VOPRF) is structurally a 354-byte blob here but unsupported.
	tok := ti.mint(t, 0x0001, nonce, digest)

	if res := v.Verify(authzHeader(tok), digest); res.OK {
		t.Fatal("unsupported token type passed")
	} else if res.Reason != "unsupported token type" {
		t.Errorf("reason = %q, want unsupported token type", res.Reason)
	}
}

func TestParseAuthorization_Malformed(t *testing.T) {
	cases := []struct{ name, hdr string }{
		{"empty", ""},
		{"wrong scheme", `Bearer abc`},
		{"no token param", `PrivateToken foo="bar"`},
		{"bad base64", `PrivateToken token="not!base64!"`},
		{"short token", `PrivateToken token="` + base64.RawURLEncoding.EncodeToString(make([]byte, 100)) + `"`},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if _, err := ParseAuthorization(c.hdr); err == nil {
				t.Errorf("ParseAuthorization(%q) = nil error, want error", c.hdr)
			}
		})
	}
}

func TestParseAuthorization_Variants(t *testing.T) {
	ti := newTestIssuer(t)
	digest := testChallengeDigest(t)
	var nonce [nonceLen]byte
	tok := ti.mint(t, TokenTypeBlindRSA, nonce, digest)

	// bare (unquoted) value + standard URL encoding with padding.
	bare := "PrivateToken token=" + base64.RawURLEncoding.EncodeToString(tok)
	padded := `PrivateToken token="` + base64.URLEncoding.EncodeToString(tok) + `"`
	for _, hdr := range []string{authzHeader(tok), bare, padded} {
		if _, err := ParseAuthorization(hdr); err != nil {
			t.Errorf("ParseAuthorization(%.40q...) error: %v", hdr, err)
		}
	}
}

func TestIssuerKeyFromSPKI_RoundTrip(t *testing.T) {
	ti := newTestIssuer(t)
	key, err := IssuerKeyFromSPKI("apple", ti.spkiDER)
	if err != nil {
		t.Fatalf("IssuerKeyFromSPKI: %v", err)
	}
	if key.KeyID != ti.keyID {
		t.Errorf("KeyID mismatch:\n got %x\nwant %x", key.KeyID, ti.keyID)
	}
	if key.Pub.N.Cmp(ti.priv.N) != 0 || key.Pub.E != ti.priv.E {
		t.Error("parsed RSA public key does not match")
	}
	if key.Name != "apple" {
		t.Errorf("name = %q", key.Name)
	}
}

func TestIssuerKeyFromSPKI_WrongOID(t *testing.T) {
	ti := newTestIssuer(t)
	rsaDER, _ := asn1.Marshal(struct {
		N *big.Int
		E int
	}{ti.priv.N, ti.priv.E})
	// rsaEncryption (1.2.840.113549.1.1.1), not id-RSASSA-PSS: must be rejected.
	bad, _ := asn1.Marshal(struct {
		Algorithm pkix.AlgorithmIdentifier
		PublicKey asn1.BitString
	}{
		Algorithm: pkix.AlgorithmIdentifier{
			Algorithm:  asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 1},
			Parameters: asn1.NullRawValue,
		},
		PublicKey: asn1.BitString{Bytes: rsaDER, BitLength: len(rsaDER) * 8},
	})
	if _, err := IssuerKeyFromSPKI("x", bad); err == nil {
		t.Fatal("expected rejection of non-RSASSA-PSS SPKI")
	}
}

func TestTokenChallenge_Marshal(t *testing.T) {
	c := TokenChallenge{TokenType: TokenTypeBlindRSA, IssuerName: "issuer.example"}
	b, err := c.Marshal()
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	// 2 (type) + 2 (issuer len) + 14 (issuer) + 1 (rc len=0) + 2 (origin len=0).
	if len(b) != 21 {
		t.Fatalf("len = %d, want 21", len(b))
	}
	if binary.BigEndian.Uint16(b[0:2]) != TokenTypeBlindRSA {
		t.Error("token_type not encoded")
	}
	if binary.BigEndian.Uint16(b[2:4]) != 14 {
		t.Error("issuer_name length prefix wrong")
	}
	if string(b[4:18]) != "issuer.example" {
		t.Error("issuer_name body wrong")
	}
	if b[18] != 0 {
		t.Error("redemption_context length should be 0")
	}

	// redemption_context must be 0 or 32 bytes.
	if _, err := (TokenChallenge{RedemptionContext: make([]byte, 16)}).Marshal(); err == nil {
		t.Error("expected error for 16-byte redemption_context")
	}
	if _, err := (TokenChallenge{RedemptionContext: make([]byte, 32)}).Marshal(); err != nil {
		t.Errorf("32-byte redemption_context should be valid: %v", err)
	}
}

func extractParam(t *testing.T, hdr, key string) string {
	t.Helper()
	marker := key + `="`
	i := strings.Index(hdr, marker)
	if i < 0 {
		t.Fatalf("param %q not found in %q", key, hdr)
	}
	rest := hdr[i+len(marker):]
	j := strings.IndexByte(rest, '"')
	if j < 0 {
		t.Fatalf("unterminated %q value in %q", key, hdr)
	}
	return rest[:j]
}

func TestBuildChallengeHeader_EmitVerifyRoundTrip(t *testing.T) {
	ti := newTestIssuer(t)
	const host = "site.example"
	issuers := []IssuerConfig{{Name: "issuer.example", SPKIB64: base64.StdEncoding.EncodeToString(ti.spkiDER)}}

	hdr := BuildChallengeHeader(issuers, host)
	if hdr == "" {
		t.Fatal("empty header")
	}

	// The emitted challenge must equal the TokenChallenge the verifier recomputes
	// for this issuer + origin (so a token minted against it will verify).
	chBytes, err := base64.URLEncoding.DecodeString(extractParam(t, hdr, "challenge"))
	if err != nil {
		t.Fatalf("challenge b64: %v", err)
	}
	want, _ := TokenChallenge{TokenType: TokenTypeBlindRSA, IssuerName: "issuer.example", OriginInfo: host}.Marshal()
	if !bytes.Equal(chBytes, want) {
		t.Error("emitted challenge != recomputed challenge")
	}
	// token-key must round-trip to the issuer SPKI.
	tkBytes, err := base64.URLEncoding.DecodeString(extractParam(t, hdr, "token-key"))
	if err != nil {
		t.Fatalf("token-key b64: %v", err)
	}
	if !bytes.Equal(tkBytes, ti.spkiDER) {
		t.Error("emitted token-key != issuer SPKI")
	}

	// End-to-end: a token minted against the EMITTED challenge passes VerifyForOrigin.
	digest := sha256.Sum256(chBytes)
	var nonce [nonceLen]byte
	v := New()
	v.SetLoader(func() []IssuerConfig { return issuers })
	if res := v.VerifyForOrigin(authzHeader(ti.mint(t, TokenTypeBlindRSA, nonce, digest)), host); !res.OK {
		t.Fatalf("token minted against emitted challenge failed verify: %q", res.Reason)
	}
}

func TestBuildChallengeHeader_MultipleAndSkip(t *testing.T) {
	ti := newTestIssuer(t)
	good := base64.StdEncoding.EncodeToString(ti.spkiDER)
	issuers := []IssuerConfig{
		{Name: "a.example", SPKIB64: good},
		{Name: "bad", SPKIB64: "!!!not-base64!!!"}, // skipped (not base64)
		{Name: "", SPKIB64: good},                  // skipped (no name)
		{Name: "notspki", SPKIB64: base64.StdEncoding.EncodeToString([]byte("valid base64, not a token-key"))}, // skipped (won't parse)
		{Name: "b.example", SPKIB64: good},
	}
	hdr := BuildChallengeHeader(issuers, "h.example")
	if n := strings.Count(hdr, "PrivateToken "); n != 2 {
		t.Errorf("want 2 PrivateToken entries, got %d in %q", n, hdr)
	}
	if BuildChallengeHeader(nil, "h.example") != "" {
		t.Error("empty issuer list should yield empty header")
	}
}
