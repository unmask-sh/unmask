package webbotauth

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"
)

// TestVerify_E2ESignerFormat replicates byte-for-byte what e2e/lib/wbasign.go
// emits and runs it through Verify the way handlers.wbaVerifyRequest presents
// a forwarded request.  Scenario 34 depends on this exact compatibility; a
// drift in either the signer or the verifier shows up here with the Reason,
// without booting the docker rig.
func TestVerify_E2ESignerFormat(t *testing.T) {
	// Fixed seed (NOT the committed fixture; any seed proves format compat).
	seed, _ := hex.DecodeString(strings.Repeat("ab", 32))
	priv := ed25519.NewKeyFromSeed(seed)
	pub := priv.Public().(ed25519.PublicKey)
	x := base64.RawURLEncoding.EncodeToString(pub)
	type canonical struct {
		Crv string `json:"crv"`
		Kty string `json:"kty"`
		X   string `json:"x"`
	}
	cb, _ := json.Marshal(canonical{Crv: "Ed25519", Kty: "OKP", X: x})
	sum := sha256.Sum256(cb)
	kid := base64.RawURLEncoding.EncodeToString(sum[:])
	dir, _ := json.Marshal(map[string]any{"keys": []map[string]any{
		{"kty": "OKP", "crv": "Ed25519", "kid": kid, "x": x, "use": "sig"},
	}})

	v, fx := newVerifier(t, &fixtureKey{priv: priv, pub: pub, xRaw: x, thumb: kid, agentURL: "ignored"}, string(dir), nil)
	v.Now = time.Now // the signer stamps real time; the verifier must agree
	agentURL := fx.agentURL // the httptest server's https URL

	// ---- byte-for-byte copy of e2e/lib/wbasign.go main() ----
	authority := "localhost"
	nonce := "compat-test-nonce"
	const label = "sig1"
	covered := []string{`"@authority"`, `"signature-agent";key="` + label + `"`}
	created := time.Now().Unix()
	params := fmt.Sprintf(`;created=%d;expires=%d;keyid="%s";alg="ed25519";nonce="%s";tag="web-bot-auth"`,
		created, created+300, kid, nonce)
	agentHdr := label + `="` + agentURL + `"`
	var base strings.Builder
	base.WriteString(`"@authority": ` + strings.ToLower(authority) + "\n")
	base.WriteString(covered[1] + `: "` + agentURL + `"` + "\n")
	base.WriteString(`"@signature-params": (` + strings.Join(covered, " ") + ")" + params)
	sig := ed25519.Sign(priv, []byte(base.String()))

	sigInput := fmt.Sprintf("%s=(%s)%s", label, strings.Join(covered, " "), params)
	sigHdr := fmt.Sprintf("%s=:%s:", label, base64.StdEncoding.EncodeToString(sig))
	// ---- end signer copy ----

	// Present it the way wbaVerifyRequest does for a forwarded check:
	// Host = X-Original-Host, URL = X-Original-URI made absolute.
	req := &http.Request{
		Method: "GET",
		Host:   "localhost",
		URL:    &url.URL{Scheme: "https", Host: "localhost", Path: "/wba-test"},
		Header: http.Header{},
	}
	req.Header.Set("Signature-Input", sigInput)
	req.Header.Set("Signature", sigHdr)
	req.Header.Set("Signature-Agent", agentHdr)

	res := v.Verify(t.Context(), req)
	if !res.OK {
		t.Fatalf("e2e signer format must verify, got Reason=%q", res.Reason)
	}
}
