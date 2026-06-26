package handlers

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"math/big"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/unmask-sh/unmask/admin/internal/settings"
)

// rsassaPSSSPKIForTest mirrors a published token-key: a DER SPKI with the
// id-RSASSA-PSS OID wrapping an RSA public key, base64-encoded as the operator
// would paste it into the issuer config.
func rsassaPSSSPKIForTest(t *testing.T) string {
	t.Helper()
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	rsaDER, err := asn1.Marshal(struct {
		N *big.Int
		E int
	}{priv.N, priv.E})
	if err != nil {
		t.Fatal(err)
	}
	spki, err := asn1.Marshal(struct {
		Algorithm pkix.AlgorithmIdentifier
		PublicKey asn1.BitString
	}{
		Algorithm: pkix.AlgorithmIdentifier{
			Algorithm:  asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 10}, // id-RSASSA-PSS
			Parameters: asn1.NullRawValue,
		},
		PublicKey: asn1.BitString{Bytes: rsaDER, BitLength: len(rsaDER) * 8},
	})
	if err != nil {
		t.Fatal(err)
	}
	return base64.StdEncoding.EncodeToString(spki)
}

// ServeChallenge advertises a PrivateToken challenge (and switches the status to
// 401) only when Privacy Pass is enabled with a usable issuer; otherwise the
// challenge stays a 403 with no WWW-Authenticate header.
func TestServeChallenge_PrivacyPassEmission(t *testing.T) {
	h := newTestHandler(t)

	// PAT off (default): 403, no WWW-Authenticate.
	req := httptest.NewRequest("GET", "/unmask/challenge/", nil)
	req.Host = "site.example"
	w := httptest.NewRecorder()
	h.ServeChallenge(w, req)
	if w.Code != 403 {
		t.Fatalf("PAT off: want 403, got %d", w.Code)
	}
	if got := w.Header().Get("WWW-Authenticate"); got != "" {
		t.Errorf("PAT off: WWW-Authenticate should be absent, got %q", got)
	}

	// PAT on with a usable issuer: 401 + a PrivateToken challenge for the host.
	s := *h.cfg()
	s.Nginx.AdvancedEnabled = true // master gate: emission also AND-gates on this
	s.Nginx.PrivacyPass = settings.PrivacyPassConfig{
		Enabled: true,
		Issuers: []settings.PrivacyPassIssuer{{Name: "issuer.example", Key: rsassaPSSSPKIForTest(t)}},
	}
	h.SetSettings(s)

	req2 := httptest.NewRequest("GET", "/unmask/challenge/", nil)
	req2.Host = "site.example"
	w2 := httptest.NewRecorder()
	h.ServeChallenge(w2, req2)
	if w2.Code != 401 {
		t.Fatalf("PAT on: want 401, got %d", w2.Code)
	}
	wa := w2.Header().Get("WWW-Authenticate")
	if !strings.HasPrefix(wa, "PrivateToken ") || !strings.Contains(wa, "challenge=") || !strings.Contains(wa, "token-key=") {
		t.Errorf("PAT on: unexpected WWW-Authenticate: %q", wa)
	}

	// An enabled-but-unusable issuer (bad key) must NOT flip the status: nothing
	// to advertise, so the challenge stays a plain 403.
	s.Nginx.PrivacyPass.Issuers = []settings.PrivacyPassIssuer{{Name: "broken", Key: "not-base64!!"}}
	h.SetSettings(s)
	req3 := httptest.NewRequest("GET", "/unmask/challenge/", nil)
	req3.Host = "site.example"
	w3 := httptest.NewRecorder()
	h.ServeChallenge(w3, req3)
	if w3.Code != 403 {
		t.Fatalf("PAT on, unusable issuer: want 403, got %d", w3.Code)
	}
	if got := w3.Header().Get("WWW-Authenticate"); got != "" {
		t.Errorf("PAT on, unusable issuer: WWW-Authenticate should be absent, got %q", got)
	}

	// Advanced master OFF must suppress emission even with a usable issuer and
	// PrivacyPass.Enabled=true: the status stays a plain 403, no challenge.
	s.Nginx.AdvancedEnabled = false
	s.Nginx.PrivacyPass.Issuers = []settings.PrivacyPassIssuer{{Name: "issuer.example", Key: rsassaPSSSPKIForTest(t)}}
	h.SetSettings(s)
	req4 := httptest.NewRequest("GET", "/unmask/challenge/", nil)
	req4.Host = "site.example"
	w4 := httptest.NewRecorder()
	h.ServeChallenge(w4, req4)
	if w4.Code != 403 {
		t.Fatalf("advanced master off: want 403, got %d", w4.Code)
	}
	if got := w4.Header().Get("WWW-Authenticate"); got != "" {
		t.Errorf("advanced master off: WWW-Authenticate should be absent, got %q", got)
	}
}
