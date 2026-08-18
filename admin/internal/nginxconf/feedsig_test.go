package nginxconf

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func testFeedKey(t *testing.T) (ed25519.PrivateKey, func()) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	restore := addFeedSigningKeyForTests(pub)
	return priv, restore
}

func TestFeedSignatureRoundtrip(t *testing.T) {
	priv, restore := testFeedKey(t)
	defer restore()
	body := []byte(`{"schemaVersion":1}`)
	line := SignFeed(priv, body)
	if err := VerifyFeedSignature(body, []byte(line)); err != nil {
		t.Fatalf("roundtrip: %v", err)
	}
	// One flipped byte in the document = refusal, which is the whole point.
	if err := VerifyFeedSignature([]byte(`{"schemaVersion":2}`), []byte(line)); err == nil {
		t.Fatal("tampered document verified")
	}
	// A key this build does not trust reads as unknown, not as corrupt.
	_, stray, _ := ed25519.GenerateKey(rand.Reader)
	if err := VerifyFeedSignature(body, []byte(SignFeed(stray, body))); err == nil ||
		!strings.Contains(err.Error(), "unknown key") {
		t.Fatalf("stray key: want unknown-key error, got %v", err)
	}
	if err := VerifyFeedSignature(body, []byte("garbage")); err == nil {
		t.Fatal("garbage signature accepted")
	}
}

// feedDoc: a minimal valid aggregate for the sync tests.
func feedDoc(generatedAt string) []byte {
	doc := AggregatedDoc{
		SchemaVersion: 1,
		GeneratedAt:   generatedAt,
		Sources: map[string]AggregatedSource{
			"google-common": {
				CreationTime: "2026-08-01T00:00:00.000000",
				Prefixes:     []AggregatedPrefix{{IPv4Prefix: "203.0.113.0/24"}},
			},
		},
	}
	raw, _ := json.Marshal(doc)
	return raw
}

// hubFor serves body at / and, when sig != "", the signature at /..sig.
func hubFor(t *testing.T, body []byte, sig string) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, FeedSigSuffix) {
			if sig == "" {
				http.NotFound(w, r)
				return
			}
			_, _ = w.Write([]byte(sig + "\n"))
			return
		}
		_, _ = w.Write(body)
	}))
}

func TestSyncSignaturePolicy(t *testing.T) {
	priv, restore := testFeedKey(t)
	defer restore()
	body := feedDoc("2026-08-18T00:00:00Z")
	good := SignFeed(priv, body)

	// Signed hub + valid signature -> pull succeeds.
	srv := hubFor(t, body, good)
	s := NewSync()
	s.Dir = t.TempDir()
	s.HubURL = srv.URL + "/bypass-iprange-all.json"
	if err := s.PullOnce(t.Context()); err != nil {
		t.Fatalf("valid signature refused: %v", err)
	}
	metaRaw, err := os.ReadFile(filepath.Join(s.Dir, "snapshot-meta.json"))
	if err != nil {
		t.Fatalf("snapshot meta not written: %v", err)
	}
	var meta struct {
		Signature string `json:"signature"`
	}
	if err := json.Unmarshal(metaRaw, &meta); err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(meta.Signature, "verified:") {
		t.Fatalf("a verified pull must record it in the snapshot meta, got %q", meta.Signature)
	}
	srv.Close()

	// Signed hub + WRONG signature (for other bytes) -> hard fail, even
	// though nothing "required" a signature: a present-and-invalid one is
	// the tamper signal.
	srv = hubFor(t, body, SignFeed(priv, []byte("other bytes")))
	s2 := NewSync()
	s2.Dir = t.TempDir()
	s2.HubURL = srv.URL + "/bypass-iprange-all.json"
	if err := s2.PullOnce(t.Context()); err == nil {
		t.Fatal("invalid signature accepted")
	}
	srv.Close()

	// Unsigned hub, default policy -> accepted on transport trust.
	srv = hubFor(t, body, "")
	s3 := NewSync()
	s3.Dir = t.TempDir()
	s3.HubURL = srv.URL + "/bypass-iprange-all.json"
	if err := s3.PullOnce(t.Context()); err != nil {
		t.Fatalf("unsigned + default policy must pass: %v", err)
	}
	srv.Close()

	// Unsigned hub + RequireSignature -> refused.
	srv = hubFor(t, body, "")
	s4 := NewSync()
	s4.Dir = t.TempDir()
	s4.HubURL = srv.URL + "/bypass-iprange-all.json"
	s4.RequireSignature = true
	if err := s4.PullOnce(t.Context()); err == nil {
		t.Fatal("unsigned + required must fail")
	}
	srv.Close()

	// InsecureTLS implies the requirement (the escape hatch is only offered
	// with content verification standing in).
	s5 := NewSync()
	s5.InsecureTLS = true
	if !s5.signatureRequired() {
		t.Fatal("InsecureTLS must imply RequireSignature")
	}
}

func TestSyncRollbackRefused(t *testing.T) {
	dir := t.TempDir()

	newer := hubFor(t, feedDoc("2026-08-18T00:00:00Z"), "")
	s := NewSync()
	s.Dir = dir
	s.HubURL = newer.URL + "/bypass-iprange-all.json"
	if err := s.PullOnce(t.Context()); err != nil {
		t.Fatalf("first pull: %v", err)
	}
	newer.Close()

	older := hubFor(t, feedDoc("2026-08-10T00:00:00Z"), "")
	defer older.Close()
	s2 := NewSync()
	s2.Dir = dir
	s2.HubURL = older.URL + "/bypass-iprange-all.json"
	err := s2.PullOnce(t.Context())
	if err == nil || !strings.Contains(err.Error(), "rollback") {
		t.Fatalf("older document must be refused as a rollback, got %v", err)
	}

	// Equal timestamp = idempotent re-pull, allowed.
	same := hubFor(t, feedDoc("2026-08-18T00:00:00Z"), "")
	defer same.Close()
	s3 := NewSync()
	s3.Dir = dir
	s3.HubURL = same.URL + "/bypass-iprange-all.json"
	if err := s3.PullOnce(t.Context()); err != nil {
		t.Fatalf("equal-timestamp re-pull must pass: %v", err)
	}
}

func TestPullFromFileSignaturePolicy(t *testing.T) {
	priv, restore := testFeedKey(t)
	defer restore()
	body := feedDoc("2026-08-18T00:00:00Z")

	write := func(dir string, withSig bool, sig string) string {
		p := filepath.Join(dir, "bypass-iprange-all.json")
		if err := os.WriteFile(p, body, 0o644); err != nil {
			t.Fatal(err)
		}
		if withSig {
			if err := os.WriteFile(p+FeedSigSuffix, []byte(sig+"\n"), 0o644); err != nil {
				t.Fatal(err)
			}
		}
		return p
	}

	// Sidecar present + valid -> pass.
	s := NewSync()
	s.Dir = t.TempDir()
	if err := s.PullFromFile(write(t.TempDir(), true, SignFeed(priv, body))); err != nil {
		t.Fatalf("valid sidecar refused: %v", err)
	}
	// Sidecar present + invalid -> fail regardless of policy.
	s2 := NewSync()
	s2.Dir = t.TempDir()
	if err := s2.PullFromFile(write(t.TempDir(), true, SignFeed(priv, []byte("x")))); err == nil {
		t.Fatal("invalid sidecar accepted")
	}
	// No sidecar + required -> fail with the sidecar named.
	s3 := NewSync()
	s3.Dir = t.TempDir()
	s3.RequireSignature = true
	if err := s3.PullFromFile(write(t.TempDir(), false, "")); err == nil ||
		!strings.Contains(err.Error(), FeedSigSuffix) {
		t.Fatalf("missing sidecar + required: want a .sig-naming error, got %v", err)
	}
}
