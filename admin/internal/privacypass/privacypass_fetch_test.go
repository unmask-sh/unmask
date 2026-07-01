package privacypass

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// TestLive_IssuerDirectories fetches the real preset issuer directories and
// confirms fetchDirectory parses out usable type-0x0002 keys.  Network-guarded
// (UNMASK_LIVE=1) so it never runs in CI / offline.
func TestLive_IssuerDirectories(t *testing.T) {
	if os.Getenv("UNMASK_LIVE") == "" {
		t.Skip("set UNMASK_LIVE=1 to run the network directory fetch")
	}
	for name, url := range map[string]string{
		"cloudflare":      "https://demo-pat.issuer.cloudflare.com/.well-known/private-token-issuer-directory",
		"cloudflare-prod": "https://dap.pat-issuer.cloudflare.com/.well-known/private-token-issuer-directory",
		"fastly":          "https://demo-issuer.private-access-tokens.fastly.com/.well-known/token-issuer-directory",
	} {
		v := New()
		keys, err := v.fetchDirectory(name, url)
		if err != nil {
			t.Errorf("%s: fetch %s: %v", name, url, err)
			continue
		}
		if len(keys) == 0 {
			t.Errorf("%s: no usable token-keys", name)
		}
		t.Logf("%s: parsed %d type-0x0002 key(s)", name, len(keys))
	}
}

// issuerDirectoryJSON builds an RFC 9578 token-key directory advertising one
// publicly verifiable (type 0x0002) key.
func issuerDirectoryJSON(spkiDER []byte) string {
	b, _ := json.Marshal(map[string]any{
		"issuer-request-uri": "/token-request",
		"token-keys": []map[string]any{
			{"token-type": TokenTypeBlindRSA, "token-key": base64.RawURLEncoding.EncodeToString(spkiDER)},
		},
	})
	return string(b)
}

func presetVerify(t *testing.T, v *Verifier, ti testIssuer, host string) Result {
	t.Helper()
	digest, err := TokenChallenge{TokenType: TokenTypeBlindRSA, IssuerName: "issuer.example", OriginInfo: host}.Digest()
	if err != nil {
		t.Fatal(err)
	}
	var nonce [nonceLen]byte
	return v.VerifyForOrigin(authzHeader(ti.mint(t, TokenTypeBlindRSA, nonce, digest)), host)
}

// A preset issuer's keys come from its directory: a token minted with the key
// the directory advertises verifies.
func TestPreset_FetchDirectory(t *testing.T) {
	ti := newTestIssuer(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, issuerDirectoryJSON(ti.spkiDER))
	}))
	defer srv.Close()

	v := New()
	v.SetLoader(func() []IssuerConfig {
		return []IssuerConfig{{Name: "issuer.example", DirectoryURL: srv.URL}}
	})
	if res := presetVerify(t, v, ti, "site.example"); !res.OK {
		t.Fatalf("verify with fetched directory key failed: %q", res.Reason)
	}
}

// When the directory fetch fails, the embedded snapshot keys still verify.
func TestPreset_SnapshotFallbackOnFetchFailure(t *testing.T) {
	ti := newTestIssuer(t)
	srv := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	deadURL := srv.URL
	srv.Close() // now unreachable

	v := New()
	v.httpc = &http.Client{Timeout: time.Second}
	v.SetLoader(func() []IssuerConfig {
		return []IssuerConfig{{
			Name:         "issuer.example",
			DirectoryURL: deadURL,
			SnapshotKeys: []string{base64.StdEncoding.EncodeToString(ti.spkiDER)},
		}}
	})
	if res := presetVerify(t, v, ti, "site.example"); !res.OK {
		t.Fatalf("snapshot fallback failed: %q", res.Reason)
	}
}

// The directory is fetched once and cached for the TTL, then re-fetched.
func TestPreset_DirectoryCachedWithTTL(t *testing.T) {
	ti := newTestIssuer(t)
	var hits int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&hits, 1)
		fmt.Fprint(w, issuerDirectoryJSON(ti.spkiDER))
	}))
	defer srv.Close()

	now := time.Unix(1_700_000_000, 0)
	v := New()
	v.ttl = time.Hour
	v.clock = func() time.Time { return now }
	v.SetLoader(func() []IssuerConfig {
		return []IssuerConfig{{Name: "issuer.example", DirectoryURL: srv.URL}}
	})

	for i := 0; i < 3; i++ {
		if res := presetVerify(t, v, ti, "site.example"); !res.OK {
			t.Fatalf("verify %d failed: %q", i, res.Reason)
		}
	}
	if got := atomic.LoadInt32(&hits); got != 1 {
		t.Errorf("directory fetched %d times within TTL, want 1", got)
	}
	now = now.Add(2 * time.Hour) // past the TTL
	presetVerify(t, v, ti, "site.example")
	if got := atomic.LoadInt32(&hits); got != 2 {
		t.Errorf("after TTL expiry, fetched %d times, want 2", got)
	}
}

// Emission: a preset issuer advertises a challenge with NO token-key (the client
// fetches the key out-of-band); a custom issuer includes its token-key.
func TestBuildChallengeHeader_PresetOmitsTokenKey(t *testing.T) {
	ti := newTestIssuer(t)
	cfgs := []IssuerConfig{
		{Name: "preset.example", DirectoryURL: "https://preset.example/.well-known/x"},
		{Name: "custom.example", SPKIB64: base64.StdEncoding.EncodeToString(ti.spkiDER)},
	}
	hdr := BuildChallengeHeader(cfgs, "site.example")
	if n := strings.Count(hdr, "PrivateToken "); n != 2 {
		t.Fatalf("want 2 challenge entries, got %d in %q", n, hdr)
	}
	if n := strings.Count(hdr, "token-key="); n != 1 {
		t.Errorf("want exactly 1 token-key (custom only), got %d in %q", n, hdr)
	}
}
