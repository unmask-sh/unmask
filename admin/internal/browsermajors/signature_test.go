package browsermajors

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/unmask-sh/unmask/admin/internal/classify"
	"github.com/unmask-sh/unmask/admin/internal/nginxconf"
	"github.com/unmask-sh/unmask/admin/internal/settings"
)

// testSigningKey makes verifySignature trust a key of the test's own, and
// returns it.
func testSigningKey(t *testing.T) ed25519.PrivateKey {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	prev := verifySignature
	verifySignature = func(body, sigLine []byte) error {
		parts := strings.SplitN(strings.TrimSpace(string(sigLine)), ":", 3)
		if len(parts) != 3 || parts[0] != "ed25519" || parts[1] != nginxconf.FeedKeyID(pub) {
			return errors.New("signed by another key")
		}
		sig, err := base64.StdEncoding.DecodeString(parts[2])
		if err != nil || !ed25519.Verify(pub, body, sig) {
			return errors.New("signature does not match the document")
		}
		return nil
	}
	t.Cleanup(func() { verifySignature = prev })
	return priv
}

// hub serves doc at /browser-majors.json and, beside it, the signature: sig
// as given, a 404 for "", a dropped connection for "drop".
func hub(t *testing.T, doc, sig string) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/browser-majors.json":
			_, _ = w.Write([]byte(doc))
		case r.URL.Path == "/browser-majors.json"+nginxconf.FeedSigSuffix && sig == "drop":
			if c, _, err := w.(http.Hijacker).Hijack(); err == nil {
				c.Close()
			}
		case r.URL.Path == "/browser-majors.json"+nginxconf.FeedSigSuffix && sig != "":
			_, _ = w.Write([]byte(sig))
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)
	return srv
}

// raisedDoc: a document with both majors far above this build's, as far as
// Validate lets a document go.
func raisedDoc() string {
	return fmt.Sprintf(`{"schemaVersion":1,"generatedAt":"2026-11-17T00:00:00Z","chrome":{"major":%d},"firefox":{"major":%d}}`,
		settings.DefaultCurrentChromeMajor+150, settings.DefaultCurrentFirefoxMajor+150)
}

// currentChromeIsStale: whether this build's current Chrome reads as out of
// date under the baselines in force.
func currentChromeIsStale() bool {
	var g settings.GlobalConfig
	ua := fmt.Sprintf("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/%d.0.0.0 Safari/537.36", settings.DefaultCurrentChromeMajor)
	return classify.IsStaleBrowser(ua, g.CurrentChromeMajorResolved(), g.CurrentFirefoxMajorResolved(), g.FirefoxESRMajors(), g.StaleBrowserLagN(), g.FirefoxStaleLagN())
}

// The published document is signed on a host other than the one serving it.
// The pull took a document whose signature could not be had -- a 404 for
// it, a failed request -- on trust of the transport, so whoever held the
// serving host could publish majors of their own: raised, they make every
// current Chrome and Firefox read as out of date on each install with the
// stale-browser tier on.  The published document is now refused without a
// signature that verifies, as the bypass ranges are.
func TestPublishedDocumentIsHeldToItsSignature(t *testing.T) {
	priv := testSigningKey(t)
	doc := raisedDoc()
	pull := func(sig string) (*Sync, error) {
		t.Helper()
		resetHub(t)
		srv := hub(t, doc, sig)
		prev := publishedHubURL
		publishedHubURL = srv.URL + "/browser-majors.json"
		t.Cleanup(func() { publishedHubURL = prev })
		s := NewSync() // no HubURL: the published document
		s.StatePath = filepath.Join(t.TempDir(), "state.json")
		return s, s.PullOnce(context.Background())
	}
	for name, sig := range map[string]string{
		"no signature published":       "",
		"the signature request failed": "drop",
		"a signature of other bytes":   nginxconf.SignFeed(priv, []byte("another document")),
		"not a signature":              "ed25519:0000000000000000:AAAA",
	} {
		s, err := pull(sig)
		if err == nil {
			t.Errorf("%s: the document was accepted", name)
		}
		if _, applied := settings.HubBrowserBaselines(); applied || currentChromeIsStale() {
			t.Errorf("%s: the refused document's majors are in force", name)
		}
		if _, statErr := os.Stat(s.StatePath); statErr == nil {
			t.Errorf("%s: the refused document was kept for the next start", name)
		}
		if s.LastError() == "" {
			t.Errorf("%s: the refusal is not recorded for the settings page", name)
		}
	}
	// Signed by a key this build trusts: taken.
	if _, err := pull(nginxconf.SignFeed(priv, []byte(doc))); err != nil {
		t.Fatalf("a signed document was refused: %v", err)
	}
	if hubVals, ok := settings.HubBrowserBaselines(); !ok || hubVals.Chrome != settings.DefaultCurrentChromeMajor+150 {
		t.Errorf("the signed document was not applied: %+v ok=%v", hubVals, ok)
	}
}

// A hub of the operator's own may not sign at all: there a missing signature
// is refused only where they asked for one (sync_require_signature).  A
// signature that is there and wrong is refused either way.
func TestOwnHubSignatureIsTheOperatorsChoice(t *testing.T) {
	priv := testSigningKey(t)
	pull := func(sig string, require bool) error {
		t.Helper()
		resetHub(t)
		s := NewSync()
		s.HubURL = hub(t, goodDoc, sig).URL + "/browser-majors.json"
		s.StatePath = filepath.Join(t.TempDir(), "state.json")
		s.RequireSignature = require
		return s.PullOnce(context.Background())
	}
	if err := pull("", false); err != nil {
		t.Errorf("an unsigned hub of the operator's own, no signature asked for: %v", err)
	}
	if err := pull("", true); err == nil {
		t.Error("sync_require_signature: an unsigned document was accepted")
	}
	if err := pull("drop", true); err == nil {
		t.Error("sync_require_signature: a document whose signature could not be fetched was accepted")
	}
	if err := pull(nginxconf.SignFeed(priv, []byte("another document")), false); err == nil {
		t.Error("a signature of other bytes was accepted")
	}
	if err := pull(nginxconf.SignFeed(priv, []byte(goodDoc)), true); err != nil {
		t.Errorf("sync_require_signature: a signed document was refused: %v", err)
	}
}
