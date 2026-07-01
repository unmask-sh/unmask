// wbasign: e2e Web Bot Auth (RFC 9421) request signer.
//
// Emits the three signature headers a signed agent sends, one per line:
//
//	Signature-Input: sig1=("@authority" "signature-agent";key="sig1");created=...
//	Signature: sig1=:base64:
//	Signature-Agent: sig1="https://nginx:9444/"
//
// The covered components and serialization mirror what real signed agents
// send (and what admin/internal/webbotauth verifies): @authority + the
// signature-agent dictionary member, signed with ed25519 under the
// "web-bot-auth" tag.  A fresh random nonce is generated per invocation so
// repeated runs don't trip the verifier's replay defence — unless -nonce
// pins one, which scenario 34 uses to PROVE the replay defence fires.
//
// Stdlib-only on purpose: the e2e harness runs it via `go run` from the
// host, outside any Go module.
//
// Usage:
//
//	go run e2e/lib/wbasign.go -seed e2e/docker/wba/signer-ed25519.seed \
//	    -kid "$(cat e2e/docker/wba/signer.kid)" \
//	    -authority localhost -agent "https://nginx:9444/"
package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"
)

func main() {
	seedPath := flag.String("seed", "", "path to a file holding the hex ed25519 seed")
	kid := flag.String("kid", "", "JWK key id (thumbprint) published in the operator directory")
	authority := flag.String("authority", "", `value of the signed "@authority" component (= the target site's host)`)
	agentURL := flag.String("agent", "", "Signature-Agent URL (= the operator's https base URL)")
	nonce := flag.String("nonce", "", "pin the nonce (default: random per run)")
	ttl := flag.Int64("ttl", 300, "seconds until the signature expires")
	flag.Parse()
	if *seedPath == "" || *kid == "" || *authority == "" || *agentURL == "" {
		fmt.Fprintln(os.Stderr, "wbasign: -seed, -kid, -authority, -agent are required")
		os.Exit(2)
	}

	seedHex, err := os.ReadFile(*seedPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, "wbasign:", err)
		os.Exit(1)
	}
	seed, err := hex.DecodeString(strings.TrimSpace(string(seedHex)))
	if err != nil || len(seed) != ed25519.SeedSize {
		fmt.Fprintln(os.Stderr, "wbasign: seed file must hold a 32-byte hex seed")
		os.Exit(1)
	}
	priv := ed25519.NewKeyFromSeed(seed)

	if *nonce == "" {
		raw := make([]byte, 16)
		if _, err := rand.Read(raw); err != nil {
			fmt.Fprintln(os.Stderr, "wbasign:", err)
			os.Exit(1)
		}
		*nonce = hex.EncodeToString(raw)
	}

	const label = "sig1"
	covered := []string{`"@authority"`, `"signature-agent";key="` + label + `"`}
	created := time.Now().Unix()
	params := fmt.Sprintf(`;created=%d;expires=%d;keyid="%s";alg="ed25519";nonce="%s";tag="web-bot-auth"`,
		created, created+*ttl, *kid, *nonce)
	agentHdr := label + `="` + *agentURL + `"`

	// Signature base per RFC 9421 §2.5 — must byte-match what the verifier
	// recomputes (webbotauth.buildSignatureBase).
	var base strings.Builder
	base.WriteString(`"@authority": ` + strings.ToLower(*authority) + "\n")
	base.WriteString(covered[1] + `: "` + *agentURL + `"` + "\n")
	base.WriteString(`"@signature-params": (` + strings.Join(covered, " ") + ")" + params)

	sig := ed25519.Sign(priv, []byte(base.String()))

	fmt.Printf("Signature-Input: %s=(%s)%s\n", label, strings.Join(covered, " "), params)
	fmt.Printf("Signature: %s=:%s:\n", label, base64.StdEncoding.EncodeToString(sig))
	fmt.Printf("Signature-Agent: %s\n", agentHdr)
}
