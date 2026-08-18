// sign-feed: produce (or verify) the detached ed25519 signature the hub
// publishes next to its feed documents (see nginxconf/feedsig.go).  Runs on
// the signing host as part of feed publication; also usable by third parties
// running their own hub, and by operators who want to check a transferred
// file by hand before importing it.
//
//	unmask sign-feed -keygen -key /path/feed.seed     # one-time key creation
//	unmask sign-feed -key /path/feed.seed FILE        # writes FILE.sig
//	unmask sign-feed -verify FILE                     # checks FILE against FILE.sig
package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/unmask-sh/unmask/admin/internal/nginxconf"
)

func cmdSignFeed(args []string) error {
	fs := flag.NewFlagSet("sign-feed", flag.ExitOnError)
	keyPath := fs.String("key", "", "path to the ed25519 seed file (64 hex chars)")
	keygen := fs.Bool("keygen", false, "generate a new key at -key (refuses to overwrite) and print its public half")
	verify := fs.Bool("verify", false, "verify FILE against FILE.sig with this build's trusted keys instead of signing")
	_ = fs.Parse(args)

	if *keygen {
		if *keyPath == "" {
			return fmt.Errorf("-keygen needs -key <path>")
		}
		if _, err := os.Stat(*keyPath); err == nil {
			return fmt.Errorf("%s already exists — refusing to overwrite a signing key", *keyPath)
		}
		pub, priv, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			return err
		}
		seed := hex.EncodeToString(priv.Seed())
		if err := os.WriteFile(*keyPath, []byte(seed+"\n"), 0o600); err != nil {
			return err
		}
		fmt.Printf("seed written to %s (mode 0600 — back it up, never publish it)\n", *keyPath)
		fmt.Printf("public key: %s\n", hex.EncodeToString(pub))
		fmt.Printf("key id    : %s\n", nginxconf.FeedKeyID(pub))
		return nil
	}

	if fs.NArg() != 1 {
		return fmt.Errorf("usage: unmask sign-feed [-keygen] [-verify] -key <seed> <file>")
	}
	file := fs.Arg(0)
	body, err := os.ReadFile(file)
	if err != nil {
		return err
	}

	if *verify {
		sig, err := os.ReadFile(file + nginxconf.FeedSigSuffix)
		if err != nil {
			return fmt.Errorf("read signature: %w", err)
		}
		if err := nginxconf.VerifyFeedSignature(body, sig); err != nil {
			return fmt.Errorf("verification FAILED: %w", err)
		}
		fmt.Println("signature OK")
		return nil
	}

	if *keyPath == "" {
		return fmt.Errorf("signing needs -key <seed file>")
	}
	seedHex, err := os.ReadFile(*keyPath)
	if err != nil {
		return err
	}
	seed, err := hex.DecodeString(strings.TrimSpace(string(seedHex)))
	if err != nil || len(seed) != ed25519.SeedSize {
		return fmt.Errorf("%s does not hold a 64-hex-char ed25519 seed", *keyPath)
	}
	priv := ed25519.NewKeyFromSeed(seed)
	line := nginxconf.SignFeed(priv, body)
	out := file + nginxconf.FeedSigSuffix
	if err := os.WriteFile(out, []byte(line+"\n"), 0o644); err != nil {
		return err
	}
	fmt.Printf("wrote %s (key %s)\n", out, strings.SplitN(line, ":", 3)[1])
	return nil
}
