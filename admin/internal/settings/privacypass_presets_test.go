package settings

import (
	"encoding/base64"
	"errors"
	"testing"

	"github.com/unmask-sh/unmask/admin/internal/privacypass"
)

func decodeAnyB64(s string) ([]byte, error) {
	for _, enc := range []*base64.Encoding{
		base64.RawURLEncoding, base64.URLEncoding,
		base64.RawStdEncoding, base64.StdEncoding,
	} {
		if b, err := enc.DecodeString(s); err == nil {
			return b, nil
		}
	}
	return nil, errors.New("no base64 encoding matched")
}

// The embedded snapshot keys must be valid id-RSASSA-PSS SPKIs -- a copy-paste
// slip would make a preset silently fail to verify any token.
func TestPrivacyPassPresetSnapshotKeysAreValid(t *testing.T) {
	if len(PrivacyPassIssuerPresets) == 0 {
		t.Fatal("no issuer presets defined")
	}
	for _, p := range PrivacyPassIssuerPresets {
		if p.ID == "" || p.IssuerName == "" || p.DirectoryURL == "" {
			t.Errorf("preset %q: missing ID / IssuerName / DirectoryURL", p.Label)
		}
		if len(p.SnapshotKeys) == 0 {
			t.Errorf("preset %q: no snapshot keys", p.ID)
		}
		for i, k := range p.SnapshotKeys {
			der, err := decodeAnyB64(k)
			if err != nil {
				t.Errorf("preset %q key %d: base64 decode failed", p.ID, i)
				continue
			}
			if _, err := privacypass.IssuerKeyFromSPKI(p.IssuerName, der); err != nil {
				t.Errorf("preset %q key %d: not a valid id-RSASSA-PSS SPKI: %v", p.ID, i, err)
			}
		}
	}
}

// IssuerConfigs flattens enabled presets (one entry per snapshot key) + custom
// issuers; disabled presets contribute nothing.
func TestPrivacyPassIssuerConfigs(t *testing.T) {
	c := PrivacyPassConfig{
		EnabledIssuerPresets: []string{"cloudflare"},
		Issuers:              []PrivacyPassIssuer{{Name: "custom.example", Key: "QUJD"}},
	}
	cfgs := c.IssuerConfigs()
	if len(cfgs) != 2 { // 1 cloudflare preset config (dir + snapshot) + 1 custom
		t.Fatalf("want 2 issuer configs, got %d", len(cfgs))
	}
	var cf, custom int
	for _, ic := range cfgs {
		switch ic.Name {
		case "demo-pat.issuer.cloudflare.com":
			cf++
			if ic.DirectoryURL == "" || len(ic.SnapshotKeys) != 2 {
				t.Errorf("cloudflare config: DirectoryURL=%q snapshotKeys=%d, want set/2", ic.DirectoryURL, len(ic.SnapshotKeys))
			}
		case "custom.example":
			custom++
			if ic.SPKIB64 != "QUJD" || ic.DirectoryURL != "" {
				t.Errorf("custom config = %+v", ic)
			}
		}
	}
	if cf != 1 || custom != 1 {
		t.Errorf("cloudflare=%d custom=%d, want 1/1", cf, custom)
	}

	// No presets enabled + no custom → nothing.
	if got := (PrivacyPassConfig{}).IssuerConfigs(); len(got) != 0 {
		t.Errorf("empty config should yield no issuer configs, got %d", len(got))
	}
	// An unknown preset ID is ignored.
	if got := (PrivacyPassConfig{EnabledIssuerPresets: []string{"nope"}}).IssuerConfigs(); len(got) != 0 {
		t.Errorf("unknown preset ID should be ignored, got %d", len(got))
	}
}
