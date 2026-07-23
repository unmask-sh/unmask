package handlers

import (
	"bytes"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/unmask-sh/unmask/admin/internal/settings"
)

func brandingUploadReq(t *testing.T, filename string, content []byte) *http.Request {
	t.Helper()
	var buf bytes.Buffer
	mw := multipart.NewWriter(&buf)
	if err := mw.WriteField("branding_site_name", "Test"); err != nil {
		t.Fatal(err)
	}
	fw, err := mw.CreateFormFile("branding_logo_file", filename)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := fw.Write(content); err != nil {
		t.Fatal(err)
	}
	if err := mw.Close(); err != nil {
		t.Fatal(err)
	}
	r := httptest.NewRequest(http.MethodPost, "/save", &buf)
	r.Header.Set("Content-Type", mw.FormDataContentType())
	return r
}

func withTempLogoDir(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	old := brandingLogoDir
	brandingLogoDir = dir
	t.Cleanup(func() { brandingLogoDir = old })
	return dir
}

// TestBrandingLogoPerScopeFiles pins the fix for per-site logos: the Default
// record and a site override land on DISTINCT files, so uploading a site
// logo no longer overwrites the Default logo (the old shared "logo.<ext>"
// silently cross-overwrote both, which made per-site logos appear broken).
func TestBrandingLogoPerScopeFiles(t *testing.T) {
	dir := withTempLogoDir(t)

	var def settings.BrandingValues
	if err := applyBrandingForm(&def, "", brandingUploadReq(t, "d.png", []byte("DEFAULT"))); err != nil {
		t.Fatal(err)
	}
	var site settings.BrandingValues
	if err := applyBrandingForm(&site, "example.com", brandingUploadReq(t, "s.png", []byte("SITE"))); err != nil {
		t.Fatal(err)
	}

	if def.LogoPath == site.LogoPath {
		t.Fatalf("default and site logo share a file: %s", def.LogoPath)
	}
	if got, _ := os.ReadFile(def.LogoPath); string(got) != "DEFAULT" {
		t.Errorf("default logo content clobbered: %q", got)
	}
	if got, _ := os.ReadFile(site.LogoPath); string(got) != "SITE" {
		t.Errorf("site logo content = %q, want SITE", got)
	}
	if want := filepath.Join(dir, "logo.png"); def.LogoPath != want {
		t.Errorf("default path = %s, want %s", def.LogoPath, want)
	}
	if want := filepath.Join(dir, "logo.example.com.png"); site.LogoPath != want {
		t.Errorf("site path = %s, want %s", site.LogoPath, want)
	}
}

// TestBrandingLogoLegacyPathMigrates: a config from before the /var/lib move
// stores an absolute path under the old <config-dir>/branding location; the
// next upload writes to the new dir and removes the old file.
func TestBrandingLogoLegacyPathMigrates(t *testing.T) {
	dir := withTempLogoDir(t)

	legacyDir := t.TempDir() // stands in for /etc/unmask/branding
	legacy := filepath.Join(legacyDir, "logo.png")
	if err := os.WriteFile(legacy, []byte("OLD"), 0o644); err != nil {
		t.Fatal(err)
	}
	cur := settings.BrandingValues{LogoPath: legacy}
	if err := applyBrandingForm(&cur, "", brandingUploadReq(t, "new.png", []byte("NEW"))); err != nil {
		t.Fatal(err)
	}
	if want := filepath.Join(dir, "logo.png"); cur.LogoPath != want {
		t.Errorf("LogoPath = %s, want %s", cur.LogoPath, want)
	}
	if _, err := os.Stat(legacy); !os.IsNotExist(err) {
		t.Errorf("legacy file must be removed after migration, stat err=%v", err)
	}
}

// TestBrandingLogoExtChangeCleansOld: re-uploading with a different extension
// removes the record's own prior file (regression for the pre-existing
// behavior, now generalized to "any old path").
func TestBrandingLogoExtChangeCleansOld(t *testing.T) {
	withTempLogoDir(t)

	var cur settings.BrandingValues
	if err := applyBrandingForm(&cur, "", brandingUploadReq(t, "a.png", []byte("PNG"))); err != nil {
		t.Fatal(err)
	}
	first := cur.LogoPath
	if err := applyBrandingForm(&cur, "", brandingUploadReq(t, "b.webp", []byte("WEBP"))); err != nil {
		t.Fatal(err)
	}
	if cur.LogoPath == first {
		t.Fatal("ext change must produce a new path")
	}
	if _, err := os.Stat(first); !os.IsNotExist(err) {
		t.Errorf("old-extension file must be removed, stat err=%v", err)
	}
}

// TestBrandingLogoNameSanitize pins the scope -> file name mapping: lowercase,
// [a-z0-9.-] kept, everything else replaced, so a hostile or odd site id can
// not traverse or collide with the Default file name.
func TestBrandingLogoNameSanitize(t *testing.T) {
	cases := map[string]string{
		"":              "logo.png",
		"Example.COM":   "logo.example.com.png",
		"*.example.com": "logo._.example.com.png",
		`a/b\c:8080`:    "logo.a_b_c_8080.png",
	}
	for scope, want := range cases {
		if got := brandingLogoName(scope, ".png"); got != want {
			t.Errorf("brandingLogoName(%q) = %q, want %q", scope, got, want)
		}
	}
}
