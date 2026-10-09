package assets

import (
	"bytes"
	"image/png"
	"testing"
)

// TestIconStaysSmall: the built-in icon is drawn at 14-28 px (the challenge
// page's credit line, the admin header, the favicon) and as the 180 px
// apple-touch-icon.  It shipped as the 1254 px source artwork (1.3 MB), so a
// page showing it at 14 px still downloaded 1.3 MB.  A square of at least
// 180 px under 64 KiB covers every use.
func TestIconStaysSmall(t *testing.T) {
	b, err := Static.ReadFile("static/icon.png")
	if err != nil {
		t.Fatalf("read icon: %v", err)
	}
	if len(b) > 64<<10 {
		t.Errorf("static/icon.png is %d bytes, want at most 64 KiB: resize it instead of embedding the source artwork", len(b))
	}
	cfg, err := png.DecodeConfig(bytes.NewReader(b))
	if err != nil {
		t.Fatalf("decode icon: %v", err)
	}
	if cfg.Width != cfg.Height || cfg.Width < 180 {
		t.Errorf("static/icon.png is %dx%d, want a square of at least 180 px", cfg.Width, cfg.Height)
	}
}
