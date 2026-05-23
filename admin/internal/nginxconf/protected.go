// Protected paths feature (= transparent CAPTCHA / PoW / strict gate).
//
// Difference from honeypot:
//   - honeypot: "step on the trap → persistent BAN on that IP → affects all subsequent paths"
//   - protected paths: "a visitor reaching here is human-verified.  affects only that path"
//
// Meaning of each mode:
//   - "captcha" : skip PoW → straight to CAPTCHA → issue _bv.  standard.  medium UX cost
//   - "pow"     : PoW only → issue _bv.  lightweight protection that only charges CPU cost
//   - "strict"  : PoW → CAPTCHA chain → _bv.  In v0.1 behaves like captcha
//     (= the chain JS state machine ships in v0.2).  The yml schema carries all 3 from the start.
package nginxconf

const (
	ProtectedModeCaptcha = "captcha"
	ProtectedModePoW     = "pow"
	ProtectedModeStrict  = "strict"
)

// IsValidProtectedMode: validate a value coming from form / yml.
func IsValidProtectedMode(m string) bool {
	return m == ProtectedModeCaptcha || m == ProtectedModePoW || m == ProtectedModeStrict
}

// ProtectedPathRule: render-time struct that maps to one row in the UI.
type ProtectedPathRule struct {
	Pattern string // nginx regex (= without ~^)
	Mode    string // "captcha" | "pow" | "strict"
}

// ProtectedPathPresetGroup: a preset group of protected paths.  Rules inside
// the group hold {Pattern, Mode} per entry (= captcha for login pages, pow
// for APIs, etc.).
type ProtectedPathPresetGroup struct {
	ID      string
	Label   string
	Rules   []ProtectedPathRule
	AddedIn string
}

// ProtectedPathPresetGroups: typical "you probably want to protect this" path sets.
//
// All OFF by default (= they may not match your path layout, and we want to
// avoid the accident of locking the operator out of admin itself).  The user
// removes them from disabled_presets to opt in.
//
// Mode is fixed by the preset.  Admin login forms expect a human, so
// "captcha" is appropriate (= blocks bots, while a real operator gets through
// after a single CAPTCHA).
var ProtectedPathPresetGroups = []ProtectedPathPresetGroup{
	{
		ID:    "unmask",
		Label: "unmask itself (= cover the /unmask/admin/ login page with CAPTCHA)",
		Rules: []ProtectedPathRule{
			{Pattern: `^/unmask/admin/`, Mode: ProtectedModeCaptcha},
		},
	},
	{
		ID:    "common-admin",
		Label: "Common admin / CMS paths (= /wp-admin/ /wp-login.php /phpmyadmin/ /admin/ /administrator/ /manager/html)",
		Rules: []ProtectedPathRule{
			{Pattern: `^/wp-admin/`, Mode: ProtectedModeCaptcha},
			{Pattern: `^/wp-login\.php`, Mode: ProtectedModeCaptcha},
			{Pattern: `^/phpmyadmin/`, Mode: ProtectedModeCaptcha},
			{Pattern: `^/admin/`, Mode: ProtectedModeCaptcha},
			{Pattern: `^/administrator/`, Mode: ProtectedModeCaptcha},
			{Pattern: `^/manager/html`, Mode: ProtectedModeCaptcha},
		},
	},
}
