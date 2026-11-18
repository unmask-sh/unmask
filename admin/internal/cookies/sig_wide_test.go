package cookies

import (
	"crypto/hmac"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/hex"
	"strconv"
	"strings"
	"testing"
)

// A signature comes in two widths.  The wide form is HMAC-SHA256's first 32
// hex digits over the message the 16-digit forms sign; it verifies beside
// them, names the same pass as the 16-digit HMAC-SHA256 form (whose
// signature is its head), and is HMAC-SHA256's alone: the same digits from
// HMAC-SHA1, or any width but 16 and 32, verify as nothing.
func TestWideSignature(t *testing.T) {
	const secret, ip, host = "test-secret", "203.0.113.5", "example.com"
	const pow, captcha, diff = 7 * 86400, 14 * 86400, 8
	issued := nowUnix() - 10
	issuedS := strconv.FormatInt(issued, 10)
	msg := issuedS + ":" + ip + ":" + host + ":captcha"
	mac := func(f func(key, msg string) string) string { return f(secret, msg) }
	sha256Hex := mac(func(k, m string) string {
		h := hmac.New(sha256.New, []byte(k))
		h.Write([]byte(m))
		return hex.EncodeToString(h.Sum(nil))
	})
	sha1Hex := mac(func(k, m string) string {
		h := hmac.New(sha1.New, []byte(k))
		h.Write([]byte(m))
		return hex.EncodeToString(h.Sum(nil))
	})

	wide := IssueValueAtH(SigSHA256Wide, secret, ip, host, "captcha", issued)
	if want := issuedS + "." + sha256Hex[:32] + ".captcha"; wide != want {
		t.Fatalf("wide entry %q, want %q", wide, want)
	}
	narrow := IssueValueAtH(SigSHA256, secret, ip, host, "captcha", issued)
	if want := issuedS + "." + sha256Hex[:16] + ".captcha"; narrow != want {
		t.Fatalf("16-digit HMAC-SHA256 entry %q, want %q", narrow, want)
	}
	if want := issuedS + "." + sha1Hex[:16] + ".captcha"; IssueValueAtH(SigSHA1, secret, ip, host, "captcha", issued) != want {
		t.Fatalf("16-digit HMAC-SHA1 entry is not %q", want)
	}

	// It verifies, for this secret, address and host and no other.
	if !Verify(wide, secret, ip, host, pow, captcha, diff) {
		t.Fatalf("the wide entry %q does not verify", wide)
	}
	if Verify(wide, "other-secret", ip, host, pow, captcha, diff) ||
		Verify(wide, secret, "203.0.113.6", host, pow, captcha, diff) ||
		Verify(wide, secret, ip, "other.example", pow, captcha, diff) {
		t.Error("the wide entry verifies for another secret, address or host")
	}
	// Its window is the CAPTCHA window counted from the time it carries,
	// as a 16-digit entry's is.
	if old := IssueValueAtH(SigSHA256Wide, secret, ip, host, "captcha", nowUnix()-captcha-60); Verify(old, secret, ip, host, pow, captcha, diff) {
		t.Error("a wide entry past its window verifies")
	}

	// One pass, one name, PassIDLen digits: the 16-digit HMAC-SHA256
	// signature is the head of the wide one.
	_, kind, id, at, ok := MatchingEntryID(wide, secret, ip, host, pow, captcha, diff)
	if !ok || kind != "captcha" || at != issued || id != sha256Hex[:PassIDLen] {
		t.Errorf("wide entry: ok %v kind %q issued %d id %q, want captcha / %d / %q", ok, kind, at, id, issued, sha256Hex[:PassIDLen])
	}
	if _, _, nid, _, ok := MatchingEntryID(narrow, secret, ip, host, pow, captcha, diff); !ok || nid != id {
		t.Errorf("the 16-digit HMAC-SHA256 entry is named %q, the wide one %q: one pass, two names", nid, id)
	}
	// In a list, behind entries that do not verify.
	list := "x~" + issuedS + "." + strings.Repeat("0", 32) + ".captcha~" + wide
	if e, _, lid, _, ok := MatchingEntryID(list, secret, ip, host, pow, captcha, diff); !ok || e != wide || lid != id {
		t.Errorf("in a list: ok %v entry %q id %q", ok, e, lid)
	}

	// What is not a pass.
	entry := func(sig, kind string) string { return issuedS + "." + sig + "." + kind }
	flip := func(sig string, i int) string {
		c := byte('0')
		if sig[i] == '0' {
			c = '1'
		}
		return sig[:i] + string(c) + sig[i+1:]
	}
	seed256 := PowSeedH(SigSHA256, secret, ip, host, issued)
	seed1 := PowSeedH(SigSHA1, secret, ip, host, issued)
	for what, e := range map[string]string{
		"the first digit changed":           entry(flip(sha256Hex[:32], 0), "captcha"),
		"the 17th digit changed":            entry(flip(sha256Hex[:32], 16), "captcha"),
		"the last digit changed":            entry(flip(sha256Hex[:32], 31), "captcha"),
		"32 digits of HMAC-SHA1":            entry(sha1Hex[:32], "captcha"),
		"24 digits":                         entry(sha256Hex[:24], "captcha"),
		"31 digits":                         entry(sha256Hex[:31], "captcha"),
		"33 digits":                         entry(sha256Hex[:33], "captcha"),
		"40 digits":                         entry(sha256Hex[:40], "captcha"),
		"64 digits":                         entry(sha256Hex, "captcha"),
		"15 digits":                         entry(sha256Hex[:15], "captcha"),
		"no digits":                         entry("", "captcha"),
		"16 digits and 16 zeros":            entry(sha256Hex[:16]+strings.Repeat("0", 16), "captcha"),
		"upper-case digits":                 entry(strings.ToUpper(sha256Hex[:32]), "captcha"),
		"a kind the daemon does not issue":  IssueValueAtH(SigSHA256Wide, secret, ip, host, "other", issued),
		"the HMAC-SHA256 seed's 32 digits":  entry(seed256[:32], "pow_seed"),
		"the HMAC-SHA1 seed's 32 digits":    entry(seed1[:32], "pow_seed"),
		"the HMAC-SHA256 seed's 16 digits":  entry(seed256[:16], "pow_seed"),
		"the seed's digits, kind captcha":   entry(seed256[:32], "captcha"),
		"a wide signature in the pow2 form": issuedS + ".pow2." + sha256Hex[:32] + ".0",
	} {
		if Verify(e, secret, ip, host, pow, captcha, diff) {
			t.Errorf("%s: %q verifies", what, e)
		}
		if _, _, _, _, ok := MatchingEntryID(e, secret, ip, host, pow, captcha, diff); ok {
			t.Errorf("%s: %q matches", what, e)
		}
	}

	// Every kind the daemon issues, in the wide form.
	for kind := range issuedKinds {
		e := IssueValueAtH(SigSHA256Wide, secret, ip, host, kind, issued)
		if _, k, _, _, ok := MatchingEntryID(e, secret, ip, host, pow, captcha, diff); !ok || k != kind {
			t.Errorf("wide entry of kind %q: ok %v kind %q", kind, ok, k)
		}
	}

	// The seed is the MAC's, whatever the signature's width.
	if w, n := PowSeedH(SigSHA256Wide, secret, ip, host, issued), seed256; w != n || len(w) != 40 {
		t.Errorf("the wide form derives the seed %q, the 16-digit HMAC-SHA256 form %q", w, n)
	}

	// _bvj: the same three forms, the wide one HMAC-SHA256's alone.
	jmsg := issuedS + ":ja4hash00000:uahash000000:lin:64512:captcha:" + host + ":bvj"
	jmac := func(f func() string) string { return f() }
	j256 := jmac(func() string {
		h := hmac.New(sha256.New, []byte(secret))
		h.Write([]byte(jmsg))
		return hex.EncodeToString(h.Sum(nil))
	})
	j1 := jmac(func() string {
		h := hmac.New(sha1.New, []byte(secret))
		h.Write([]byte(jmsg))
		return hex.EncodeToString(h.Sum(nil))
	})
	jbody := issuedS + ".ja4hash00000.uahash000000.lin.64512.captcha."
	jw := IssueJValueAtH(SigSHA256Wide, secret, "ja4hash00000", "uahash000000", "lin", 64512, host, "captcha", issued)
	if jw != jbody+j256[:32] {
		t.Fatalf("wide _bvj %q, want %q", jw, jbody+j256[:32])
	}
	for what, c := range map[string]struct {
		value string
		good  bool
	}{
		"wide":                        {jw, true},
		"16 digits, HMAC-SHA256":      {jbody + j256[:16], true},
		"16 digits, HMAC-SHA1":        {jbody + j1[:16], true},
		"32 digits of HMAC-SHA1":      {jbody + j1[:32], false},
		"24 digits":                   {jbody + j256[:24], false},
		"the 17th digit changed":      {jbody + flip(j256[:32], 16), false},
		"16 digits and 16 zeros":      {jbody + j256[:16] + strings.Repeat("0", 16), false},
		"no signature":                {jbody, false},
		"wide, another host's":        {IssueJValueAtH(SigSHA256Wide, secret, "ja4hash00000", "uahash000000", "lin", 64512, "other.example", "captcha", issued), false},
		"wide, the lineage rewritten": {strings.Replace(jw, ".lin.", ".lim.", 1), false},
	} {
		cl, ok := ParseJValue(c.value, secret, host, captcha)
		if ok != c.good {
			t.Errorf("_bvj %s: parses %v, want %v (%q)", what, ok, c.good, c.value)
		}
		if ok && (cl.Lineage != "lin" || cl.ASN != 64512 || cl.Kind != "captcha" || cl.Issued != issued) {
			t.Errorf("_bvj %s: claims %+v", what, cl)
		}
	}

	// The settings words.
	for s, want := range map[string]SigHash{"": SigSHA1, "sha1": SigSHA1, "sha256": SigSHA256, "sha256-128": SigSHA256Wide} {
		got, ok := ParseSigHash(s)
		if !ok || got != want {
			t.Errorf("ParseSigHash(%q) = %v, %v", s, got, ok)
		}
		if s != "" && got.String() != s {
			t.Errorf("%v.String() = %q, want %q", got, got.String(), s)
		}
	}
	for _, s := range []string{"sha256-64", "sha256_128", "SHA256-128", "sha512", "sha1-128", " sha256-128"} {
		if _, ok := ParseSigHash(s); ok {
			t.Errorf("ParseSigHash accepted %q", s)
		}
	}
	// An install that names no form issues the one every module in the
	// field verifies.
	if DefaultSigHash != SigSHA1 || len(strings.Split(IssueValueAt(secret, ip, host, "captcha", issued), ".")[1]) != SigHexLen {
		t.Error("the default form is not HMAC-SHA1 with a 16-digit signature")
	}
	// The widths the verifier takes, and what it tries at each.
	for n := 0; n <= 64; n++ {
		forms := formsOfWidth(n)
		switch n {
		case SigHexLen:
			if len(forms) != 2 || forms[0] != SigSHA256 || forms[1] != SigSHA1 {
				t.Errorf("formsOfWidth(16) = %v", forms)
			}
		case SigHexLenWide:
			if len(forms) != 1 || forms[0] != SigSHA256Wide {
				t.Errorf("formsOfWidth(32) = %v", forms)
			}
		default:
			if forms != nil {
				t.Errorf("formsOfWidth(%d) = %v, want none", n, forms)
			}
		}
	}
}
