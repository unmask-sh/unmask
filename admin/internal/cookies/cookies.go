// Package cookies: _bv cookie の発行 / 検証.
//
// format:
//
//	"<day>.<sig>.<kind>"        ※ kind は "captcha" 等の自由文字列 (ASCII)
//	sig = HMAC-SHA1("<day>:<remote_ip>:<ja4>:<kind>", BV_SECRET) の先頭 16 hex
//
// day は floor(time.Unix() / 86400). nginx 側で同じロジックを再現することで、
// cookie だけで challenge skip 可能になる.  有効期間は config.cookie_days (default 3 日).
package cookies

import (
	"crypto/hmac"
	"crypto/sha1"
	"encoding/hex"
	"strconv"
	"strings"
	"time"
)

// dayNow returns floor(unix / 86400).
func dayNow() int64 { return time.Now().Unix() / 86400 }

// IssueValue computes the cookie value for `Set-Cookie: _bv=<value>`.
func IssueValue(bvSecret, remoteIP, ja4, kind string) string {
	return issueValueAt(bvSecret, remoteIP, ja4, kind, dayNow())
}

func issueValueAt(bvSecret, remoteIP, ja4, kind string, day int64) string {
	if kind == "" {
		kind = "captcha"
	}
	msg := strconv.FormatInt(day, 10) + ":" + remoteIP + ":" + ja4 + ":" + kind
	mac := hmac.New(sha1.New, []byte(bvSecret))
	mac.Write([]byte(msg))
	sig := hex.EncodeToString(mac.Sum(nil))[:16]
	return strconv.FormatInt(day, 10) + "." + sig + "." + kind
}

// Verify returns true iff `value` is a valid signature signed within
// validDays days for (remoteIP, ja4).
func Verify(value, bvSecret, remoteIP, ja4 string, validDays int) bool {
	if value == "" {
		return false
	}
	parts := strings.SplitN(value, ".", 3)
	if len(parts) < 3 {
		return false
	}
	day, err := strconv.ParseInt(parts[0], 10, 64)
	if err != nil {
		return false
	}
	kind := parts[2]
	today := dayNow()
	if day > today || today-day > int64(validDays) {
		return false
	}
	expected := issueValueAt(bvSecret, remoteIP, ja4, kind, day)
	return hmac.Equal([]byte(expected), []byte(value))
}
