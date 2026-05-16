// 3rd-party CAPTCHA provider integrations.
//
// The builtin path (= unmask's behavioral check) is self-contained via
// Score()/VerifyMath(), but external providers take a token and POST it
// along with secret_key to the provider's siteverify endpoint before deciding.
//
// Supported providers:
//
//	turnstile : https://challenges.cloudflare.com/turnstile/v0/siteverify
//	hcaptcha  : https://api.hcaptcha.com/siteverify
//	recaptcha : https://www.google.com/recaptcha/api/siteverify  (v3 expected = score 0..1)
//
// All share the same protocol: send `secret`, `response`, `remoteip` as
// multipart/x-www-form-urlencoded.  Differences are only the response field
// names and the fact that only recaptcha returns a score.
package captcha

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// VerifyResult: provider verification result.
type VerifyResult struct {
	OK    bool
	Score float64 // Only meaningful for recaptcha v3 (= 0..1).  Others: 1 when OK==true.
	Err   string  // Error returned by the provider (= for logging).
}

// VerifyExternal: given provider name, token, ip, hit siteverify.
// Returns ok=false immediately if secret == "" or token == "".
//
// The returned err covers system-level failures (network / 5xx / parse).
// A "bad token" (= bot verdict) is expressed as err==nil + result.OK==false.
func VerifyExternal(ctx context.Context, provider, secret, token, ip string) (*VerifyResult, error) {
	switch provider {
	case "turnstile":
		return verifyHTTP(ctx, "https://challenges.cloudflare.com/turnstile/v0/siteverify", secret, token, ip, false, 0)
	case "hcaptcha":
		return verifyHTTP(ctx, "https://api.hcaptcha.com/siteverify", secret, token, ip, false, 0)
	case "recaptcha":
		// The v3 score threshold is supplied by the caller (= skip the threshold check if <= 0).
		return verifyHTTP(ctx, "https://www.google.com/recaptcha/api/siteverify", secret, token, ip, true, 0)
	default:
		return &VerifyResult{OK: false, Err: "unknown_provider"}, nil
	}
}

func verifyHTTP(ctx context.Context, endpoint, secret, token, ip string, useScore bool, _ float64) (*VerifyResult, error) {
	if secret == "" || token == "" {
		return &VerifyResult{OK: false, Err: "missing_secret_or_token"}, nil
	}
	form := url.Values{}
	form.Set("secret", secret)
	form.Set("response", token)
	if ip != "" {
		form.Set("remoteip", ip)
	}
	cctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(cctx, http.MethodPost, endpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 500 {
		return nil, fmt.Errorf("siteverify status %d", resp.StatusCode)
	}
	var body struct {
		Success    bool     `json:"success"`
		Score      float64  `json:"score"`        // recaptcha v3
		ErrorCodes []string `json:"error-codes"`  // turnstile / recaptcha
	}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		return nil, err
	}
	r := &VerifyResult{OK: body.Success}
	if useScore {
		r.Score = body.Score
	} else if body.Success {
		r.Score = 1.0
	}
	if len(body.ErrorCodes) > 0 {
		r.Err = strings.Join(body.ErrorCodes, ",")
	}
	return r, nil
}

var httpClient = &http.Client{Timeout: 6 * time.Second}
