package handlers

import (
	"bytes"
	"html/template"
	"strings"

	"github.com/unmask-sh/unmask/admin/internal/settings"
)

// The deny-mode rate-limit page is the JS-free "hard cap" 403 a "deny" zone
// serves at /unmask/_rl... (see serveRateDeny).  Unlike the challenge page --
// which localizes client-side via challenge.js's navigator.language -- this
// page runs no JS, so it localizes SERVER-side from Accept-Language against the
// built-in table below.  An operator override (Branding.RateDenyTitle/Body)
// wins over the table and is shown verbatim to every visitor.

type denyMsg struct {
	Title string
	Body  string
	Dir   string // "rtl" for Arabic, else "ltr"
}

// denyI18N mirrors challenge.js's language set (ar de en es fr hi id it ja ko
// pl pt ru th tr vi zh zh-Hant) so the deny page localizes the same way the
// challenge does.  English is the fallback.
var denyI18N = map[string]denyMsg{
	"en":      {"Too many requests", "You've made too many requests in a short time. Please wait a moment, then try again.", "ltr"},
	"ja":      {"リクエストが多すぎます", "短時間に多くのリクエストが送信されました。少し待ってから、もう一度お試しください。", "ltr"},
	"de":      {"Zu viele Anfragen", "Sie haben in kurzer Zeit zu viele Anfragen gesendet. Bitte warten Sie einen Moment und versuchen Sie es erneut.", "ltr"},
	"es":      {"Demasiadas solicitudes", "Has realizado demasiadas solicitudes en poco tiempo. Espera un momento e inténtalo de nuevo.", "ltr"}, //nolint:misspell // "momento" is Spanish for "moment"
	"fr":      {"Trop de requêtes", "Vous avez effectué trop de requêtes en peu de temps. Veuillez patienter un instant, puis réessayer.", "ltr"},
	"it":      {"Troppe richieste", "Hai effettuato troppe richieste in poco tempo. Attendi un momento e riprova.", "ltr"},          //nolint:misspell // "momento" is Italian for "moment"
	"pt":      {"Muitas solicitações", "Você fez muitas solicitações em pouco tempo. Aguarde um momento e tente novamente.", "ltr"}, //nolint:misspell // "momento" is Portuguese for "moment"
	"ru":      {"Слишком много запросов", "Вы отправили слишком много запросов за короткое время. Подождите немного и повторите попытку.", "ltr"},
	"ko":      {"요청이 너무 많습니다", "짧은 시간에 너무 많은 요청을 보냈습니다. 잠시 기다린 후 다시 시도해 주세요.", "ltr"},
	"zh":      {"请求过多", "您在短时间内发送了过多请求。请稍候片刻，然后重试。", "ltr"},
	"zh-Hant": {"請求過多", "您在短時間內發送了過多請求。請稍候片刻，然後重試。", "ltr"},
	"ar":      {"طلبات كثيرة جدًا", "لقد أرسلت طلبات كثيرة جدًا في وقت قصير. يرجى الانتظار قليلًا ثم المحاولة مرة أخرى.", "rtl"},
	"hi":      {"बहुत अधिक अनुरोध", "आपने कम समय में बहुत अधिक अनुरोध भेजे हैं। कृपया थोड़ी देर प्रतीक्षा करें, फिर पुनः प्रयास करें।", "ltr"},
	"id":      {"Terlalu banyak permintaan", "Anda mengirim terlalu banyak permintaan dalam waktu singkat. Harap tunggu sebentar, lalu coba lagi.", "ltr"},
	"pl":      {"Zbyt wiele żądań", "Wysłano zbyt wiele żądań w krótkim czasie. Poczekaj chwilę i spróbuj ponownie.", "ltr"},
	"th":      {"คำขอมากเกินไป", "คุณส่งคำขอมากเกินไปในเวลาอันสั้น โปรดรอสักครู่แล้วลองอีกครั้ง", "ltr"},
	"tr":      {"Çok fazla istek", "Kısa sürede çok fazla istek gönderdiniz. Lütfen biraz bekleyip tekrar deneyin.", "ltr"},
	"vi":      {"Quá nhiều yêu cầu", "Bạn đã gửi quá nhiều yêu cầu trong thời gian ngắn. Vui lòng đợi một lát rồi thử lại.", "ltr"},
}

// denyLangFromAccept picks the best built-in language from an Accept-Language
// header, defaulting to English.  Tags are tried in header order (q-values are
// not weighted -- the first supported tag wins, which is good enough for a
// static error page).  Traditional-Chinese locales map to zh-Hant; every other
// region falls back to its primary subtag.
func denyLangFromAccept(accept string) string {
	for _, part := range strings.Split(accept, ",") {
		tag := strings.TrimSpace(part)
		if i := strings.IndexByte(tag, ';'); i >= 0 { // drop ;q=...
			tag = tag[:i]
		}
		tag = strings.ToLower(strings.TrimSpace(tag))
		if tag == "" {
			continue
		}
		if tag == "zh-hant" || strings.HasPrefix(tag, "zh-tw") ||
			strings.HasPrefix(tag, "zh-hk") || strings.HasPrefix(tag, "zh-mo") {
			return "zh-Hant"
		}
		primary := tag
		if i := strings.IndexByte(primary, '-'); i >= 0 {
			primary = primary[:i]
		}
		if _, ok := denyI18N[primary]; ok {
			return primary
		}
	}
	return "en"
}

type rateDenyData struct {
	Lang, Dir, Title, Body, SiteName, Footer, LogoURL string
	// Marker is injected as known-safe HTML because html/template elides HTML
	// comments from the template TEXT; passing it as a value emits it verbatim
	// so the "unmask:rate-deny" detection marker survives.
	Marker template.HTML
}

// rateDenyMarker is the e2e / capture detection comment kept out of the
// template text (html/template would strip it) and injected as a value.
const rateDenyMarkerStr = "<!-- unmask:rate-deny -->"

// rateDenyTmpl is the JS-free branded deny page.  No PoW / CAPTCHA / escape
// hatch -- a "deny" zone is a hard cap the operator chose, not a puzzle.  The
// "unmask:rate-deny" marker lets the e2e suite (and an operator grepping a
// capture) tell a deny from a challenge without parsing the page.
var rateDenyTmpl = template.Must(template.New("ratedeny").Parse(`<!doctype html>
<html lang="{{.Lang}}" dir="{{.Dir}}">
{{.Marker}}
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="robots" content="noindex, nofollow">
<title>{{.Title}}</title>
<style>
  :root { color-scheme: light dark; }
  body { font-family: system-ui, -apple-system, "Segoe UI", Roboto, sans-serif;
         margin: 0; min-height: 100vh; display: grid; place-items: center;
         background: #f6f7f9; color: #1d2433; }
  main { max-width: 28rem; padding: 2rem; text-align: center; }
  .logo { max-height: 3rem; max-width: 12rem; margin: 0 0 1.25rem; }
  .site { font-weight: 600; font-size: 1.05rem; margin: 0 0 1rem; }
  h1 { font-size: 1.5rem; margin: 0 0 0.75rem; }
  p { margin: 0; line-height: 1.6; color: #5a6473; }
  footer { margin: 1.75rem 0 0; font-size: 0.8rem; color: #8a93a2; }
  @media (prefers-color-scheme: dark) {
    body { background: #15181d; color: #e6e9ee; }
    p { color: #9aa4b2; }
    footer { color: #79828f; }
  }
</style>
</head>
<body>
<main>
{{if .LogoURL}}<img class="logo" src="{{.LogoURL}}" alt="{{.SiteName}}">{{end}}
{{if .SiteName}}<div class="site">{{.SiteName}}</div>{{end}}
<h1>{{.Title}}</h1>
<p>{{.Body}}</p>
{{if .Footer}}<footer>{{.Footer}}</footer>{{end}}
</main>
</body>
</html>
`))

// renderRateDeny builds the branded, localized deny page.  An operator override
// (br.RateDenyTitle / RateDenyBody) takes precedence over the localized
// built-in; basePath is the /unmask mount used to reach the logo route.
func renderRateDeny(br settings.BrandingValues, acceptLanguage, basePath string) []byte {
	lang := denyLangFromAccept(acceptLanguage)
	m := denyI18N[lang]
	title, body := m.Title, m.Body
	if t := strings.TrimSpace(br.RateDenyTitle); t != "" {
		title = t
	}
	if b := strings.TrimSpace(br.RateDenyBody); b != "" {
		body = b
	}
	logoURL := ""
	if br.LogoPath != "" {
		logoURL = basePath + "/branding/logo"
	}
	var buf bytes.Buffer
	if err := rateDenyTmpl.Execute(&buf, rateDenyData{
		Lang:     lang,
		Dir:      m.Dir,
		Title:    title,
		Body:     body,
		SiteName: br.SiteName,
		Footer:   br.FooterText,
		LogoURL:  logoURL,
		Marker:   template.HTML(rateDenyMarkerStr), //nolint:gosec // constant literal, no user input
	}); err != nil {
		return []byte(rateDenyFallback) // never expected; keep a 403 body regardless
	}
	return buf.Bytes()
}

// rateDenyFallback is a last-resort body if template execution ever fails.
const rateDenyFallback = `<!doctype html><html lang="en"><!-- unmask:rate-deny -->` +
	`<head><meta charset="utf-8"><title>Too many requests</title></head>` +
	`<body><h1>Too many requests</h1><p>Please wait a moment, then try again.</p></body></html>`
