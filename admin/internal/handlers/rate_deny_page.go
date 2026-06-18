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
// built-in tables below.  There is no free-text operator override (a verbatim
// string would be shown to every visitor in one language, defeating the
// localization); instead the wording follows the operator's branding copy
// preset (friendly / neutral / minimal), exactly like the challenge page, and
// every preset is translated into all supported languages so the visitor still
// reads it in their own.

type denyMsg struct {
	Title string
	Body  string
}

// denyDir returns the text direction for a built-in language: "rtl" for Arabic
// (the only RTL language in the set), "ltr" otherwise.
func denyDir(lang string) string {
	if lang == "ar" {
		return "rtl"
	}
	return "ltr"
}

// denyMsgs holds the deny-page copy per branding copy preset, each localized to
// the same 18 languages the challenge supports (ar de en es fr hi id it ja ko
// pl pt ru th tr vi zh zh-Hant).  BrandingValues.CopyPreset picks the tone; the
// visitor's Accept-Language picks the language.  "friendly" is the fallback
// preset and English the fallback language.  The "neutral" set is the original
// matter-of-fact wording; "friendly" is warmer/apologetic and "minimal" terse,
// mirroring the challenge presets' tone.
var denyMsgs = map[string]map[string]denyMsg{
	settings.BrandingPresetFriendly: {
		"en":      {"Just a moment", "We're getting a lot of requests right now. Please wait a moment and try again. Thanks for your patience."},
		"ja":      {"少々お待ちください", "現在アクセスが集中しています。少し時間をおいてから、もう一度お試しください。ご協力ありがとうございます。"},
		"de":      {"Einen Moment bitte", "Im Moment erreichen uns sehr viele Anfragen. Bitte warten Sie kurz und versuchen Sie es dann erneut. Danke für Ihre Geduld."},
		"es":      {"Un momento", "Estamos recibiendo muchas solicitudes ahora mismo. Espera un momento y vuelve a intentarlo. Gracias por tu paciencia."}, //nolint:misspell // "momento" is Spanish for "moment"
		"fr":      {"Un instant", "Nous recevons beaucoup de requêtes en ce moment. Veuillez patienter un instant, puis réessayer. Merci de votre patience."},
		"it":      {"Un momento", "Stiamo ricevendo molte richieste in questo momento. Attendi un attimo e riprova. Grazie per la pazienza."},          //nolint:misspell // "momento" is Italian for "moment"
		"pt":      {"Um momento", "Estamos recebendo muitas solicitações no momento. Aguarde um instante e tente novamente. Obrigado pela paciência."}, //nolint:misspell // "momento" is Portuguese for "moment"
		"ru":      {"Один момент", "Сейчас поступает много запросов. Пожалуйста, подождите немного и повторите попытку. Спасибо за терпение."},
		"ko":      {"잠시만 기다려 주세요", "현재 요청이 많이 들어오고 있습니다. 잠시 후 다시 시도해 주세요. 기다려 주셔서 감사합니다."},
		"zh":      {"请稍候", "当前请求量较大，请稍等片刻后再试。感谢您的耐心。"},
		"zh-Hant": {"請稍候", "目前請求量較大，請稍待片刻後再試。感謝您的耐心。"},
		"ar":      {"لحظة من فضلك", "نتلقى عددًا كبيرًا من الطلبات حاليًا. يرجى الانتظار قليلًا ثم المحاولة مرة أخرى. شكرًا لصبرك."},
		"hi":      {"कृपया एक क्षण रुकें", "अभी हमें बहुत सारे अनुरोध मिल रहे हैं। कृपया थोड़ी देर रुककर फिर से प्रयास करें। आपके धैर्य के लिए धन्यवाद।"},
		"id":      {"Mohon tunggu sebentar", "Saat ini kami menerima banyak permintaan. Silakan tunggu sebentar, lalu coba lagi. Terima kasih atas kesabaran Anda."},
		"pl":      {"Chwileczkę", "Otrzymujemy teraz wiele żądań. Poczekaj chwilę i spróbuj ponownie. Dziękujemy za cierpliwość."},
		"th":      {"กรุณารอสักครู่", "ขณะนี้มีคำขอเข้ามาจำนวนมาก กรุณารอสักครู่แล้วลองใหม่อีกครั้ง ขอบคุณสำหรับความอดทน"},
		"tr":      {"Bir dakika lütfen", "Şu anda çok sayıda istek alıyoruz. Lütfen biraz bekleyip tekrar deneyin. Sabrınız için teşekkürler."},
		"vi":      {"Vui lòng chờ một lát", "Hiện chúng tôi đang nhận được rất nhiều yêu cầu. Vui lòng đợi một lát rồi thử lại. Cảm ơn sự kiên nhẫn của bạn."},
	},
	settings.BrandingPresetNeutral: {
		"en":      {"Too many requests", "You've made too many requests in a short time. Please wait a moment, then try again."},
		"ja":      {"リクエストが多すぎます", "短時間に多くのリクエストが送信されました。少し待ってから、もう一度お試しください。"},
		"de":      {"Zu viele Anfragen", "Sie haben in kurzer Zeit zu viele Anfragen gesendet. Bitte warten Sie einen Moment und versuchen Sie es erneut."},
		"es":      {"Demasiadas solicitudes", "Has realizado demasiadas solicitudes en poco tiempo. Espera un momento e inténtalo de nuevo."}, //nolint:misspell // "momento" is Spanish for "moment"
		"fr":      {"Trop de requêtes", "Vous avez effectué trop de requêtes en peu de temps. Veuillez patienter un instant, puis réessayer."},
		"it":      {"Troppe richieste", "Hai effettuato troppe richieste in poco tempo. Attendi un momento e riprova."},          //nolint:misspell // "momento" is Italian for "moment"
		"pt":      {"Muitas solicitações", "Você fez muitas solicitações em pouco tempo. Aguarde um momento e tente novamente."}, //nolint:misspell // "momento" is Portuguese for "moment"
		"ru":      {"Слишком много запросов", "Вы отправили слишком много запросов за короткое время. Подождите немного и повторите попытку."},
		"ko":      {"요청이 너무 많습니다", "짧은 시간에 너무 많은 요청을 보냈습니다. 잠시 기다린 후 다시 시도해 주세요."},
		"zh":      {"请求过多", "您在短时间内发送了过多请求。请稍候片刻，然后重试。"},
		"zh-Hant": {"請求過多", "您在短時間內發送了過多請求。請稍候片刻，然後重試。"},
		"ar":      {"طلبات كثيرة جدًا", "لقد أرسلت طلبات كثيرة جدًا في وقت قصير. يرجى الانتظار قليلًا ثم المحاولة مرة أخرى."},
		"hi":      {"बहुत अधिक अनुरोध", "आपने कम समय में बहुत अधिक अनुरोध भेजे हैं। कृपया थोड़ी देर प्रतीक्षा करें, फिर पुनः प्रयास करें।"},
		"id":      {"Terlalu banyak permintaan", "Anda mengirim terlalu banyak permintaan dalam waktu singkat. Harap tunggu sebentar, lalu coba lagi."},
		"pl":      {"Zbyt wiele żądań", "Wysłano zbyt wiele żądań w krótkim czasie. Poczekaj chwilę i spróbuj ponownie."},
		"th":      {"คำขอมากเกินไป", "คุณส่งคำขอมากเกินไปในเวลาอันสั้น โปรดรอสักครู่แล้วลองอีกครั้ง"},
		"tr":      {"Çok fazla istek", "Kısa sürede çok fazla istek gönderdiniz. Lütfen biraz bekleyip tekrar deneyin."},
		"vi":      {"Quá nhiều yêu cầu", "Bạn đã gửi quá nhiều yêu cầu trong thời gian ngắn. Vui lòng đợi một lát rồi thử lại."},
	},
	settings.BrandingPresetMinimal: {
		"en":      {"Too many requests", "Please try again shortly."},
		"ja":      {"リクエストが多すぎます", "しばらくしてから再度お試しください。"},
		"de":      {"Zu viele Anfragen", "Bitte versuchen Sie es in Kürze erneut."},
		"es":      {"Demasiadas solicitudes", "Inténtalo de nuevo en breve."},
		"fr":      {"Trop de requêtes", "Veuillez réessayer dans un instant."},
		"it":      {"Troppe richieste", "Riprova tra poco."},
		"pt":      {"Muitas solicitações", "Tente novamente em breve."},
		"ru":      {"Слишком много запросов", "Повторите попытку позже."},
		"ko":      {"요청이 너무 많습니다", "잠시 후 다시 시도해 주세요."},
		"zh":      {"请求过多", "请稍后重试。"},
		"zh-Hant": {"請求過多", "請稍後重試。"},
		"ar":      {"طلبات كثيرة جدًا", "يرجى المحاولة مرة أخرى بعد قليل."},
		"hi":      {"बहुत अधिक अनुरोध", "कृपया कुछ देर बाद पुनः प्रयास करें।"},
		"id":      {"Terlalu banyak permintaan", "Silakan coba lagi sebentar lagi."},
		"pl":      {"Zbyt wiele żądań", "Spróbuj ponownie za chwilę."},
		"th":      {"คำขอมากเกินไป", "โปรดลองใหม่อีกครั้งในภายหลัง"},
		"tr":      {"Çok fazla istek", "Lütfen birazdan tekrar deneyin."},
		"vi":      {"Quá nhiều yêu cầu", "Vui lòng thử lại sau giây lát."},
	},
}

// denyLangFromAccept picks the best built-in language from an Accept-Language
// header, defaulting to English.  Tags are tried in header order (q-values are
// not weighted -- the first supported tag wins, which is good enough for a
// static error page).  Traditional-Chinese locales map to zh-Hant; every other
// region falls back to its primary subtag.  The language set is identical
// across presets, so the neutral table is the canonical membership check.
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
		if _, ok := denyMsgs[settings.BrandingPresetNeutral][primary]; ok {
			return primary
		}
	}
	return "en"
}

// refLabels localizes the short label that precedes the support correlation id
// in the page footer ("<label> <id>").  Keyed by the same built-in language set
// as denyI18N; the value is the established loanword abbreviation "Ref." for
// Latin-script locales (matching how Cloudflare / Akamai leave their Ray ID /
// Reference # untranslated) and a localized term where that reads oddly.
// Anything unmapped falls back to "Ref.".
var refLabels = map[string]string{
	"en": "Ref.", "ja": "参照番号", "ko": "참조 번호",
	"zh": "参考编号", "zh-Hant": "參考編號",
	"de": "Ref.", "es": "Ref.", "fr": "Réf.", "it": "Rif.", "pt": "Ref.",
	"pl": "Nr ref.", "id": "Ref.", "tr": "Ref.", "vi": "Mã tham chiếu",
	"ru": "Код", "ar": "مرجع", "hi": "संदर्भ", "th": "รหัสอ้างอิง",
}

// refLabel returns the localized "Ref." label for lang, falling back to "Ref.".
func refLabel(lang string) string {
	if v, ok := refLabels[lang]; ok {
		return v
	}
	return "Ref."
}

// denyMsgForPreset returns the (preset, lang) message, clamping an unknown
// preset to friendly and an unknown lang to English.
func denyMsgForPreset(preset, lang string) denyMsg {
	table, ok := denyMsgs[preset]
	if !ok {
		table = denyMsgs[settings.BrandingPresetFriendly]
	}
	if m, ok := table[lang]; ok {
		return m
	}
	return table["en"]
}

// banDenyMsgs is the deny page copy for a ban whose action is "deny".  Unlike a
// rate-limit deny (transient -- clears once the client slows down, so its copy
// invites a retry), a ban is persistent until the operator lifts it, so the
// wording is "blocked" with no retry framing.  One tone only (a hard block does
// not need the friendly/neutral/minimal spread), localized to the same 18
// languages.  English is the fallback.
var banDenyMsgs = map[string]denyMsg{
	"en":      {"Access blocked", "Your access to this site has been blocked."},
	"ja":      {"アクセスがブロックされています", "このサイトへのアクセスはブロックされています。"},
	"de":      {"Zugriff blockiert", "Ihr Zugriff auf diese Website wurde blockiert."},
	"es":      {"Acceso bloqueado", "Tu acceso a este sitio ha sido bloqueado."},
	"fr":      {"Accès bloqué", "Votre accès à ce site a été bloqué."},
	"it":      {"Accesso bloccato", "Il tuo accesso a questo sito è stato bloccato."},
	"pt":      {"Acesso bloqueado", "Seu acesso a este site foi bloqueado."},
	"ru":      {"Доступ заблокирован", "Ваш доступ к этому сайту заблокирован."},
	"ko":      {"접근이 차단되었습니다", "이 사이트에 대한 접근이 차단되었습니다."},
	"zh":      {"访问已被阻止", "您对本网站的访问已被阻止。"},
	"zh-Hant": {"存取已遭封鎖", "您對本網站的存取已遭封鎖。"},
	"ar":      {"تم حظر الوصول", "تم حظر وصولك إلى هذا الموقع."},
	"hi":      {"पहुँच अवरुद्ध", "इस साइट तक आपकी पहुँच अवरुद्ध कर दी गई है।"},
	"id":      {"Akses diblokir", "Akses Anda ke situs ini telah diblokir."},
	"pl":      {"Dostęp zablokowany", "Twój dostęp do tej witryny został zablokowany."},
	"th":      {"การเข้าถึงถูกบล็อก", "การเข้าถึงเว็บไซต์นี้ของคุณถูกบล็อก"},
	"tr":      {"Erişim engellendi", "Bu siteye erişiminiz engellendi."},
	"vi":      {"Quyền truy cập bị chặn", "Quyền truy cập của bạn vào trang web này đã bị chặn."},
}

// banDenyMsg returns the ban "blocked" message for lang, English as fallback.
func banDenyMsg(lang string) denyMsg {
	if m, ok := banDenyMsgs[lang]; ok {
		return m
	}
	return banDenyMsgs["en"]
}

type rateDenyData struct {
	Lang, Dir, Title, Body, SiteName, Footer, LogoURL string
	// Ref is the short support correlation id printed at the foot of the page so
	// a blocked visitor can quote it; the operator resolves it via
	// `unmask events --ref`.  Auto-escaped by html/template (it is bare hex
	// anyway).  Empty -> the line is omitted.  RefLabel is its localized prefix.
	Ref, RefLabel string
	// Theme is "auto" | "light" | "dark"; it drives the <html data-theme>
	// attribute that the static CSS keys off.  Keeping it an attribute value
	// (not interpolated CSS) sidesteps html/template's CSS-context sanitizer.
	Theme string
	// Marker is injected as known-safe HTML because html/template elides HTML
	// comments from the template TEXT; passing it as a value emits it verbatim
	// so the "unmask:rate-deny" detection marker survives.
	Marker template.HTML
}

// rateDenyMarker / banDenyMarker are the e2e / capture detection comments kept
// out of the template text (html/template would strip them) and injected as a
// value.  Distinct markers let a capture tell a rate-limit deny ("too many
// requests", transient) from a ban deny ("blocked", persistent).
const (
	rateDenyMarkerStr = "<!-- unmask:rate-deny -->"
	banDenyMarkerStr  = "<!-- unmask:ban-deny -->"
)

// rateDenyTmpl is the JS-free branded deny page.  No PoW / CAPTCHA / escape
// hatch -- a "deny" zone is a hard cap the operator chose, not a puzzle.  The
// "unmask:rate-deny" marker lets the e2e suite (and an operator grepping a
// capture) tell a deny from a challenge without parsing the page.
var rateDenyTmpl = template.Must(template.New("ratedeny").Parse(`<!doctype html>
<html lang="{{.Lang}}" dir="{{.Dir}}" data-theme="{{.Theme}}">
{{.Marker}}
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="robots" content="noindex, nofollow">
<title>{{.Title}}</title>
<style>
  /* Light is the base palette; data-theme (set from the operator's choice)
     forces a scheme, and "auto" additionally follows prefers-color-scheme. */
  body { font-family: system-ui, -apple-system, "Segoe UI", Roboto, sans-serif;
         margin: 0; min-height: 100vh; display: grid; place-items: center;
         background: #f6f7f9; color: #1d2433; }
  main { max-width: 28rem; padding: 2rem; text-align: center; }
  .logo { max-height: 3rem; max-width: 12rem; margin: 0 0 1.25rem; }
  .site { font-weight: 600; font-size: 1.05rem; margin: 0 0 1rem; }
  h1 { font-size: 1.5rem; margin: 0 0 0.75rem; }
  p { margin: 0; line-height: 1.6; color: #5a6473; }
  footer { margin: 1.75rem 0 0; font-size: 0.8rem; color: #8a93a2; }
  .ref { margin: 1.1rem 0 0; font-size: 0.72rem; color: #aab2bf;
         font-family: ui-monospace, SFMono-Regular, Menlo, monospace; }
  html[data-theme="light"] { color-scheme: light; }
  html[data-theme="dark"] { color-scheme: dark; }
  html[data-theme="dark"] body { background: #15181d; color: #e6e9ee; }
  html[data-theme="dark"] p { color: #9aa4b2; }
  html[data-theme="dark"] footer { color: #79828f; }
  html[data-theme="dark"] .ref { color: #5f6772; }
  html[data-theme="auto"] { color-scheme: light dark; }
  @media (prefers-color-scheme: dark) {
    html[data-theme="auto"] body { background: #15181d; color: #e6e9ee; }
    html[data-theme="auto"] p { color: #9aa4b2; }
    html[data-theme="auto"] footer { color: #79828f; }
    html[data-theme="auto"] .ref { color: #5f6772; }
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
{{if .Ref}}<div class="ref">{{.RefLabel}} {{.Ref}}</div>{{end}}
</main>
</body>
</html>
`))

// renderRateDeny builds the branded, localized deny page.  The visual shell
// (logo / site name / footer) comes from per-site Branding; preset is the
// already-resolved copy preset (friendly / neutral / minimal -- the deny page's
// own DenyCopyPreset, which may inherit the branding one) whose wording is
// localized to the visitor's Accept-Language (no free-text override -- a
// verbatim string would override the localization for every visitor).  theme is
// the light/dark choice ("auto" | "light" | "dark"; anything else clamps to
// auto).  basePath is the /unmask mount used to reach the logo route.
func renderRateDeny(br settings.BrandingValues, preset, theme, acceptLanguage, basePath, ref string) []byte {
	lang := denyLangFromAccept(acceptLanguage)
	return renderDenyPage(br, denyMsgForPreset(preset, lang), rateDenyMarkerStr, theme, lang, basePath, ref)
}

// renderBanDeny builds the deny page for a ban whose action is "deny".  Same
// branded, themed shell as the rate-limit deny, but the "blocked" wording and a
// distinct marker -- a ban is persistent (no "retry" framing fits).
func renderBanDeny(br settings.BrandingValues, theme, acceptLanguage, basePath, ref string) []byte {
	lang := denyLangFromAccept(acceptLanguage)
	return renderDenyPage(br, banDenyMsg(lang), banDenyMarkerStr, theme, lang, basePath, ref)
}

// renderDenyPage renders the shared JS-free deny template with a resolved
// message + marker.  theme is the light/dark choice (clamped to auto on an
// unknown value); basePath is the /unmask mount used to reach the logo route.
func renderDenyPage(br settings.BrandingValues, m denyMsg, marker, theme, lang, basePath, ref string) []byte {
	switch theme {
	case settings.DenyThemeLight, settings.DenyThemeDark, settings.DenyThemeAuto:
	default:
		theme = settings.DenyThemeAuto
	}
	logoURL := ""
	if br.LogoPath != "" {
		logoURL = basePath + "/branding/logo"
	}
	var buf bytes.Buffer
	if err := rateDenyTmpl.Execute(&buf, rateDenyData{
		Lang:     lang,
		Dir:      denyDir(lang),
		Title:    m.Title,
		Body:     m.Body,
		SiteName: br.SiteName,
		Footer:   br.FooterText,
		LogoURL:  logoURL,
		Ref:      ref,
		RefLabel: refLabel(lang),
		Theme:    theme,
		Marker:   template.HTML(marker), //nolint:gosec // constant literal, no user input
	}); err != nil {
		return []byte(rateDenyFallback) // never expected; keep a 403 body regardless
	}
	return buf.Bytes()
}

// rateDenyFallback is a last-resort body if template execution ever fails.
const rateDenyFallback = `<!doctype html><html lang="en"><!-- unmask:rate-deny -->` +
	`<head><meta charset="utf-8"><title>Too many requests</title></head>` +
	`<body><h1>Too many requests</h1><p>Please wait a moment, then try again.</p></body></html>`
