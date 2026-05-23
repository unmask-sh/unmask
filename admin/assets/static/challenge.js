(async function(){
  // ============================================================
  // _preview=1: dedicated mode for the settings UI's iframe.  Don't run PoW / CAPTCHA;
  // stop with spinner + "Verifying your browser..." displayed (= just for previewing
  // the theme. No cookies, reloads, or debug beacons fire).
  // ============================================================
  if (window.UNMASK && window.UNMASK._preview) return;

  // ============================================================
  // multi-site support: extract site ID from our own URL pathname.
  //   /unmask/challenge/         → site = "default"
  //   /unmask/challenge/test-1/  → site = "test-1"
  //   /unmask/challenge.html     → site = "default" (legacy)
  // All fetch URLs are built as API_BASE + "/" + relative path.
  // ============================================================
  var SITE = 'default';
  var m = location.pathname.match(/^\/unmask\/challenge\/([a-z0-9][a-z0-9-]*)\/?$/);
  if (m) SITE = m[1];
  var API_BASE = '/unmask/api' + (SITE === 'default' ? '' : '/' + SITE);

  // ============================================================
  // debug log send (for investigating challenge loop stalls)
  //   beacons each phase's state to API_BASE + '/debug'
  //   - rate limit is implemented server-side (same IP, 20 per 5 min)
  //   - browsers without sendBeacon fall back to fetch keepalive
  //   - errors stay silent (don't disturb the normal challenge flow)
  // ============================================================
  function _bcDebug(phase, extra){
    try {
      var pl = {
        phase: phase,
        flags: (typeof flags !== 'undefined') ? flags : null,
        reload_count: (function(){
          try { var m=document.cookie.match(/_br=(\d+)/); return m?parseInt(m[1]):0; } catch(e) { return 0; }
        })(),
        ua: navigator.userAgent,
        screen_w: screen.width, screen_h: screen.height,
        viewport_w: window.innerWidth, viewport_h: window.innerHeight,
        device_pixel_ratio: window.devicePixelRatio,
        languages: navigator.languages || null,
        nav_webdriver: !!navigator.webdriver,
        plugins_len: (navigator.plugins && navigator.plugins.length) || 0,
        has_window_chrome: !!window.chrome,
        connection_type: (navigator.connection && navigator.connection.type) || null,
        save_data: (navigator.connection && navigator.connection.saveData) || false,
        cookie_enabled: navigator.cookieEnabled,
        url: location.href,
        orig_path: (window.UNMASK && window.UNMASK.orig_path) || '',
        bt: (window.UNMASK && window.UNMASK.beacon_token) || '',
        ts: Date.now(),
        elapsed_ms: (typeof start !== 'undefined') ? Date.now() - start : null
      };
      if (extra) for (var k in extra) pl[k] = extra[k];
      var body = JSON.stringify(pl);
      var url = API_BASE + '/debug';
      // sendBeacon: doesn't block page unload / reload
      if (navigator.sendBeacon) {
        var blob = new Blob([body], {type: 'application/json'});
        navigator.sendBeacon(url, blob);
      } else if (typeof fetch === 'function') {
        fetch(url, { method:'POST', body:body, headers:{'Content-Type':'application/json'}, keepalive:true }).catch(function(){});
      }
    } catch(e) {}
  }
  // window.onerror: record exceptions thrown by challenge JS.  Routed through
  // the unified 'error' phase with kind='js_exception'.  Other failure paths
  // (ext_render_err / ext_exec_err / ext_unknown_provider) also funnel into
  // 'error' with a kind discriminator so the server-side allowedPhases set
  // stays small and the funnel SQL doesn't need to enumerate variants.
  window.addEventListener('error', function(e){
    try { _bcDebug('error', { kind:'js_exception', error_msg:String(e && e.message), error_filename:e && e.filename, error_lineno:e && e.lineno }); } catch(_){}
  });

  // --- i18n ---
  var L={
    en:{verify:'Verifying your browser, please wait...',title:'Security Check',desc:'Please confirm to continue.',note:'This check protects the site from automated access.',notRobot:"I'm not a robot",wrong:'Verification failed. Please try again.',error:'Error. Please try again.'},
    ja:{verify:'ブラウザを確認しています。しばらくお待ちください...',title:'セキュリティ確認',desc:'続行するにはチェックを入れてください。',note:'この確認は自動アクセスからサイトを保護するために表示されています。',notRobot:'私はロボットではありません',wrong:'確認に失敗しました。もう一度お試しください。',error:'エラーが発生しました。もう一度お試しください。'},
    zh:{verify:'正在验证您的浏览器，请稍候...',title:'安全验证',desc:'请勾选以继续。',note:'此验证用于保护网站免受自动访问。',notRobot:'我不是机器人',wrong:'验证失败，请重试。',error:'发生错误，请重试。'},
    zht:{verify:'正在驗證您的瀏覽器，請稍候...',title:'安全驗證',desc:'請勾選以繼續。',note:'此驗證用於保護網站免受自動存取。',notRobot:'我不是機器人',wrong:'驗證失敗，請重試。',error:'發生錯誤，請重試。'},
    ko:{verify:'브라우저를 확인하고 있습니다. 잠시 기다려 주세요...',title:'보안 확인',desc:'계속하려면 체크해 주세요.',note:'이 확인은 자동 접근으로부터 사이트를 보호하기 위해 표시됩니다.',notRobot:'저는 로봇이 아닙니다',wrong:'확인에 실패했습니다. 다시 시도해 주세요.',error:'오류가 발생했습니다. 다시 시도해 주세요.'},
    es:{verify:'Verificando su navegador, por favor espere...',title:'Verificación de seguridad',desc:'Resuelva esto para continuar.',note:'Esta verificación protege el sitio del acceso automatizado.',wrong:'Incorrecto. Inténtelo de nuevo.',enterNum:'Introduzca un número.',error:'Error. Inténtelo de nuevo.'},
    pt:{verify:'Verificando seu navegador, aguarde...',title:'Verificação de segurança',desc:'Resolva isto para continuar.',note:'Esta verificação protege o site contra acesso automatizado.',wrong:'Incorreto. Tente novamente.',enterNum:'Digite um número.',error:'Erro. Tente novamente.'},
    fr:{verify:'Vérification de votre navigateur, veuillez patienter...',title:'Vérification de sécurité',desc:'Résolvez ceci pour continuer.',note:'Cette vérification protège le site contre les accès automatisés.',wrong:'Incorrect. Réessayez.',enterNum:'Veuillez entrer un nombre.',error:'Erreur. Veuillez réessayer.'},
    de:{verify:'Ihr Browser wird überprüft, bitte warten...',title:'Sicherheitsprüfung',desc:'Lösen Sie dies, um fortzufahren.',note:'Diese Prüfung schützt die Website vor automatisiertem Zugriff.',wrong:'Falsch. Versuchen Sie es erneut.',enterNum:'Bitte geben Sie eine Zahl ein.',error:'Fehler. Bitte versuchen Sie es erneut.'},
    ru:{verify:'Проверка вашего браузера, подождите...',title:'Проверка безопасности',desc:'Решите задачу, чтобы продолжить.',note:'Эта проверка защищает сайт от автоматического доступа.',wrong:'Неверно. Попробуйте снова.',enterNum:'Введите число.',error:'Ошибка. Попробуйте снова.'},
    it:{verify:'Verifica del browser in corso, attendere...',title:'Controllo di sicurezza',desc:'Risolvi questo per continuare.',note:'Questo controllo protegge il sito dall\'accesso automatizzato.',wrong:'Errato. Riprova.',enterNum:'Inserisci un numero.',error:'Errore. Riprova.'},
    tr:{verify:'Tarayıcınız doğrulanıyor, lütfen bekleyin...',title:'Güvenlik kontrolü',desc:'Devam etmek için bunu çözün.',note:'Bu kontrol siteyi otomatik erişimden korur.',wrong:'Yanlış. Tekrar deneyin.',enterNum:'Lütfen bir sayı girin.',error:'Hata. Lütfen tekrar deneyin.'},
    pl:{verify:'Weryfikacja przeglądarki, proszę czekać...',title:'Kontrola bezpieczeństwa',desc:'Rozwiąż to, aby kontynuować.',note:'Ta kontrola chroni stronę przed automatycznym dostępem.',wrong:'Niepoprawnie. Spróbuj ponownie.',enterNum:'Proszę wpisać liczbę.',error:'Błąd. Spróbuj ponownie.'},
    vi:{verify:'Đang xác minh trình duyệt, vui lòng đợi...',title:'Kiểm tra bảo mật',desc:'Hãy giải bài toán này để tiếp tục.',note:'Kiểm tra này bảo vệ trang web khỏi truy cập tự động.',wrong:'Sai. Vui lòng thử lại.',enterNum:'Vui lòng nhập một số.',error:'Lỗi. Vui lòng thử lại.'},
    th:{verify:'กำลังตรวจสอบเบราว์เซอร์ กรุณารอสักครู่...',title:'การตรวจสอบความปลอดภัย',desc:'กรุณาแก้โจทย์นี้เพื่อดำเนินการต่อ',note:'การตรวจสอบนี้ปกป้องเว็บไซต์จากการเข้าถึงอัตโนมัติ',wrong:'ไม่ถูกต้อง ลองอีกครั้ง',enterNum:'กรุณาใส่ตัวเลข',error:'เกิดข้อผิดพลาด กรุณาลองอีกครั้ง'},
    id:{verify:'Memverifikasi browser Anda, harap tunggu...',title:'Pemeriksaan keamanan',desc:'Selesaikan ini untuk melanjutkan.',note:'Pemeriksaan ini melindungi situs dari akses otomatis.',wrong:'Salah. Coba lagi.',enterNum:'Masukkan angka.',error:'Error. Coba lagi.'},
    ar:{verify:'جارٍ التحقق من متصفحك، يرجى الانتظار...',title:'فحص أمني',desc:'حل هذه المسألة للمتابعة.',note:'هذا الفحص يحمي الموقع من الوصول الآلي.',wrong:'إجابة خاطئة. حاول مرة أخرى.',enterNum:'الرجاء إدخال رقم.',error:'خطأ. يرجى المحاولة مرة أخرى.'},
    hi:{verify:'आपके ब्राउज़र की जाँच हो रही है, कृपया प्रतीक्षा करें...',title:'सुरक्षा जाँच',desc:'जारी रखने के लिए इसे हल करें।',note:'यह जाँच साइट को स्वचालित पहुँच से बचाती है।',wrong:'गलत। पुनः प्रयास करें।',enterNum:'कृपया एक संख्या दर्ज करें।',error:'त्रुटि। कृपया पुनः प्रयास करें।'}
  };

  // language detection: URL path -> Accept-Language -> default English
  function detectLang(){
    // from URL path: /ja/..., /en/..., etc.
    var m=location.pathname.match(/^\/(en|ja|zh|zht|ko|es|pt|fr|de|ru|it|tr|pl|vi|th|id|ar|hi)\//);
    if(m&&L[m[1]])return m[1];
    // navigator.language
    var nl=(navigator.language||navigator.userLanguage||'en').toLowerCase();
    // zh-TW,zh-Hant → zht, zh-CN,zh-Hans → zh
    if(/^zh.*(tw|hant|hk|mo)/i.test(nl))return 'zht';
    if(/^zh/i.test(nl))return 'zh';
    var code=nl.split('-')[0];
    if(L[code])return code;
    return 'en';
  }

  var lang=detectLang();
  var t=L[lang]||L.en;

  // --- branding: copy preset + site name + logo/footer ----------------
  //
  // Operators pick a preset in the admin panel; the visitor sees the same
  // preset text translated into their own language.  Only ja / en have
  // translations for now — other languages fall back to the L baseline so
  // the language stays consistent (verify message in en preset on a fr
  // visitor would feel jarring).
  //
  // {site_name} in any preset / L string is replaced with the configured
  // site name, or a localized default ("サイト" / "this site") when not
  // configured.
  var P={
    friendly:{
      en:{verify:'Verifying you can reach {site_name} safely, just a moment...',title:'Safety check',desc:'Please confirm to continue.',note:'This check helps protect the site from automated abuse.'},
      ja:{verify:'{site_name} で安全確認中です. 数秒お待ちください...',title:'安全確認',desc:'続行するにはチェックを入れてください.',note:'自動アクセスから site を保護するための確認です.'}
    },
    neutral:{
      en:{verify:'Performing a security check for {site_name}, please wait...',title:'Security check',desc:'Please confirm to continue.',note:'This security check protects the site from automated access.'},
      ja:{verify:'{site_name} のセキュリティ確認中です. しばらくお待ちください...',title:'セキュリティ確認',desc:'続行するにはチェックを入れてください.',note:'自動アクセス対策のための確認です.'}
    },
    minimal:{
      en:{verify:'Connecting to {site_name}... just a moment',title:'Connecting',desc:'Please confirm to continue.',note:''},
      ja:{verify:'{site_name} に接続中... 数秒お待ちください',title:'接続中',desc:'続行するにはチェックを入れてください.',note:''}
    }
  };
  var brand=(window.UNMASK&&window.UNMASK.brand)||null;
  if(brand&&brand.copy_preset&&P[brand.copy_preset]&&P[brand.copy_preset][lang]){
    var pv=P[brand.copy_preset][lang];
    // Shallow-merge: preset fields override the L baseline; notRobot /
    // wrong / error stay from L (= operator does not customize them).
    var merged={};
    for(var lk in t){ if(t.hasOwnProperty(lk)) merged[lk]=t[lk]; }
    for(var pk in pv){ if(pv.hasOwnProperty(pk)) merged[pk]=pv[pk]; }
    t=merged;
  }
  // {site_name} substitution.  Run on every string in t so a preset can put
  // the placeholder in any field; non-string entries (= none today) skipped.
  var subjectFallback=(lang==='ja')?'サイト':'this site';
  var subject=(brand&&brand.site_name)?brand.site_name:subjectFallback;
  for(var sk in t){
    if(typeof t[sk]==='string') t[sk]=t[sk].replace(/\{site_name\}/g, subject);
  }
  // Apply brand DOM (logo / site name / footer).  Each element is hidden by
  // default (inline style="display:none" in challenge.html); flip to visible
  // only when the corresponding field is set so the layout doesn't move on
  // pages that don't use branding.
  if(brand){
    var bhead=document.getElementById('brand-head');
    var blogo=document.getElementById('brand-logo');
    var bsite=document.getElementById('brand-site');
    var bfoot=document.getElementById('brand-foot');
    var headShow=false;
    if(brand.logo_url&&blogo){
      blogo.src=brand.logo_url;
      blogo.alt=brand.site_name||'';
      blogo.style.display='';
      headShow=true;
    }
    if(brand.site_name&&bsite){
      bsite.textContent=brand.site_name;
      bsite.style.display='';
      headShow=true;
    }
    if(headShow&&bhead) bhead.style.display='';
    if(brand.footer_text&&bfoot){
      bfoot.textContent=brand.footer_text;
      bfoot.style.display='';
    }
  }

  // set the html lang and dir attributes
  document.documentElement.lang=lang==='zht'?'zh-Hant':lang;
  if(lang==='ar')document.documentElement.dir='rtl';

  // set initial text
  document.getElementById('msg').textContent=t.verify;

  var start=Date.now();
  var captchaToken='';

  // --- behavioral signal collection ---
  // On checkbox click, send this sig to the server which makes the bot decision.
  var sig = {
    mouseTrail: [],   // [[clientX, clientY, t_ms], ...] capped at 200 points
    scrolls:    [],   // [[scrollY, t_ms], ...] capped at 50 points
    keys:       0,
    hasMouseEvents: false,
    hasTouchEvents: false,
    windowSize: [window.innerWidth || 0, window.innerHeight || 0],
    screenSize: [(screen && screen.width) || 0, (screen && screen.height) || 0],
    loadAt:     0,    // time showCaptcha was called (= performance.now())
  };

  document.addEventListener('mousemove', function(e){
    sig.hasMouseEvents = true;
    if (sig.mouseTrail.length < 200) {
      sig.mouseTrail.push([Math.round(e.clientX), Math.round(e.clientY), Math.round(performance.now())]);
    }
  });
  document.addEventListener('touchstart', function(){ sig.hasTouchEvents = true; });
  document.addEventListener('keypress',  function(){ sig.keys++; });
  document.addEventListener('scroll', function(){
    if (sig.scrolls.length < 50) sig.scrolls.push([window.scrollY || 0, Math.round(performance.now())]);
  });

  // --- function definitions (placed before any early return) ---
  function showCaptcha(){
    document.getElementById('spinner').style.display='none';
    document.getElementById('msg').style.display='none';
    var cap=document.getElementById('captcha');
    cap.style.display='block';
    document.getElementById('captchaTitle').textContent=t.title;
    document.getElementById('captchaDesc').textContent=t.desc;
    var noteEl=document.getElementById('captchaNote');
    // Empty note (= the "minimal" preset removes the note string) hides the
    // element entirely instead of leaving a blank line where it used to be.
    if(t.note){ noteEl.textContent=t.note; noteEl.style.display=''; }
    else      { noteEl.style.display='none'; }
    document.getElementById('notRobotLabel').textContent = t.notRobot || "I'm not a robot";
    sig.loadAt = performance.now();
    captchaToken = String(Math.random()).slice(2) + '.' + Math.round(performance.now());

    // if a 3rd-party CAPTCHA provider is configured, hide the built-in checkbox and show the widget.
    var ext = window.UNMASK && window.UNMASK.captcha;
    if (ext && ext.provider && ext.site_key) {
      document.getElementById('clickRow').style.display='none';
      mountExternalCaptcha(ext.provider, ext.site_key);
      _bcDebug('captcha', { provider: ext.provider });
      return;
    }

    var cb = document.getElementById('notRobot');
    cb.addEventListener('change', function(){
      if (!cb.checked) return;
      cb.disabled = true;
      submitClick();
    });
    _bcDebug('captcha');
  }

  // --- 3rd party CAPTCHA widget mount ---
  // Turnstile / hCaptcha hand the token to a callback.  reCAPTCHA v3 is invisible
  // and needs execute() at render time to fetch the token.
  function mountExternalCaptcha(provider, siteKey){
    var mount = document.getElementById('extCaptcha');
    mount.style.display='block';
    function done(token){
      submitProviderToken(token);
    }
    if (provider === 'turnstile') {
      window._unmaskTurnstileCb = function(){
        try { window.turnstile.render(mount, { sitekey: siteKey, callback: done }); }
        catch(e){ showError(t.error); _bcDebug('error', { kind:'ext_render_err', provider: provider, error: String(e) }); }
      };
      injectScript('https://challenges.cloudflare.com/turnstile/v0/api.js?onload=_unmaskTurnstileCb&render=explicit');
    } else if (provider === 'hcaptcha') {
      window._unmaskHcaptchaCb = function(){
        try { window.hcaptcha.render(mount, { sitekey: siteKey, callback: done }); }
        catch(e){ showError(t.error); _bcDebug('error', { kind:'ext_render_err', provider: provider, error: String(e) }); }
      };
      injectScript('https://js.hcaptcha.com/1/api.js?onload=_unmaskHcaptchaCb&render=explicit');
    } else if (provider === 'recaptcha') {
      // v3 invisible: automatically execute -> token -> submit.  UI is just spinner + description.
      mount.innerHTML = '<div class="spinner" style="margin:0 auto"></div>';
      window._unmaskRecaptchaCb = function(){
        try {
          window.grecaptcha.ready(function(){
            window.grecaptcha.execute(siteKey, { action: 'unmask' }).then(done).catch(function(e){
              showError(t.error); _bcDebug('error', { kind:'ext_exec_err', provider: provider, error: String(e) });
            });
          });
        } catch(e){ showError(t.error); _bcDebug('error', { kind:'ext_render_err', provider: provider, error: String(e) }); }
      };
      injectScript('https://www.google.com/recaptcha/api.js?render=' + encodeURIComponent(siteKey) + '&onload=_unmaskRecaptchaCb');
    } else {
      showError(t.error);
      _bcDebug('error', { kind:'ext_unknown_provider', provider: provider });
    }
  }

  function injectScript(src){
    var s = document.createElement('script');
    s.src = src; s.async = true; s.defer = true;
    document.head.appendChild(s);
  }

  function submitProviderToken(providerToken){
    fetch(API_BASE + '/verify', {
      method:'POST',
      headers:{'Content-Type':'application/json'},
      body:JSON.stringify({ token: captchaToken, provider_token: providerToken })
    }).then(function(r){return r.json().then(function(d){return{status:r.status,data:d};});})
    .then(function(res){
      if(res.data.ok===1){
        _bcDebug(bvPhaseForCaptchaPass(), { method:'provider', score: res.data.score });
        passAndRedirect();
      } else {
        _bcDebug('verify_ng', { method:'provider', http_status: res.status, score: res.data.score, detail: res.data.detail });
        showError(t.wrong);
      }
    }).catch(function(){ showError(t.error); });
  }

  function submitClick(){
    document.getElementById('errMsg').style.display='none';
    var clickAt = Math.round(performance.now());
    fetch(API_BASE + '/verify', {
      method:'POST',
      headers:{'Content-Type':'application/json'},
      body:JSON.stringify({
        token: captchaToken,
        sig: {
          mouseTrail: sig.mouseTrail,
          scrolls:    sig.scrolls,
          keys:       sig.keys,
          hasMouseEvents: sig.hasMouseEvents,
          hasTouchEvents: sig.hasTouchEvents,
          windowSize: sig.windowSize,
          screenSize: sig.screenSize,
          clickAt:    clickAt - (sig.loadAt || 0),  // ms elapsed since the captcha was shown
        }
      })
    }).then(function(r){return r.json().then(function(d){return{status:r.status,data:d};});})
    .then(function(res){
      if(res.data.ok===1){
        _bcDebug(bvPhaseForCaptchaPass(), { score: res.data.score });
        passAndRedirect();
      } else {
        _bcDebug('verify_ng', { http_status: res.status, score: res.data.score });
        // checkbox couldn't confirm -> switch to the numeric-add fallback (= UX rescue).
        // bots score low here, but LLMs can solve numeric add, so bot bypass risk exists.
        // Still, the 2-stage gate "behavioral failed + numeric add solved" keeps simple scrapers out.
        showMathFallback();
      }
    }).catch(function(){
      showError(t.error);
      var cb = document.getElementById('notRobot');
      cb.checked = false;
      cb.disabled = false;
    });
  }

  function passAndRedirect(){
    var u=new URL(location.href);
    u.searchParams.delete('_test_bot');
    u.searchParams.delete('_test_ja4');
    // the following paths have no "original page" (= test or direct access), so redirect to "/".
    //   - /unmask/challenge.html / /unmask/challenge/<site>/    direct challenge access
    //   - /unmask/(admin/)?test/force-(pow|captcha)             test pages.
    //                                                            reloading the same path causes a loop.
    if (u.pathname === '/unmask/challenge.html' ||
        /^\/unmask\/challenge(\/[a-z0-9][a-z0-9-]*)?\/?$/.test(u.pathname) ||
        /^\/unmask\/(admin\/)?test\/force-(pow|captcha)\/?$/.test(u.pathname)) {
      location.replace('/');
    } else {
      location.replace(u.pathname+u.search);
    }
  }

  // numeric-add fallback. Rescues users whose checkbox behavioral check failed.
  function showMathFallback(){
    document.getElementById('clickRow').style.display='none';
    document.getElementById('errMsg').style.display='none';
    document.getElementById('mathFallback').style.display='block';
    document.getElementById('captchaDesc').textContent = (t.solveMath || 'Please solve this to continue.');
    fetch(API_BASE + '/captcha/new').then(function(r){return r.json();}).then(function(data){
      captchaToken = data.token;
      document.getElementById('mathQ').textContent = data.a + ' + ' + data.b + ' = ?';
      document.getElementById('answerInput').value='';
      document.getElementById('answerInput').focus();
      document.getElementById('submitBtn').disabled=false;
    });
    document.getElementById('submitBtn').onclick = submitMath;
    document.getElementById('answerInput').addEventListener('keydown', function(e){
      if(e.key==='Enter') submitMath();
    });
  }

  function submitMath(){
    var ans = document.getElementById('answerInput').value.trim();
    if(!ans || !/^\d+$/.test(ans)) {
      showError(t.enterNum || 'Please enter a number.');
      return;
    }
    document.getElementById('submitBtn').disabled = true;
    fetch(API_BASE + '/verify',{
      method:'POST',
      headers:{'Content-Type':'application/json'},
      body:JSON.stringify({answer:parseInt(ans), token:captchaToken})
    }).then(function(r){return r.json().then(function(d){return{status:r.status,data:d};});})
    .then(function(res){
      if(res.data.ok===1){
        _bcDebug(bvPhaseForCaptchaPass(), { method:'math' });
        passAndRedirect();
      } else {
        _bcDebug('verify_ng', { method:'math', http_status: res.status });
        showError(t.wrong);
        // retry with a different question
        fetch(API_BASE + '/captcha/new').then(function(r){return r.json();}).then(function(data){
          captchaToken = data.token;
          document.getElementById('mathQ').textContent = data.a + ' + ' + data.b + ' = ?';
          document.getElementById('answerInput').value='';
          document.getElementById('submitBtn').disabled=false;
        });
      }
    }).catch(function(){
      showError(t.error);
      document.getElementById('submitBtn').disabled=false;
    });
  }

  function showError(msg){
    var el=document.getElementById('errMsg');
    el.textContent=msg;
    el.style.display='block';
  }

  // Error screen for environments where cookies are disabled or unwritable.
  // Both the PoW path and the flags>=3 path will reload forever without cookies,
  // so display an explicit error before falling into the loop.
  var COOKIE_ERR_I18N = {
    en: { title:'Cookies are required', desc:'This site uses a security cookie to verify your browser. Please enable cookies in your browser settings and reload this page.' },
    ja: { title:'Cookie を有効にしてください', desc:'このサイトはブラウザを確認するためにセキュリティ Cookie を使用します。ブラウザの設定で Cookie を有効にして、このページを再読み込みしてください。' },
    zh: { title:'需要启用 Cookie', desc:'本网站使用安全 Cookie 来验证您的浏览器。请在浏览器设置中启用 Cookie 并重新加载此页面。' },
    zht:{ title:'需要啟用 Cookie', desc:'本網站使用安全 Cookie 來驗證您的瀏覽器。請在瀏覽器設定中啟用 Cookie 並重新載入此頁面。' },
    ko: { title:'쿠키를 활성화해 주세요', desc:'이 사이트는 브라우저를 확인하기 위해 보안 쿠키를 사용합니다. 브라우저 설정에서 쿠키를 활성화하고 이 페이지를 다시 로드해 주세요.' },
    es: { title:'Se requieren cookies', desc:'Este sitio utiliza una cookie de seguridad para verificar su navegador. Habilite las cookies en la configuración de su navegador y vuelva a cargar esta página.' },
    pt: { title:'Cookies são necessários', desc:'Este site usa um cookie de segurança para verificar seu navegador. Ative os cookies nas configurações do seu navegador e recarregue esta página.' },
    fr: { title:'Les cookies sont requis', desc:'Ce site utilise un cookie de sécurité pour vérifier votre navigateur. Activez les cookies dans les paramètres de votre navigateur et rechargez cette page.' },
    de: { title:'Cookies sind erforderlich', desc:'Diese Website verwendet ein Sicherheits-Cookie zur Überprüfung Ihres Browsers. Aktivieren Sie Cookies in Ihren Browsereinstellungen und laden Sie diese Seite neu.' }
  };
  function showCookieError(){
    var c=COOKIE_ERR_I18N[lang]||COOKIE_ERR_I18N.en;
    document.getElementById('spinner').style.display='none';
    document.getElementById('msg').style.display='none';
    document.getElementById('captcha').style.display='none';
    document.getElementById('cookieErrTitle').textContent=c.title;
    document.getElementById('cookieErrDesc').textContent=c.desc;
    document.getElementById('cookieErr').style.display='block';
    _bcDebug('cookie_err');
  }

  // --- headless browser detection ---
  var flags=0;
  if(/[?&]_test_bot=1/.test(location.search))flags=31;
  if(navigator.webdriver)flags|=1;
  if(navigator.plugins&&navigator.plugins.length===0)flags|=2;
  if(!navigator.languages||navigator.languages.length===0)flags|=4;
  if(screen.width===0||screen.height===0)flags|=8;
  // bit 16 (!window.chrome) was disabled on 2026-05-01 because Android WebView apps
  // (Yahoo, NAVER, Daum, etc.) triggered many false positives.  Uncomment if revived.
  // if(/Chrome/.test(navigator.userAgent)&&!window.chrome)flags|=16;

  // The server rewrites the /*__CAPTCHA_FORCE__*/"none" placeholder at serve time.
  // Any value other than "none" (= ja4_bot / honeypot / banned / protected / rate_limit / test)
  // means skip PoW and force CAPTCHA.  The reason is kept for dashboard stats.
  // (the old ?c=1 URL query couldn't be detected via location.search because internal rewrite
  //  doesn't reflect it in the URL bar, so we moved to a placeholder approach; URL stays clean)
  var forceReason = (window.UNMASK && window.UNMASK.force_reason) || 'none';
  // chMode is the single source of truth for the challenge chain.  The admin
  // picks it per axis (UA filter / JA4 / honeypot / protected / rate-limit /
  // no-match) so what the operator configured is what actually runs — bot
  // signal presence no longer silently downgrades the chain.
  //   "captcha_only"       : straight to CAPTCHA (PoW skipped)
  //   "pow_only"           : PoW only (lightweight; issues _bv on success)
  //   "pow_then_captcha"   : PoW then CAPTCHA chain (no _bv until CAPTCHA passes)
  //   "deny"               : we never reach here (the subrequest returned 403)
  var chMode = (window.UNMASK && window.UNMASK.challenge_mode) || 'pow_then_captcha';

  // bvPhaseForCaptchaPass: phase name to report when /verify returns ok=1.
  // Format: 'bv_' + chMode value (= bv_pow_then_captcha / bv_captcha_only / ...).
  // chMode-aligned naming means adding a new challenge_mode in the future
  // (e.g. pow_then_behavioral) automatically yields a distinct phase without
  // touching this code — the server-side allowedPhases list is the only place
  // that needs to learn about the new value.
  function bvPhaseForCaptchaPass(){
    return 'bv_' + chMode;
  }

  _bcDebug('load', { force_reason: forceReason, chmode: chMode });

  if (chMode === 'captcha_only') {
    showCaptcha();
    return;
  }
  // chainPoWThenCaptcha: when true, the PoW success path branches into
  // showCaptcha() instead of issuing _bv.
  var chainPoWThenCaptcha = (chMode === 'pow_then_captcha');

  // flags >= 3 -> bot decision -> show CAPTCHA
  if(flags>=3){
    var rc=0;
    try{var m2=document.cookie.match(/_br=(\d+)/);if(m2)rc=parseInt(m2[1]);}catch(e){}
    if(rc>=2){
      showCaptcha();
      return;
    }
    // _br retry counter: independent of _bv server-validity windows.  365 days
    // is "practically permanent"; the server only ever reads this to count
    // recent JS-side challenge attempts, never to authenticate.
    var exp=new Date(Date.now()+86400000*365);
    document.cookie='_br='+(rc+1)+';path=/;expires='+exp.toUTCString()+';SameSite=Lax';
    // _br set check: if we can't write, the page reloads forever, so show an error and give up
    var _br_set_ok = /(?:^|;\s*)_br=/.test(document.cookie);
    if (!_br_set_ok) {
      showCookieError();
      return;
    }
    setTimeout(function(){passAndRedirect();},2000);
    return;
  }

  // --- Proof-of-Work (= SHA-256 hashcash style.  unix-second granularity since 2026-05) ---
  //   issued = window.UNMASK.issued_at  (= server unix seconds; falls back to
  //            client clock only when the server forgot to inject the field)
  //   seed   = "<issued>_unmask"        (= bit-identical to cookies.go server side)
  //   target = leading-zero-bits >= window.UNMASK.pow_difficulty (default 18)
  //   nonce  = incremented until SHA-256(seed + ":" + nonce) meets the target
  // Using server-supplied issued_at keeps the visitor's wall clock out of the
  // loop, so a wildly wrong client time can't poison the seed or the cookie's
  // first segment.
  var issuedAt = (window.UNMASK && window.UNMASK.issued_at) || Math.floor(Date.now()/1000);
  // Difficulty comes from settings.Challenge.PowDifficulty (= default 18 bits)
  // via window.UNMASK.pow_difficulty.
  var powDiff=(window.UNMASK && window.UNMASK.pow_difficulty) || 18;
  var seed=String(issuedAt)+'_unmask';

  // ---- pure JS SHA-256 (= RFC 6234). 32-byte output. ~150 lines. ----
  var SHA256_K = new Uint32Array([
    0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
    0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
    0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
    0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
    0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
    0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
    0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
    0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2
  ]);
  var SHA256_W = new Uint32Array(64);
  function sha256(str){
    // UTF-8 encode + pad to 64-byte chunks
    var enc=new TextEncoder().encode(str);
    var msgLen=enc.length, bitLen=msgLen*8;
    var paddedLen=Math.ceil((msgLen+9)/64)*64;
    var p=new Uint8Array(paddedLen);
    p.set(enc); p[msgLen]=0x80;
    // 64-bit length (high 32 bits = 0 for typical inputs, low 32 = bitLen)
    p[paddedLen-4]=(bitLen>>>24)&0xff; p[paddedLen-3]=(bitLen>>>16)&0xff;
    p[paddedLen-2]=(bitLen>>>8)&0xff;  p[paddedLen-1]=bitLen&0xff;
    var h0=0x6a09e667,h1=0xbb67ae85,h2=0x3c6ef372,h3=0xa54ff53a;
    var h4=0x510e527f,h5=0x9b05688c,h6=0x1f83d9ab,h7=0x5be0cd19;
    var W=SHA256_W;
    for(var c=0;c<paddedLen;c+=64){
      for(var i=0;i<16;i++){ W[i]=(p[c+i*4]<<24)|(p[c+i*4+1]<<16)|(p[c+i*4+2]<<8)|p[c+i*4+3]; }
      for(var i=16;i<64;i++){
        var w15=W[i-15], w2=W[i-2];
        var s0=((w15>>>7)|(w15<<25))^((w15>>>18)|(w15<<14))^(w15>>>3);
        var s1=((w2>>>17)|(w2<<15))^((w2>>>19)|(w2<<13))^(w2>>>10);
        W[i]=(W[i-16]+s0+W[i-7]+s1)>>>0;
      }
      var a=h0,b=h1,cc=h2,dd=h3,e=h4,f=h5,g=h6,hh=h7;
      for(var i=0;i<64;i++){
        var S1=((e>>>6)|(e<<26))^((e>>>11)|(e<<21))^((e>>>25)|(e<<7));
        var ch=(e&f)^(~e&g);
        var t1=(hh+S1+ch+SHA256_K[i]+W[i])>>>0;
        var S0=((a>>>2)|(a<<30))^((a>>>13)|(a<<19))^((a>>>22)|(a<<10));
        var mj=(a&b)^(a&cc)^(b&cc);
        var t2=(S0+mj)>>>0;
        hh=g; g=f; f=e; e=(dd+t1)>>>0; dd=cc; cc=b; b=a; a=(t1+t2)>>>0;
      }
      h0=(h0+a)>>>0; h1=(h1+b)>>>0; h2=(h2+cc)>>>0; h3=(h3+dd)>>>0;
      h4=(h4+e)>>>0; h5=(h5+f)>>>0;  h6=(h6+g)>>>0; h7=(h7+hh)>>>0;
    }
    // Return as 32-byte Uint8Array
    var out=new Uint8Array(32);
    var hs=[h0,h1,h2,h3,h4,h5,h6,h7];
    for(var i=0;i<8;i++){
      out[i*4]=(hs[i]>>>24)&0xff; out[i*4+1]=(hs[i]>>>16)&0xff;
      out[i*4+2]=(hs[i]>>>8)&0xff; out[i*4+3]=hs[i]&0xff;
    }
    return out;
  }
  function leadingZeroBits(bytes){
    var bits=0;
    for(var i=0;i<bytes.length;i++){
      if(bytes[i]===0){ bits+=8; continue; }
      var b=bytes[i];
      while((b&0x80)===0){ bits++; b<<=1; }
      return bits;
    }
    return bits;
  }
  // ---- PoW solve loop ----
  var nonce=0, target=0;
  var BATCH=5000, MAX_ITER=10000000;
  while(nonce<MAX_ITER){
    var batchEnd=Math.min(nonce+BATCH, MAX_ITER);
    for(;nonce<batchEnd;nonce++){
      var h=sha256(seed+':'+nonce);
      if(leadingZeroBits(h)>=powDiff){ target=nonce; nonce=MAX_ITER; break; }
    }
    if(target>0)break;
    // yield to UI thread between batches
    await new Promise(function(r){setTimeout(r,0);});
  }

  // cookie token: <issued_unix>.pow2.<nonce>.<flags> (= 4 segments).
  //   parts[0] = issuance unix seconds (= server-injected via window.UNMASK.issued_at).
  //   parts[1] = "pow2" marker (= distinguishes from the legacy djb2 cookie's base36 hash;
  //              server / C plugin uses this to branch into the SHA-256 verify path).
  //   parts[2] = nonce in base36 (= server verifies by recomputing SHA-256(seed+":"+nonce)).
  //   parts[3] = flags base36.
  var tok=issuedAt+'.pow2.'+target.toString(36)+'.'+flags.toString(36);

  var elapsed=Date.now()-start;

  // Branch by chain mode.  Two distinct phases because they mean different things:
  //   - 'pow_pass'    : PoW solved + handing off to next stage (= midpoint; still unauthenticated.
  //                     _bv is NOT issued here; the server issues it on the next stage pass)
  //   - 'bv_pow_only' : PoW solved + _bv issued client-side (= terminal; authentication complete
  //                     via the challenge_mode=pow_only route)
  // "Total PoW solved" is SUM(phase IN ('bv_pow_only','pow_pass')); _bv issuance attribution is
  // phase-level (bv_<chMode>) so the funnel doesn't need JSON_EXTRACT.
  if (chainPoWThenCaptcha) {
    _bcDebug('pow_pass', { pow_iterations: target, pow_elapsed_ms: elapsed, token_flags: flags });
    showCaptcha();
    return;
  }

  // Evict stale `_bv` at every ancestor directory of orig_path before setting
  // the fresh one.  Browsers send cookies in path-specificity order (longest
  // path first), so an old `_bv=...` at /foo/bar/ would sort ahead of our new
  // entry at / on every request to /foo/bar/* and a stale value would wedge
  // verification (= the server-side iteration fix accepts ANY valid cookie,
  // but cleaning up the shadow leaves a single canonical `_bv` in the jar).
  try {
    var op = (window.UNMASK && window.UNMASK.orig_path) || '/';
    var qm = op.indexOf('?'); if (qm >= 0) op = op.slice(0, qm);
    var segs = op.split('/').filter(function(s){ return s.length > 0; });
    var paths = ['/'];
    for (var i = 0; i < segs.length; i++) {
      paths.push('/' + segs.slice(0, i + 1).join('/') + '/');
    }
    for (var j = 0; j < paths.length; j++) {
      document.cookie = '_bv=;path=' + paths[j] +
        ';expires=Thu, 01 Jan 1970 00:00:00 GMT;SameSite=Lax';
    }
  } catch (_) { /* best effort */ }

  // _bv browser lifetime: fixed 365 days (= practically permanent).  The real
  // expiration gate is the server's PowCookieValidSeconds window evaluated at
  // each request against the embedded `issued_at` field, so a settings change
  // takes effect on the very next request rather than waiting for in-flight
  // cookies to expire client-side.  Date.now() here only controls the browser
  // Max-Age cap (= unrelated to authentication / signature validation).
  var exp2=new Date(Date.now()+86400000*365);
  document.cookie='_bv='+tok+';path=/;expires='+exp2.toUTCString()+';SameSite=Lax';
  // After PoW completion + cookie set (read back immediately to verify the set succeeded)
  var _bv_set_ok = /(?:^|;\s*)_bv=/.test(document.cookie);
  _bcDebug('bv_pow_only', { pow_iterations: target, pow_elapsed_ms: elapsed, cookie_set_ok: _bv_set_ok, token_flags: flags });

  // If the cookie can't be written, reloading won't help, so show an error and give up
  if (!_bv_set_ok) {
    showCookieError();
    return;
  }
  var wait=Math.max(800-elapsed,100);
  setTimeout(function(){passAndRedirect();},wait);
})();
