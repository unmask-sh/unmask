(async function(){
  // _preview=1 mode: see the early-return below `document.getElementById('msg').textContent=t.verify`.
  // We let setup run far enough to apply the brand / preset / site-name overlay
  // and paint the spinner text, then bail before any PoW or beacon work runs.

  // ============================================================
  // multi-site support: extract site ID from our own URL pathname.
  //   /unmask/challenge/            → site = "default"
  //   /unmask/challenge/test-1/     → site = "test-1"
  //   /unmask/challenge/shop.ex.jp/ → site = "shop.ex.jp" (host-derived id,
  //                                    used by the test-page site picker)
  //   /unmask/challenge.html        → site = "default" (legacy)
  // All fetch URLs are built as API_BASE + "/" + relative path.
  // ============================================================
  var SITE = 'default';
  var m = location.pathname.match(/^\/unmask\/challenge\/([a-z0-9][a-z0-9.-]*)\/?$/);
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
    // Remember the last phase reached so an abandonment beacon can say WHERE
    // the visitor gave up.  Recording it here rather than at each call site
    // means a phase added later is covered without anyone remembering to.
    // 'abandon' itself is excluded so it cannot overwrite the phase it is
    // reporting about.
    if (phase !== 'abandon') { try { window.__unmaskPhase = phase; } catch (_) {} }
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
        // force_reason rides every phase beacon (not just 'load') so the funnel
        // can attribute the whole serve->load->pass chain to the axis that
        // raised it (header / asn / geo / rate_limit / ...), not only counts.
        force_reason: (window.UNMASK && window.UNMASK.force_reason) || 'none',
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
  // window.onerror: record exceptions thrown on the challenge page.  Routed
  // through the unified 'error' phase with a kind discriminator.  Other
  // failure paths (ext_render_err / ext_exec_err / ext_unknown_provider)
  // also funnel into 'error' so the server-side allowedPhases set stays
  // small and the funnel SQL doesn't need to enumerate variants.
  //
  // Mobile pages are full of scripts unmask did not ship -- in-app webview
  // bridges, extensions, carrier-injected JS -- and their failures land on
  // this same global hook.  Classify by the reported source so the dashboard
  // can separate "challenge code broke" from that ambient noise:
  //   js_exception : this document (inline challenge script) or an /unmask/
  //                  asset -- actionable
  //   js_foreign   : cross-origin "Script error." (browsers mask message and
  //                  filename for foreign scripts) or a source that is
  //                  neither this document nor /unmask/*
  window.addEventListener('error', function(e){
    try {
      var src = String((e && e.filename) || '');
      var own = src && (src.split('#')[0] === location.href.split('#')[0] || src.indexOf('/unmask/') !== -1);
      _bcDebug('error', { kind: own ? 'js_exception' : 'js_foreign', error_msg:String(e && e.message), error_filename:src, error_lineno:e && e.lineno });
    } catch(_){}
  });

  // --- i18n ---
  //
  // The L baseline is what visitors see for languages that do NOT yet have
  // a preset translation in the P table (see below).  ja / en land on the
  // P-table presets (friendly / neutral / minimal) via the operator's
  // selection; the 16 other languages currently fall back to the L row.
  // To keep the visitor experience consistent across languages, the L
  // verify wording uses a calm, destination-focused loading message rather
  // than phrasing that made some real users worry their device was
  // compromised.  Title / desc / note / wrong / error were also softened
  // to avoid an accusatory tone.
  var L={
    en:{verify:'Loading {site_name}, just a moment...',title:'Quick check',desc:'Please confirm to continue.',note:'This check protects the site from malicious automated access.',notRobot:"I'm not a robot",wrong:"That didn't go through — please try once more.",error:'Something went wrong. Please try again in a moment.',checking:'Verifying...',verified:'Verified',connecting:'Connecting to {site_name}…'},
    ja:{verify:'{site_name} を読み込んでいます。もう少々お待ちください…',title:'アクセス確認',desc:'続行するにはチェックを入れてください。',note:'ボットによる不正アクセスからサイトを守るための確認です。',notRobot:'私はロボットではありません',wrong:'もう一度確認させてください。',error:'うまくいきませんでした。少し時間をおいてからお試しください。',checking:'確認中…',verified:'確認できました',connecting:'{site_name} に接続しています…'},
    zh:{verify:'正在加载 {site_name}，请稍候...',title:'快速验证',desc:'请勾选以继续。',note:'此验证用于保护网站免受恶意自动化访问。',notRobot:'我不是机器人',wrong:'请再试一次。',error:'出了点问题，请稍后再试。',checking:'正在验证…',verified:'验证通过',connecting:'正在连接到 {site_name}…'},
    zht:{verify:'正在載入 {site_name}，請稍候...',title:'快速驗證',desc:'請勾選以繼續。',note:'此驗證用於保護網站免受惡意自動化存取。',notRobot:'我不是機器人',wrong:'請再試一次。',error:'發生問題，請稍候再試。',checking:'正在驗證…',verified:'驗證通過',connecting:'正在連線至 {site_name}…'},
    ko:{verify:'{site_name} 로딩 중... 잠시만 기다려 주세요',title:'확인',desc:'계속하려면 체크해 주세요.',note:'봇의 악의적인 접근으로부터 사이트를 보호하기 위한 확인입니다.',notRobot:'저는 로봇이 아닙니다',wrong:'다시 한 번 시도해 주세요.',error:'문제가 발생했습니다. 잠시 후 다시 시도해 주세요.',checking:'확인 중…',verified:'확인되었습니다',connecting:'{site_name}에 연결하는 중…'},
    es:{verify:'Cargando {site_name}, un momento...',title:'Verificación rápida',desc:'Confirme para continuar.',note:'Esta verificación protege el sitio contra accesos automatizados maliciosos.',wrong:'Inténtelo una vez más, por favor.',enterNum:'Introduzca un número.',error:'Algo no funcionó. Inténtelo de nuevo en un momento.',checking:'Verificando…',verified:'Verificado',connecting:'Conectando con {site_name}…'},
    pt:{verify:'Carregando {site_name}, um momento...',title:'Verificação rápida',desc:'Confirme para continuar.',note:'Esta verificação protege o site contra acessos automatizados mal-intencionados.',wrong:'Tente novamente, por favor.',enterNum:'Digite um número.',error:'Algo deu errado. Tente novamente em um instante.',checking:'Verificando…',verified:'Verificado',connecting:'Conectando a {site_name}…'},
    fr:{verify:'Chargement de {site_name}, un instant...',title:'Vérification rapide',desc:'Confirmez pour continuer.',note:'Cette vérification protège le site contre les accès automatisés malveillants.',wrong:'Veuillez réessayer.',enterNum:'Veuillez entrer un nombre.',error:'Une erreur est survenue. Réessayez dans un instant.',checking:'Vérification…',verified:'Vérifié',connecting:'Connexion à {site_name}…'},
    de:{verify:'{site_name} wird geladen, einen Moment...',title:'Kurze Prüfung',desc:'Bestätigen Sie, um fortzufahren.',note:'Diese Prüfung schützt die Website vor böswilligen automatisierten Zugriffen.',wrong:'Bitte versuchen Sie es erneut.',enterNum:'Bitte geben Sie eine Zahl ein.',error:'Etwas ist schiefgelaufen. Bitte versuchen Sie es gleich noch einmal.',checking:'Wird überprüft…',verified:'Bestätigt',connecting:'Verbindung zu {site_name} wird hergestellt…'},
    ru:{verify:'Загрузка {site_name}, подождите немного...',title:'Быстрая проверка',desc:'Подтвердите, чтобы продолжить.',note:'Эта проверка защищает сайт от вредоносных автоматических обращений.',wrong:'Попробуйте ещё раз.',enterNum:'Введите число.',error:'Что-то пошло не так. Попробуйте снова через мгновение.',checking:'Проверка…',verified:'Проверено',connecting:'Подключение к {site_name}…'},
    it:{verify:'Caricamento di {site_name}, un attimo...',title:'Verifica rapida',desc:'Conferma per continuare.',note:'Questa verifica protegge il sito dagli accessi automatici dannosi.',wrong:'Riprova, per favore.',enterNum:'Inserisci un numero.',error:'Qualcosa è andato storto. Riprova tra poco.',checking:'Verifica in corso…',verified:'Verificato',connecting:'Connessione a {site_name}…'},
    tr:{verify:'{site_name} yükleniyor, bir saniye...',title:'Hızlı doğrulama',desc:'Devam etmek için onaylayın.',note:'Bu doğrulama, siteyi kötü amaçlı otomatik erişime karşı korur.',wrong:'Lütfen tekrar deneyin.',enterNum:'Lütfen bir sayı girin.',error:'Bir şeyler ters gitti. Birazdan tekrar deneyin.',checking:'Doğrulanıyor…',verified:'Doğrulandı',connecting:'{site_name} ile bağlantı kuruluyor…'},
    pl:{verify:'Ładowanie {site_name}, chwila...',title:'Szybka weryfikacja',desc:'Potwierdź, aby kontynuować.',note:'Ta weryfikacja chroni witrynę przed złośliwym zautomatyzowanym dostępem.',wrong:'Spróbuj jeszcze raz.',enterNum:'Proszę wpisać liczbę.',error:'Coś poszło nie tak. Spróbuj ponownie za chwilę.',checking:'Weryfikacja…',verified:'Zweryfikowano',connecting:'Łączenie z {site_name}…'},
    vi:{verify:'Đang tải {site_name}, một lát...',title:'Kiểm tra nhanh',desc:'Xác nhận để tiếp tục.',note:'Bước kiểm tra này bảo vệ trang web khỏi truy cập tự động độc hại.',wrong:'Vui lòng thử lại.',enterNum:'Vui lòng nhập một số.',error:'Đã xảy ra lỗi. Vui lòng thử lại sau giây lát.',checking:'Đang xác minh…',verified:'Đã xác minh',connecting:'Đang kết nối đến {site_name}…'},
    th:{verify:'กำลังโหลด {site_name} สักครู่...',title:'การยืนยันด่วน',desc:'กดยืนยันเพื่อดำเนินการต่อ',note:'การตรวจสอบนี้ช่วยปกป้องเว็บไซต์จากการเข้าถึงอัตโนมัติที่เป็นอันตราย',wrong:'กรุณาลองอีกครั้ง',enterNum:'กรุณาใส่ตัวเลข',error:'เกิดบางอย่างผิดพลาด กรุณาลองใหม่อีกครั้ง',checking:'กำลังตรวจสอบ…',verified:'ยืนยันแล้ว',connecting:'กำลังเชื่อมต่อกับ {site_name}…'},
    id:{verify:'Memuat {site_name}, sebentar...',title:'Pemeriksaan cepat',desc:'Konfirmasi untuk melanjutkan.',note:'Pemeriksaan ini melindungi situs dari akses otomatis berbahaya.',wrong:'Silakan coba lagi.',enterNum:'Masukkan angka.',error:'Terjadi kesalahan. Silakan coba lagi sebentar lagi.',checking:'Memverifikasi…',verified:'Terverifikasi',connecting:'Menghubungkan ke {site_name}…'},
    ar:{verify:'جارٍ تحميل {site_name}، لحظة...',title:'تحقق سريع',desc:'يرجى التأكيد للمتابعة.',note:'هذا التحقق يحمي الموقع من الوصول الآلي الضار.',wrong:'يرجى المحاولة مرة أخرى.',enterNum:'الرجاء إدخال رقم.',error:'حدث خطأ ما. يرجى المحاولة بعد لحظات.',checking:'جارٍ التحقق…',verified:'تم التحقق',connecting:'جارٍ الاتصال بـ {site_name}…'},
    hi:{verify:'{site_name} लोड हो रहा है, एक क्षण...',title:'त्वरित जाँच',desc:'जारी रखने के लिए पुष्टि करें।',note:'यह जाँच साइट को दुर्भावनापूर्ण स्वचालित पहुँच से बचाती है।',wrong:'कृपया फिर से प्रयास करें।',enterNum:'कृपया एक संख्या दर्ज करें।',error:'कुछ गलत हो गया। कृपया कुछ देर बाद पुनः प्रयास करें।',checking:'सत्यापित किया जा रहा है…',verified:'सत्यापित',connecting:'{site_name} से कनेक्ट हो रहा है…'}
  };

  // language detection: preview override -> URL path -> Accept-Language -> English
  function detectLang(){
    // Preview override: the admin theme tab / /admin/test/ pages pass
    // ?_preview_lang=XX so the operator can preview any locale regardless of
    // their own browser language.  Honored only in a preview context; real
    // visitors keep path -> Accept-Language detection unchanged.
    try{
      var pq=new URLSearchParams(location.search);
      var isPrev=pq.get('_preview')==='1'||location.pathname.indexOf('/admin/test/')!==-1;
      var pl=pq.get('_preview_lang');
      if(isPrev&&pl&&L[pl])return pl;
    }catch(_){}
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
  // preset text translated into their own language.  All 18 languages have
  // friendly / neutral / minimal entries so preset switching is honoured
  // regardless of the visitor's locale.
  //
  // {site_name} in any preset / L string is replaced with the configured
  // site name, or a localized default ("サイト" / "this site") when not
  // configured.
  var P={
    friendly:{
      en:{verify:'Loading {site_name}, just a moment...',title:'Quick check',desc:'Please confirm to continue.',note:'This check protects the site from malicious automated access.'},
      ja:{verify:'{site_name} を読み込んでいます。もう少々お待ちください…',title:'アクセス確認',desc:'続行するにはチェックを入れてください。',note:'ボットによる不正アクセスからサイトを守るための確認です。'},
      zh:{verify:'正在加载 {site_name},请稍候...',title:'快速验证',desc:'请勾选以继续。',note:'此验证用于保护网站免受恶意自动化访问。'},
      zht:{verify:'正在載入 {site_name},請稍候...',title:'快速驗證',desc:'請勾選以繼續。',note:'此驗證用於保護網站免受惡意自動化存取。'},
      ko:{verify:'{site_name} 로딩 중... 잠시만 기다려 주세요',title:'확인',desc:'계속하려면 체크해 주세요.',note:'봇의 악의적인 접근으로부터 사이트를 보호하기 위한 확인입니다.'},
      es:{verify:'Cargando {site_name}, un momento...',title:'Verificación rápida',desc:'Confirme para continuar.',note:'Esta verificación protege el sitio contra accesos automatizados maliciosos.'},
      pt:{verify:'Carregando {site_name}, um momento...',title:'Verificação rápida',desc:'Confirme para continuar.',note:'Esta verificação protege o site contra acessos automatizados mal-intencionados.'},
      fr:{verify:'Chargement de {site_name}, un instant...',title:'Vérification rapide',desc:'Confirmez pour continuer.',note:'Cette vérification protège le site contre les accès automatisés malveillants.'},
      de:{verify:'{site_name} wird geladen, einen Moment...',title:'Kurze Prüfung',desc:'Bestätigen Sie, um fortzufahren.',note:'Diese Prüfung schützt die Website vor böswilligen automatisierten Zugriffen.'},
      ru:{verify:'Загрузка {site_name}, подождите немного...',title:'Быстрая проверка',desc:'Подтвердите, чтобы продолжить.',note:'Эта проверка защищает сайт от вредоносных автоматических обращений.'},
      it:{verify:'Caricamento di {site_name}, un attimo...',title:'Verifica rapida',desc:'Conferma per continuare.',note:'Questa verifica protegge il sito dagli accessi automatici dannosi.'},
      tr:{verify:'{site_name} yükleniyor, bir saniye...',title:'Hızlı doğrulama',desc:'Devam etmek için onaylayın.',note:'Bu doğrulama, siteyi kötü amaçlı otomatik erişime karşı korur.'},
      pl:{verify:'Ładowanie {site_name}, chwila...',title:'Szybka weryfikacja',desc:'Potwierdź, aby kontynuować.',note:'Ta weryfikacja chroni witrynę przed złośliwym zautomatyzowanym dostępem.'},
      vi:{verify:'Đang tải {site_name}, một lát...',title:'Kiểm tra nhanh',desc:'Xác nhận để tiếp tục.',note:'Bước kiểm tra này bảo vệ trang web khỏi truy cập tự động độc hại.'},
      th:{verify:'กำลังโหลด {site_name} สักครู่...',title:'การยืนยันด่วน',desc:'กดยืนยันเพื่อดำเนินการต่อ',note:'การตรวจสอบนี้ช่วยปกป้องเว็บไซต์จากการเข้าถึงอัตโนมัติที่เป็นอันตราย'},
      id:{verify:'Memuat {site_name}, sebentar...',title:'Pemeriksaan cepat',desc:'Konfirmasi untuk melanjutkan.',note:'Pemeriksaan ini melindungi situs dari akses otomatis berbahaya.'},
      ar:{verify:'جارٍ تحميل {site_name}، لحظة...',title:'تحقق سريع',desc:'يرجى التأكيد للمتابعة.',note:'هذا التحقق يحمي الموقع من الوصول الآلي الضار.'},
      hi:{verify:'{site_name} लोड हो रहा है, एक क्षण...',title:'त्वरित जाँच',desc:'जारी रखने के लिए पुष्टि करें।',note:'यह जाँच साइट को दुर्भावनापूर्ण स्वचालित पहुँच से बचाती है।'}
    },
    neutral:{
      en:{verify:'Verifying your access to {site_name}, please wait...',title:'Security check',desc:'Please confirm to continue.',note:'This check protects against automated access.'},
      ja:{verify:'{site_name} へのアクセスを確認しています。しばらくお待ちください…',title:'セキュリティ確認',desc:'続行するにはチェックを入れてください。',note:'自動アクセスを防ぐための確認です。'},
      zh:{verify:'正在验证您对 {site_name} 的访问,请稍候...',title:'安全验证',desc:'请勾选以继续。',note:'此验证可防止自动化访问。'},
      zht:{verify:'正在驗證您對 {site_name} 的存取,請稍候...',title:'安全驗證',desc:'請勾選以繼續。',note:'此驗證可防止自動化存取。'},
      ko:{verify:'{site_name}에 대한 액세스를 확인하고 있습니다. 잠시만 기다려 주세요...',title:'보안 확인',desc:'계속하려면 체크해 주세요.',note:'자동화된 접근을 막기 위한 확인입니다.'},
      es:{verify:'Verificando tu acceso a {site_name}, espera un momento...',title:'Verificación de seguridad',desc:'Confirme para continuar.',note:'Esta verificación protege contra accesos automatizados.'},
      pt:{verify:'Verificando seu acesso a {site_name}, aguarde um momento...',title:'Verificação de segurança',desc:'Confirme para continuar.',note:'Esta verificação protege contra acessos automatizados.'},
      fr:{verify:'Vérification de votre accès à {site_name}, patientez un instant...',title:'Vérification de sécurité',desc:'Confirmez pour continuer.',note:'Cette vérification protège contre les accès automatisés.'},
      de:{verify:'Ihr Zugriff auf {site_name} wird überprüft, einen Moment...',title:'Sicherheitsprüfung',desc:'Bestätigen Sie, um fortzufahren.',note:'Diese Prüfung schützt vor automatisierten Zugriffen.'},
      ru:{verify:'Проверяем ваш доступ к {site_name}, подождите...',title:'Проверка безопасности',desc:'Подтвердите, чтобы продолжить.',note:'Эта проверка защищает от автоматических обращений.'},
      it:{verify:'Verifica del tuo accesso a {site_name}, attendi un momento...',title:'Verifica di sicurezza',desc:'Conferma per continuare.',note:'Questa verifica protegge dagli accessi automatici.'},
      tr:{verify:'{site_name} erişiminiz doğrulanıyor, lütfen bekleyin...',title:'Güvenlik doğrulaması',desc:'Devam etmek için onaylayın.',note:'Bu doğrulama otomatik erişime karşı koruma sağlar.'},
      pl:{verify:'Weryfikujemy Twój dostęp do {site_name}, proszę czekać...',title:'Weryfikacja bezpieczeństwa',desc:'Potwierdź, aby kontynuować.',note:'Ta weryfikacja chroni przed zautomatyzowanym dostępem.'},
      vi:{verify:'Đang xác minh quyền truy cập của bạn vào {site_name}, vui lòng chờ...',title:'Kiểm tra bảo mật',desc:'Xác nhận để tiếp tục.',note:'Bước kiểm tra này giúp chặn truy cập tự động.'},
      th:{verify:'กำลังตรวจสอบการเข้าถึง {site_name} ของคุณ กรุณารอสักครู่...',title:'การตรวจสอบความปลอดภัย',desc:'กดยืนยันเพื่อดำเนินการต่อ',note:'การตรวจสอบนี้ป้องกันการเข้าถึงอัตโนมัติ'},
      id:{verify:'Memverifikasi akses Anda ke {site_name}, mohon tunggu...',title:'Pemeriksaan keamanan',desc:'Konfirmasi untuk melanjutkan.',note:'Pemeriksaan ini melindungi dari akses otomatis.'},
      ar:{verify:'جارٍ التحقق من وصولك إلى {site_name}، يرجى الانتظار...',title:'تحقق أمني',desc:'يرجى التأكيد للمتابعة.',note:'هذا التحقق يحمي من الوصول الآلي.'},
      hi:{verify:'{site_name} तक आपकी पहुँच की पुष्टि की जा रही है, कृपया प्रतीक्षा करें...',title:'सुरक्षा जाँच',desc:'जारी रखने के लिए पुष्टि करें।',note:'यह जाँच स्वचालित पहुँच से सुरक्षा करती है।'}
    },
    minimal:{
      en:{verify:'Connecting to {site_name}...',title:'Connecting',desc:'Please confirm to continue.',note:''},
      ja:{verify:'{site_name} に接続中…',title:'接続中',desc:'続行するにはチェックを入れてください。',note:''},
      zh:{verify:'正在连接到 {site_name}...',title:'正在连接',desc:'请勾选以继续。',note:''},
      zht:{verify:'正在連線至 {site_name}...',title:'正在連線',desc:'請勾選以繼續。',note:''},
      ko:{verify:'{site_name}에 연결 중...',title:'연결 중',desc:'계속하려면 체크해 주세요.',note:''},
      es:{verify:'Conectando con {site_name}...',title:'Conectando',desc:'Confirme para continuar.',note:''},
      pt:{verify:'Conectando a {site_name}...',title:'Conectando',desc:'Confirme para continuar.',note:''},
      fr:{verify:'Connexion à {site_name}...',title:'Connexion',desc:'Confirmez pour continuer.',note:''},
      de:{verify:'Verbindung zu {site_name}...',title:'Verbindung',desc:'Bestätigen Sie, um fortzufahren.',note:''},
      ru:{verify:'Подключение к {site_name}...',title:'Подключение',desc:'Подтвердите, чтобы продолжить.',note:''},
      it:{verify:'Connessione a {site_name}...',title:'Connessione',desc:'Conferma per continuare.',note:''},
      tr:{verify:'{site_name} adresine bağlanılıyor...',title:'Bağlanıyor',desc:'Devam etmek için onaylayın.',note:''},
      pl:{verify:'Łączenie z {site_name}...',title:'Łączenie',desc:'Potwierdź, aby kontynuować.',note:''},
      vi:{verify:'Đang kết nối tới {site_name}...',title:'Đang kết nối',desc:'Xác nhận để tiếp tục.',note:''},
      th:{verify:'กำลังเชื่อมต่อกับ {site_name}...',title:'กำลังเชื่อมต่อ',desc:'กดยืนยันเพื่อดำเนินการต่อ',note:''},
      id:{verify:'Menghubungkan ke {site_name}...',title:'Menghubungkan',desc:'Konfirmasi untuk melanjutkan.',note:''},
      ar:{verify:'جارٍ الاتصال بـ {site_name}...',title:'جارٍ الاتصال',desc:'يرجى التأكيد للمتابعة.',note:''},
      hi:{verify:'{site_name} से कनेक्ट हो रहा है...',title:'कनेक्ट हो रहा है',desc:'जारी रखने के लिए पुष्टि करें।',note:''}
    }
  };
  var brand=(window.UNMASK&&window.UNMASK.brand)||null;
  // Admin "live preview" overrides: the branding panel links to
  // /admin/test/force-* with ?_preview_preset=X (and optionally
  // ?_preview_site_name=...); the theme cards' iframes use the same params
  // with ?_preview=1 on /unmask/challenge/.  Honour the override when EITHER
  // path is admin-auth-gated (/admin/test/) OR _preview=1 is set on the
  // challenge route (the latter is rendered with `pointer-events:none` inside
  // an admin iframe and only paints text -- no real bypass).  Public visitors
  // hitting /unmask/challenge/ without _preview=1 cannot inject a preset.
  try {
    var qs = new URLSearchParams(location.search);
    var isAdminTest = location.pathname.indexOf('/admin/test/') !== -1;
    // _preview=1 is reachable without auth, so a phishing link
    // (/unmask/challenge/?_preview=1&_preview_site_name=...) could rewrite the
    // page's site name / footer.  Gate the free-text override on a same-origin
    // /admin/ referrer: the theme-tab iframe carries it, a victim-facing link
    // does not (M-C1).  /admin/test/ stays trusted via isAdminTest (auth path).
    var isIframePreview = qs.get('_preview') === '1' && (function () {
      try {
        var ref = new URL(document.referrer);
        return ref.origin === location.origin && ref.pathname.indexOf('/admin/') !== -1;
      } catch (e) { return false; }
    })();
    if (isAdminTest || isIframePreview) {
      var qp  = qs.get('_preview_preset');
      var qs2 = qs.get('_preview_site_name');
      var qs3 = qs.get('_preview_footer_text');
      if ((qp && P[qp]) || qs2 != null || qs3 != null) {
        if (!brand) brand = {};
        if (qp && P[qp]) brand.copy_preset = qp;
        if (qs2 != null) brand.site_name = qs2;
        if (qs3 != null) brand.footer_text = qs3;
      }
    }
  } catch (_) {}
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
  // Apply brand DOM (logo / footer).  Site name lives only in the copy
  // ({site_name} substitution above) and as the logo's alt text -- a
  // visible name line below the logo was redundant with the logo image
  // itself.  Each element is hidden by default in challenge.html and only
  // shown when the corresponding brand field is set, so layouts without
  // branding don't shift.
  if(brand){
    var bhead=document.getElementById('brand-head');
    var blogo=document.getElementById('brand-logo');
    var bfoot=document.getElementById('brand-foot');
    if(brand.logo_url&&blogo){
      blogo.src=brand.logo_url;
      blogo.alt=brand.site_name||'';
      blogo.style.display='';
      if(bhead) bhead.style.display='';
    }
    if(brand.footer_text&&bfoot){
      bfoot.textContent=brand.footer_text;
      bfoot.style.display='';
    }
  }

  // set the html lang and dir attributes
  document.documentElement.lang=lang==='zht'?'zh-Hant':lang;
  if(lang==='ar')document.documentElement.dir='rtl';

  // "protected by unmask" credit: point a Japanese visitor at the Japanese
  // landing page.  The credit is the one link out of the challenge, and it sent
  // every locale to the English root -- a visitor who just read a Japanese
  // challenge landed on English copy.  Only /ja/ exists on the site; the other
  // 17 locales keep the root.  The LABEL stays English (it is the brand mark).
  //
  // Deferred to DOMContentLoaded on purpose: the credit <aside> sits AFTER this
  // script in the document, and ServeChallenge inlines the script verbatim in
  // place of its `defer`-ed <script src> tag -- which drops the defer, so this
  // code runs synchronously while the aside does not exist yet.  Querying it
  // here directly would silently no-op.
  if(lang==='ja'){
    var pointCreditToJa=function(){
      var credit=document.querySelector('.unmask-credit a');
      if(credit)credit.href='https://unmask.sh/ja/';
    };
    if(document.readyState==='loading'){
      document.addEventListener('DOMContentLoaded',pointCreditToJa);
    }else{
      pointCreditToJa();
    }
  }

  // set initial text
  document.getElementById('msg').textContent=t.verify;

  // ============================================================
  // _preview=1 / admin theme cards: stop here.  Setup has run far enough
  // to paint the brand (logo / site name / footer / preset text); skip
  // behavioral listeners, PoW, CAPTCHA, debug beacons, and the redirect
  // back to orig.  See the early-return comment at the top of the IIFE.
  // ============================================================
  if (window.UNMASK && window.UNMASK._preview) return;

  var start=Date.now();
  var captchaToken='';
  var captchaCt='';

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
    // Collapse the PoW progress bar's reserved box (height + .6em/1em margins) so
    // the CAPTCHA card doesn't sit under an empty gap where the spinner/bar were.
    var pp=document.getElementById('powProgress'); if(pp) pp.style.display='none';
    var cap=document.getElementById('captcha');
    cap.style.display='block';
    // Trigger the fade-in / slide-up transition next frame (= must paint at
    // the initial opacity/transform first, then flip to .show, otherwise the
    // browser collapses the two state changes and the animation never runs).
    requestAnimationFrame(function(){ cap.classList.add('show'); });
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
    mount.innerHTML='';
    // Loading spinner shown from now until the provider's widget iframe is
    // actually in the DOM.  Both the provider script download AND the widget's
    // own challenge fetch can take several seconds; clearing on script-load
    // alone leaves a multi-second blank box that reads as broken.  The provider
    // mounts into a separate child (`widget`) so the spinner can persist until
    // its iframe appears -- then the widget's own loading UI takes over.
    var spin = document.createElement('div');
    spin.className='spinner';
    spin.style.cssText='width:28px;height:28px;border-width:3px;margin:.2em auto';
    var widget = document.createElement('div');
    mount.appendChild(spin); mount.appendChild(widget);
    function stopSpin(){ if (spin.parentNode) spin.parentNode.removeChild(spin); }
    function spinUntilWidget(){
      // Clear our spinner once the provider's own widget box is visible (its own
      // "verifying" UI then takes over).  Detect this with a ResizeObserver on
      // the mount child -- NOT a MutationObserver: the provider renders into a
      // shadow DOM / cross-origin iframe whose internal changes never reach a
      // MutationObserver (or querySelector) on the host, but the host's SIZE
      // change when the widget paints does.  Avoids a blank gap, a stuck double
      // spinner, AND a false error while the widget is actually showing.
      function visible(){ return widget.getBoundingClientRect().height > 8; }
      var tm = setTimeout(function(){ if (!visible()) extFail('ext_load_timeout')(); }, 10000);
      function onShown(){ stopSpin(); clearTimeout(tm); }
      if (typeof ResizeObserver !== 'undefined') {
        var ro = new ResizeObserver(function(){ if (visible()) { ro.disconnect(); onShown(); } });
        ro.observe(widget);
      } else {
        var iv = setInterval(function(){ if (visible()) { clearInterval(iv); onShown(); } }, 150);
      }
    }
    // error / timeout: external widgets can fail silently (= provider key not
    // enabled for this domain, network blocked, script blocked).  Surface it
    // instead of leaving a blank/stuck box the visitor cannot act on.
    function extFail(kind){ return function(e){ stopSpin(); widget.innerHTML=''; showError(t.error); _bcDebug('error', { kind:kind, provider:provider, error:(e===undefined?'':String(e)) }); }; }
    function done(token){ submitProviderToken(token); }
    if (provider === 'turnstile') {
      window._unmaskTurnstileCb = function(){
        try { spinUntilWidget(); window.turnstile.render(widget, { sitekey: siteKey, callback: done, 'error-callback': extFail('ext_error_cb'), 'timeout-callback': extFail('ext_timeout_cb') }); }
        catch(e){ stopSpin(); showError(t.error); _bcDebug('error', { kind:'ext_render_err', provider: provider, error: String(e) }); }
      };
      injectScript('https://challenges.cloudflare.com/turnstile/v0/api.js?onload=_unmaskTurnstileCb&render=explicit');
    } else if (provider === 'hcaptcha') {
      window._unmaskHcaptchaCb = function(){
        try { spinUntilWidget(); window.hcaptcha.render(widget, { sitekey: siteKey, callback: done, 'error-callback': extFail('ext_error_cb') }); }
        catch(e){ stopSpin(); showError(t.error); _bcDebug('error', { kind:'ext_render_err', provider: provider, error: String(e) }); }
      };
      injectScript('https://js.hcaptcha.com/1/api.js?onload=_unmaskHcaptchaCb&render=explicit');
    } else if (provider === 'recaptcha') {
      // v3 invisible: no widget iframe, so keep the spinner until the token
      // resolves (or fails) -- there is nothing else for the visitor to see.
      window._unmaskRecaptchaCb = function(){
        try {
          window.grecaptcha.ready(function(){
            window.grecaptcha.execute(siteKey, { action: 'unmask' }).then(function(tok){ stopSpin(); done(tok); }).catch(function(e){
              stopSpin(); showError(t.error); _bcDebug('error', { kind:'ext_exec_err', provider: provider, error: String(e) });
            });
          });
        } catch(e){ stopSpin(); showError(t.error); _bcDebug('error', { kind:'ext_render_err', provider: provider, error: String(e) }); }
      };
      injectScript('https://www.google.com/recaptcha/api.js?render=' + encodeURIComponent(siteKey) + '&onload=_unmaskRecaptchaCb');
    } else {
      stopSpin();
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

  // Post-click status: hide the checkbox / math, show a spinner + message so a
  // slow /verify or a slow redirect target never leaves the visitor unsure
  // whether their click registered.  done=true marks success (= a checkmark
  // kept on screen with the spinner while the destination page loads).
  function showCaptchaBusy(msg, done){
    var cr=document.getElementById('clickRow'); if(cr) cr.style.display='none';
    var mf=document.getElementById('mathFallback'); if(mf) mf.style.display='none';
    var em=document.getElementById('errMsg'); if(em) em.style.display='none';
    var box=document.getElementById('captchaBusy');
    var m=document.getElementById('captchaBusyMsg');
    if(!box||!m) return;
    box.style.display='flex';
    m.textContent=(done?'✓ ':'')+msg;
    m.style.color=done?'#16a34a':'#475569';
    // The "connecting to the site" sub-line belongs to the success state only.
    // Hide it during a plain "verifying" pass so a retry never shows a stale line.
    if(!done){ var sb=document.getElementById('captchaBusySub'); if(sb) sb.style.display='none'; }
    // On success the instruction ("please tick the box") and the why-this-check
    // note have done their job -- the box they refer to is gone, so leaving
    // them up reads as a stale prompt.  Success never returns to the checkbox
    // (passAndRedirect navigates away), so there is nothing to restore.
    if(done){
      var dsc=document.getElementById('captchaDesc'); if(dsc) dsc.style.display='none';
      var nt=document.getElementById('captchaNote'); if(nt) nt.style.display='none';
    }
  }

  function submitClick(){
    document.getElementById('errMsg').style.display='none';
    showCaptchaBusy(t.checking || 'Verifying...');
    var clickAt = Math.round(performance.now());
    fetch(API_BASE + '/verify', {
      method:'POST',
      headers:{'Content-Type':'application/json'},
      body:JSON.stringify({
        token: captchaToken,
        ct: (window.UNMASK && window.UNMASK.ct) || '', // proof-of-load token bound to IP + this challenge
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
      var bz=document.getElementById('captchaBusy'); if(bz) bz.style.display='none';
      var cr=document.getElementById('clickRow'); if(cr) cr.style.display='';
      showError(t.error);
      var cb = document.getElementById('notRobot');
      cb.checked = false;
      cb.disabled = false;
    });
  }

  function passAndRedirect(){
    // Leaving this page is now intentional: suppress the abandonment beacon,
    // which pagehide would otherwise fire on the very navigation that means
    // the visitor succeeded.
    try { window.__unmaskPassed = true; } catch (_) {}
    // Success state stays painted (✓ + spinner) while the destination loads --
    // location.replace doesn't unload this page until the target renders.  The
    // sub-line says the check passed AND the site is now loading, so a slow
    // origin doesn't read as "verified but stuck / not connecting".
    showCaptchaBusy(t.verified || 'Verified', true);
    var sub=document.getElementById('captchaBusySub');
    if(sub){ sub.textContent=(t.connecting||'Connecting to the site…'); sub.style.display=''; }
    var u=new URL(location.href);
    u.searchParams.delete('_test_bot');
    u.searchParams.delete('_test_ja4');
    // the following paths have no "original page" (= test or direct access), so redirect to "/".
    //   - /unmask/challenge.html / /unmask/challenge/<site>/    direct challenge access
    //   - /unmask/(admin/)?test/force-*                         test pages of any flavor
    //                                                            (pow / pow-then-captcha / captcha / ...).
    //                                                            Reloading the same path causes a loop.
    // The <site> segment must accept dots: site ids are host names
    // (shop.example.jp), and the id parser at the top of this file already
    // does.  This copy did not, so a site-scoped page fell through to the
    // "reload the original URL" branch below and reloaded ITSELF -- solve,
    // redirect here, serve a challenge, solve, ... which is the loop the
    // comment above warns about, reachable from the test page's site picker
    // for every real host name.
    if (u.pathname === '/unmask/challenge.html' ||
        /^\/unmask\/challenge(\/[a-z0-9][a-z0-9.-]*)?\/?$/.test(u.pathname) ||
        /^\/unmask\/(admin\/)?test\/force-[a-z][a-z0-9-]*\/?$/.test(u.pathname)) {
      // Test-only override: ?_test_redirect=PATH (same-origin only).  Must
      // start with `/` and must not be protocol-relative `//host`, so a
      // hostile URL crafted with `_test_redirect=https://evil.example/` is
      // ignored.  Empty / invalid falls back to "/".
      var target = '/';
      var qsRedir = u.searchParams.get('_test_redirect');
      // Local path only: reject "//host" AND "/\host" (browsers normalize the
      // backslash to "//" = off-site protocol-relative redirect).
      if (qsRedir && qsRedir.length > 0 && qsRedir.charAt(0) === '/' && qsRedir.charAt(1) !== '/' && qsRedir.charAt(1) !== '\\') {
        target = qsRedir;
      }
      location.replace(target);
    } else {
      location.replace(u.pathname+u.search);
    }
  }

  // numeric-add fallback. Rescues users whose checkbox behavioral check failed.
  function showMathFallback(){
    document.getElementById('clickRow').style.display='none';
    var bz=document.getElementById('captchaBusy'); if(bz) bz.style.display='none';
    document.getElementById('errMsg').style.display='none';
    document.getElementById('mathFallback').style.display='block';
    document.getElementById('captchaDesc').textContent = (t.solveMath || 'Please solve this to continue.');
    fetch(API_BASE + '/captcha/new').then(function(r){return r.json();}).then(function(data){
      captchaToken = data.token;
      captchaCt = data.ct || '';
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
      body:JSON.stringify({answer:parseInt(ans), token:captchaToken, ct:captchaCt})
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
          captchaCt = data.ct || '';
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
  // Cookie-required screen.  Old wording said "to verify your browser",
  // which fed the same "is my browser infected?" anxiety that drove the
  // visitor-copy rewrite above.  Reframe as "needed to load this site" so
  // the visitor understands cookies are a normal site requirement, not a
  // security investigation.
  var COOKIE_ERR_I18N = {
    en: { title:'Please enable cookies', desc:'This site needs cookies to load. Please enable cookies in your browser settings and reload this page.' },
    ja: { title:'Cookie を有効にしてください', desc:'このサイトを表示するには cookie が必要です。ブラウザの設定で cookie を有効にして、ページを再読み込みしてください。' },
    zh: { title:'请启用 Cookie', desc:'本站需要 Cookie 才能正常加载。请在浏览器设置中启用 Cookie 后重新加载页面。' },
    zht:{ title:'請啟用 Cookie', desc:'本站需要 Cookie 才能正常載入。請在瀏覽器設定中啟用 Cookie 後重新載入頁面。' },
    ko: { title:'쿠키를 활성화해 주세요', desc:'이 사이트를 표시하려면 쿠키가 필요합니다. 브라우저 설정에서 쿠키를 활성화한 후 페이지를 다시 로드해 주세요.' },
    es: { title:'Habilite las cookies', desc:'Este sitio necesita cookies para cargar. Habilite las cookies en la configuración de su navegador y recargue la página.' },
    pt: { title:'Habilite os cookies', desc:'Este site precisa de cookies para carregar. Habilite os cookies nas configurações do seu navegador e recarregue a página.' },
    fr: { title:'Activez les cookies', desc:'Ce site a besoin des cookies pour se charger. Activez les cookies dans les paramètres de votre navigateur et rechargez la page.' },
    de: { title:'Bitte Cookies aktivieren', desc:'Diese Website benötigt Cookies zum Laden. Aktivieren Sie Cookies in Ihren Browser-Einstellungen und laden Sie die Seite neu.' }
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

  // ============================================================
  // Abandonment tracking.
  //
  // A visitor who closes the tab or hits Back mid-challenge leaves no trace:
  // the phase chain simply stops, which looks identical to a bot that fetched
  // the page and never ran the JS.  That ambiguity makes the one question
  // worth asking -- are we losing real people to the wait, and at which step
  // -- unanswerable from the counts alone.  Report the departure with the
  // phase it happened in and how long the visitor had been waiting.
  //
  // pagehide rather than beforeunload: beforeunload is unreliable on mobile
  // (a backgrounded tab may be discarded without firing it) and blocks the
  // bfcache.  visibilitychange->hidden covers the tab-switch-then-killed case
  // that pagehide can miss.  Whichever runs first wins; `left` makes it fire
  // at most once.
  //
  // Which UI gesture it was (Back vs close vs a link) is deliberately not
  // guessed: browsers do not expose that, and a wrong label is worse than no
  // label.  What matters for tuning is the phase and the elapsed time.
  (function(){
    var left = false;
    function abandon(via, ev){
      // Passing navigates away on purpose -- that is a success, not a
      // departure, and counting it would drown the signal we came for.
      if (left || window.__unmaskPassed) return;
      left = true;
      // Two different clocks, and the gap between them is itself a finding.
      //
      // elapsed_ms (added by _bcDebug) is when this handler RAN.  The PoW
      // yields between batches, but an event that arrives mid-batch waits for
      // the loop to release the thread, so the handler can run measurably
      // later than the visitor acted -- which is why a departure during the
      // final batch surfaces just after the solve and reads as "left right
      // after passing".
      //
      // event.timeStamp is when the browser CREATED the event, i.e. when the
      // visitor actually left, and it does not shift when the handler is
      // delayed (measured: a 600ms blocked thread put 474ms between the two).
      // Reporting both makes "when they left" and "when we noticed" separable
      // -- and the difference doubles as a read on how much the PoW is
      // holding the UI.
      // No bfcache / persisted flag here.  It is the one hint a browser gives
      // about a Back navigation, but a challenge page is served no-store and
      // is therefore never bfcache-eligible, so the flag can only ever read
      // false -- a field that looks like evidence and carries none.  Whether
      // the visitor went back or closed is answered instead by what the server
      // sees next: a Back lands them on another page and produces a follow-up
      // request; a close produces silence.
      var extra = {
        abandon_phase: window.__unmaskPhase || 'load',
        // pagehide = left the page (navigated away or closed; not coming back)
        // hidden   = tab backgrounded (they may well return)
        abandon_via: via,
        chmode: chMode
      };
      try {
        if (ev && typeof ev.timeStamp === 'number' && ev.timeStamp > 0) {
          // Relative to the page's own start, matching elapsed_ms's origin,
          // so the two are directly comparable.
          extra.left_at_ms = Math.round(ev.timeStamp);
          if (typeof performance !== 'undefined' && performance.now) {
            extra.notice_delay_ms = Math.max(0, Math.round(performance.now() - ev.timeStamp));
          }
        }
      } catch (_) { /* timeStamp is optional; never lose the beacon over it */ }
      _bcDebug('abandon', extra);
    }
    window.addEventListener('pagehide', function(e){
      abandon('pagehide', e);
    });
    document.addEventListener('visibilitychange', function(e){
      if (document.visibilityState === 'hidden') abandon('hidden', e);
    });
  })();

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
  // seed is SERVER-supplied (= PowSeed(bvSecret, clientIP, issued)): the client
  // cannot derive it (no secret), so the PoW can't be precomputed offline, and
  // it is bound to this IP so a solved cookie can't be reused from another IP.
  var seed=(window.UNMASK && window.UNMASK.pow_seed) || '';

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
  // Expected work to find powDiff leading-zero bits is 2^powDiff, so a fixed
  // 10M cap locks out legitimate visitors once the operator raises difficulty
  // (2^24 = 16.7M > 10M -> ~half never solve and loop).  Scale the budget to
  // ~8x the expectation (>99.9% solve) with a 10M floor for the default (18).
  var BATCH=5000, MAX_ITER=Math.max(10000000, Math.pow(2, powDiff) * 8);
  // Reveal the progress bar -- the visitor sees something moving instead of a
  // static "Loading..." that reads like a hung page (= ~6% of legitimate
  // browsers abandon the challenge during this loop with no other signal in
  // the logs, see hunt's load-then-silent investigation 2026-05-25).
  // The expected nonce on a successful solve is ~2^(powDiff-1) on average
  // (= geometric distribution mean for a leading-zero-bit target).  We scale
  // the bar against that midpoint and clamp at 95% so the bar can keep moving
  // forward even when the solve runs longer than average -- jumping to 100%
  // only on completion avoids the "stuck at 100%" look that suggests a freeze.
  var powBar=document.getElementById('powProgress');
  var powFill=document.getElementById('powProgressFill');
  var powExpectedAvg=Math.pow(2, Math.max(1, powDiff - 1));
  if(powBar){ powBar.style.opacity='1'; }
  while(nonce<MAX_ITER){
    var batchEnd=Math.min(nonce+BATCH, MAX_ITER);
    for(;nonce<batchEnd;nonce++){
      var h=sha256(seed+':'+nonce);
      if(leadingZeroBits(h)>=powDiff){ target=nonce; nonce=MAX_ITER; break; }
    }
    if(target>0)break;
    if(powFill){
      var pct=Math.min(95, Math.round((nonce/powExpectedAvg)*60));
      powFill.style.width=pct+'%';
    }
    // yield to UI thread between batches
    await new Promise(function(r){setTimeout(r,0);});
  }
  if(powFill){ powFill.style.width='100%'; }

  // cookie token: <issued_unix>.pow2.<nonce>.<flags> (= 4 segments).
  //   parts[0] = issuance unix seconds (= server-injected via window.UNMASK.issued_at).
  //   parts[1] = "pow2" marker (= server / C plugin branches into the SHA-256 verify path).
  //   parts[2] = nonce in base36 (= server verifies by recomputing SHA-256(seed+":"+nonce)).
  //   parts[3] = flags base36.
  var tok=issuedAt+'.pow2.'+target.toString(36)+'.'+flags.toString(36);

  var elapsed=Date.now()-start;

  // Spinner floor: PoW often finishes in ~30-100 ms on modern hardware, which
  // makes the page look like it skipped the check entirely.  Hold the spinner
  // for at least `pow_min_display_ms` (= operator-configured floor; default
  // 1.5s) so the visual "we ran a verification" beat lands.  0 disables the
  // floor for real-timing measurement on /unmask/test/.
  var minDisp = (window.UNMASK && window.UNMASK.pow_min_display_ms) || 0;
  if (minDisp > 0 && elapsed < minDisp) {
    await new Promise(function(r){ setTimeout(r, minDisp - elapsed); });
    elapsed = Date.now() - start;
  }

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

  // Capture the prior _bv (the accumulated per-IP signature list) BEFORE the
  // shadow-eviction below clears path=/, so this solve's token can be appended
  // to it rather than replacing it (= roaming-client accumulation).
  var _bvOld = (document.cookie.match(/(?:^|;\s*)_bv=([^;]*)/) || [])[1] || '';

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
  var _bvSecure = (location.protocol === 'https:') ? ';Secure' : '';
  // Prepend this solve's token to the prior list, keep at most 8
  // (= cookies.MaxBVEntries), skip blanks + an exact dup.  Server + native
  // plugin any-match the "~"-list, so each network the client solved on stays
  // passed and switching 5G<->wifi doesn't re-challenge.
  var _bvMax = (window.UNMASK && window.UNMASK.bv_max_entries) | 0;
  if (_bvMax < 1 || _bvMax > 16) { _bvMax = 8; } // clamp to the verifier ceiling; default
  var _bvList = tok, _bvN = 1;
  if (_bvOld) {
    var _bvP = _bvOld.split('~');
    for (var _k = 0; _k < _bvP.length && _bvN < _bvMax; _k++) {
      if (_bvP[_k] && _bvP[_k] !== tok) { _bvList += '~' + _bvP[_k]; _bvN++; }
    }
  }
  document.cookie='_bv='+_bvList+';path=/;expires='+exp2.toUTCString()+';SameSite=Lax'+_bvSecure;
  // After PoW completion + cookie set (read back immediately to verify the set succeeded)
  var _bv_set_ok = /(?:^|;\s*)_bv=/.test(document.cookie);
  _bcDebug('bv_pow_only', { pow_iterations: target, pow_elapsed_ms: elapsed, cookie_set_ok: _bv_set_ok, token_flags: flags });
  // Fetch the roaming-rebind credential (_bvj) for this solve.  The server
  // gates it on the _bv we just set, so this must run after the cookie write.
  // keepalive lets the Set-Cookie land even if the redirect below wins the
  // race; failures are non-fatal (the next network change re-challenges as
  // before, same as without the feature).
  if (_bv_set_ok) {
    try { fetch(API_BASE + '/bvj', { method:'POST', keepalive:true }).catch(function(){}); } catch (_) {}
  }

  // If the cookie can't be written, reloading won't help, so show an error and give up
  if (!_bv_set_ok) {
    showCookieError();
    return;
  }
  var wait=Math.max(800-elapsed,100);
  setTimeout(function(){passAndRedirect();},wait);
})();
