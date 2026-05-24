# 変更履歴

unmask の変更履歴.  Format は [Keep a Changelog](https://keepachangelog.com/),
versioning は [Semantic Versioning](https://semver.org/) に従う.

英語版は [CHANGELOG.md](CHANGELOG.md).  この日本語版は v0.1.0 release から
の差分を要約する翻訳で、 詳細な commit 日時 / 内部 ref は英語版を参照.

## [0.1.0] — 2026-05-24

### Added

- **Alpine の native module を first-class サポート**:
  `apk add unmask unmask-plugin-nginx unmask-web-nginx` で end-to-end 動作
  (= http=403 + challenge HTML を返却).  apk metadata に `gcompat`
  dependency を pin し、 musl link の Alpine nginx でも bundled glibc plugin
  が dlopen 可.  postinstall-web-nginx は host nginx.conf を parse して
  `http {}` 内 include dir (= Alpine `http.d/`, RHEL/Debian `conf.d/`) を
  自動選択. postinstall-plugin-nginx は gcompat 有無で分岐 (= 有なら通常配置,
  無なら skip + auth_request 案内).  Alpine でも JA4 fingerprint 利用可.

- **challenge ページの branding feature**:
  theme tab から logo / site name / footer / copy preset (= friendly / neutral
  / minimal) / unmask credit 表示 を edit. theme × preset の組み合わせは
  iframe で live preview.

- **18 言語の preset 翻訳**:
  challenge copy の preset (= ja / en + zh / zht / ko / es / pt / fr / de / ru
  / it / tr / pl / vi / th / id / ar / hi). visitor の locale に関係なく preset
  切替が効く.

- **CAPTCHA box の fade-in**:
  captcha 出現時に .25s の opacity + translateY transition. `prefers-reduced-motion`
  は transition off.

### Fixed

- **RHEL 系で SELinux が auth_request subrequest を block していた問題**:
  postinstall-web-nginx で SELinux Enforcing 検出時に `setsebool -P
  httpd_can_network_connect 1` を auto 適用.  `UNMASK_SKIP_SETSEBOOL=1` で opt-out.
  alma8 / alma9 / alma10 / centos7 で「challenge が silently 発火しない」
  症状を解消 (= 8 distro install matrix で http=403 + challenge page 全 PASS).

- **postinstall-web-nginx の Alpine 対応**:
  Alpine の nginx.conf は conf.d も include するが http {} 外なので、 conf.d/
  に upstream directive を置いていたのが「not allowed here」 で reject されていた.
  http.d/ への自動配置で fix.

- **install-test-official.sh の centos6 quoting 問題**:
  docker-bullseye legacy SSH proxy が cleanup_rpm body 内の `"` literal を
  mangle (= "bash: +en: command not found" 等)し、 install / fire-check が
  silent fail. centos6 を default keys から外し manual verify path へ.
  `centos6` 引数で opt-in 可.

### Changed

- **Apache forward-auth を explicit per-VirtualHost opt-in 化**:
  `snippets/apache-forward-auth.conf` の `LuaHookAccessChecker` を default で
  comment-out. nginx mode の per-server `include protect.inc;` と同じメンタル
  モデル. package install で「全 VirtualHost で silent 発火」 を回避.
  conf.d 内の global `/unmask/*` ProxyPass は残るので admin UI / challenge HTML
  / static asset は引き続き全 VirtualHost から到達可.

- **install page の nginx config 例**:
  共通 3 要素 (= `# unmask` + `include server.inc;` + `location @unmask_admin_down`)
  を範囲 3 種で固定. `include protect.inc;` の配置だけが scope (= whole site /
  particular location / catch-all) によって variable.

- **CI workflow**:
  Go 1.22 → 1.25.10 (= 5 件の stdlib CVE fix 含む). multi-site branch も push /
  PR trigger に追加.

- **README + LP の product tone sweep**:
  README status の「handled when time permits」 等の self-hedging を撤回.
  LP TOP use case 03 を「SaaS-non-委託」 に書換. 競合 product 名を全 LP / docs
  から除外. 「nginx」 を「httpd」 に一般化 (= multi-httpd 対応強調).

## [0.1.0-pre] — 2026-05-07

OSS 初期 commit (= pre-tag). 2026-05-07 ~ 2026-05-24 の polish work と共に
0.1.0 に rollup.

詳細項目 (= bot 検出 / challenge / 動作モード / 配布 / observability / CLI /
i18n / architecture の各カテゴリ) は CHANGELOG.md (英語) の [0.1.0-pre] section
を参照.

[0.1.0]: https://github.com/unmask-sh/unmask/releases/tag/v0.1.0
[0.1.0-pre]: https://github.com/unmask-sh/unmask/commits/main/?until=2026-05-07
