# Mojolicious (tool) → unmask 移植ガイド

このリポジトリは `<internal-codebase>` の bot-challenge 機能を独立した
配布物として切り出すための再実装です. 元の Perl/Mojolicious 実装を
読みつつ、 unmask 用に Python/C で書き直してください.

## 元コード参照マップ

### challenge ページ配信
- 元: `<internal-codebase>/lib/Tool/Controller/BotChallenge.pm`
- 役割: `data/bot-challenge.html` を読み、 ja4_verdict を見て
  `/*__JA4_HIT__*/0` placeholder を `0` か `1` に書き換え 403 で返す.
  `phase='serve'` を `bot_challenge_debug` テーブルに INSERT.
- unmask 移植先: `admin/main.py` (FastAPI) の challenge endpoint
- 注: nginx に proxy_pass される. 静的配信ではない.

### PoW / CAPTCHA verify
- 元: `<internal-codebase>/lib/Tool/Controller/Api/BotChallenge.pm`
- 役割:
  - `_score_click_signals()`: behavioral signals (mouseTrail, scrolls,
    keys, windowSize, clickAt) → 0.0-1.0 score. 閾値 0.5
  - `_issue_bv_cookie()`: HMAC-SHA1 で `day.signature.0.c` 形式 cookie 発行
  - `verify_json`: 新方式 (sig payload) と旧方式 (math answer) 両対応
  - `debug_log`: phase=load/pow/captcha/verify_ok/verify_ng/cookie_err/error
    ビーコンを INSERT
- unmask 移植先: `admin/main.py` の verify / debug endpoint

### 集計と判定
- 元: `<internal-codebase>/lib/Tool/Command/AggregateAccessLog.pm`
- 利用部分:
  - `_build_bot_categories()`: crawler-user-agents.json + 追加 pattern を
    search_ai / service / user_dev に分類
  - `_is_old_browser()`: Chrome 30 未満等の偽装検出
  - `classify_is_bot()`: UA + ja4_verdict から is_bot 値 (0-6) 算出
- unmask 移植先: `admin/classify.py` (= UA / verdict → is_bot 関数)

### Admin 画面
- 元: `<internal-codebase>/templates/tool/admin/bot_challenge_debug/index.html.ep`
- 構成 (= 上から順):
  1. challenge ファネル (verdict 別) — serve / rl / load / silent / stealth /
     pow / captcha / verify_ok / verify_ng / cookie_err / JS error / PoW率 /
     CAPTCHA率. 末尾に rate_limit / TOTAL 行
  2. レート制限ヒット (100r/min) 集計
  3. cookie 通過状況 (= bv=0/1, bp=0/1)
  4. flags 分布 (load phase)
  5. JA4 verdict 分布
  6. JA4 hit 判定
  7. CAPTCHA 失敗 IP ランキング
  8. PoW で cookie_set_ok=false
  9. bot-challenge 30日推移 chart (chart.js)
  10. JS エラー一覧
  11. challenge 発動フロー (= 図 + dl 解説)
- IP popover: hover で /api/myip/?ip=X を fetch して国 / ISP / 逆引き等表示
- unmask 移植先: `admin/templates/dashboard.html`

### nginx 設定
- 元: `<internal-codebase>/conf/middle/nginx/nginx-front_reverse_proxy-production.conf`
- 抽出すべきセクション:
  - `map $effective_ja4 $ja4_verdict { ... }` (~133-180 行付近)
  - `map "$bv_valid:$is_search_bot:$is_google_ip:$is_known_browser:$ja4_verdict:$serve_bot_challenge" $final_challenge { ... }` (~225 行付近)
  - `map $ja4_verdict $ja4_hit_flag { ... }`
  - `limit_req_zone $rate_limit_key zone=app_rate:10m rate=100r/m;`
  - `location = /bot-challenge.html { proxy_pass ... }`
  - `location @rate_challenge { rewrite ^ /bot-challenge.html?_rl=1 last; }`
- unmask 移植先: `nginx/unmask.conf` (= snippet 化, include 推奨)

### challenge HTML JS
- 元: `<internal-codebase>/data/bot-challenge.html` (= 既にコピー済 `challenge/`)
- 機能:
  - PoW: djb2 hash で 1-2 秒の計算
  - 完了後 `_bv` cookie set + reload で transparent pass
  - JA4 hit (= placeholder=1) なら PoW スキップ即 CAPTCHA
  - CAPTCHA: behavioral checkbox + math fallback
  - debug ビーコン: phase=load/pow/captcha/verify_ok/verify_ng/cookie_err/error

### Schema
- 元: `bot_challenge_debug` テーブル (`<internal-codebase>/lib/Tool/Schema/Result/BotChallengeDebug.pm`)
- 主要列: id, ip_address (varbinary 16), user_agent (varchar 255),
  ja4 (varchar 40), ja4_verdict (varchar 40), phase (varchar 16),
  flags (int), reload_count (int), cookie_bv (varchar 80),
  cookie_br (varchar 8), payload_json (longtext), date_created (datetime)
- unmask 移植先: `sql/schema-sqlite.sql` + `sql/schema-mariadb.sql`

## 移植順序の推奨

1. **JA4 module** (= C, 最も独立) — `ja4-module/`. PoC 済 (internal-dev で compile 通り).
   公式 nginx での動作確認のため、 docker 等で clean RHEL/Rocky build env
   を用意する.
2. **schema** — SQLite で event テーブル + index 設計
3. **challenge serve endpoint** (= FastAPI) — `bot-challenge.html` を返す + INSERT
4. **PoW verify** + **CAPTCHA verify** + **debug beacon** endpoint
5. **HMAC-SHA1 _bv cookie** 発行ロジック
6. **Admin dashboard** — funnel テーブルから始める. chart.js は最後
7. **集計 cron** — incremental SQL 化 (= elapsed 軽い)
8. **RPM SPEC** — 全部入り
