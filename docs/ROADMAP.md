# Roadmap

unmask の今後の作業項目. close したものは取り除く / 「Done」 セクションに移す.

## 着手予定 (= 優先順は文脈次第)

### challenge HTML JS のモジュール化
現状 `challenge/challenge.html` は 427 行の inline JS. PoW / behavioral
collector / cookie_err 検出 / debug ビーコンの各 phase が混ざっている. 別 file に
切り出して embed 結合するか、 JS bundler を入れずに `<script src=>` と
`add_header Content-Security-Policy` で nonce 配信する形に整理.

### unmask-admin events tail -f (= live debug stream)
challenge の動作 debug 用に, sqlite/mariadb の `unmask_event` を tail -f 風に
stream するサブコマンド. SSE で `/admin/api/events/stream` も併設.

### ダッシュボード認証強化
現状: `bind 127.0.0.1` 前提 / `admin_token` URL query 認証 のみ.
追加候補:
- IP allowlist (= `geo $allow_admin_ip` で外部公開時の前段制御)
- basic auth optional (= reverse proxy で `auth_basic` でも代用可)
- Webauthn / passkey (= 過剰だが将来的に)

### multi-server scale ガイド
SQLite (default) では複数 admin instance で競合する. MariaDB / Postgres を
shared backend にする deployment パターンと、 nginx 側の sticky session 等の
注意点を docs/scaling.md に書く.

### E2E test in CI
docker-compose で nginx + admin + curl を上げて、 以下 4 シナリオを実走:
1. 通常 GET / は 200
2. honeypot path + browser UA は 403 challenge
3. honeypot path + curl UA は 素通し
4. /unmask/api/verify → _bv 発行 → 同 cookie で / が challenge 抜ける

### auth_request の完全廃止
`/unmask/api/bv-check` endpoint は ja4 module を load できない環境向けに残置.
ja4 module + $unmask_bv_valid に完全移行できると判断したら remove.

### ja4-module で BV cookie の site binding を検証
multi-site (= 同一 domain 上に複数論理サイト) 構成での cross-site cookie replay
を完全に防御するため、 ja4-module 内で `$unmask_site` 変数を読んで HMAC 入力に
含めるか、 cookie の kind 部分が "captcha-<site>" の <site> と一致するか確認する
ロジックを追加する.

現状: admin が発行する cookie kind には site が入っているが, ja4-module 側は
cookie の kind 全体を HMAC 入力に流すだけで site=A の cookie が site=B でも
HMAC 検証通過する. 別 domain 構成なら browser cookie scoping で防げるので
priority 中.

### dashboard: GeoIP / ASN を IP popover に出す
IP popover は現状 rDNS + family のみ. **国は 30 日推移 card に horizontal bar で
表示済 (= geoip.mmdb_path 設定時)**. ASN / city も popover に出すなら GeoLite2-City
+ ASN DB を追加サポート要.

## アイデア (= まだ採用するか未確定)

### prometheus exporter の grafana dashboard JSON
`/dashboards/grafana-unmask.json`. challenge funnel / verdict 分布 / score
histogram heatmap / DB latency を 1 page にまとめる. 配布 RPM に同梱して
`/usr/share/unmask/grafana/` に置く.

### unmask-admin analyze
観測ログから新種 fingerprint をクラスター化. `unmask-admin analyze
--days 30 --threshold 100` で「verdict=ok だが頻度高 + UA は browser を
名乗る」 fingerprint を発見し、 ja4-verdict.map への追加候補として suggest する.

### crawler-user-agents.json の差分 review CLI
`unmask-admin review-crawler-list` で upstream の最新版と embed 版の diff を
表示し、 新規 / 削除 pattern を確認できる UI. 自動 update を有効にする前の
sanity check 用.

### IP リバース DNS のキャッシュ層
`/admin/api/myip` が毎回 net.LookupAddr する. dashboard で 100 IP 並べたら
100 回 DNS 引く. ttl 付き in-memory cache (= map + sync.Mutex で十分) を入れる.

### nginx VTS module 連携 (= optional)
$client_ja4 をラベルにして per-fingerprint の bytes/req を nginx-vts で
出せると、 ja4 module だけでは取れない traffic 量分析が可能. 公式 vts module
を load した時のみ有効化.

## Done (= 直近 session で close)

- ja4-module の compile / 動作確認 (nginx 1.26.2)
- BV cookie 検証を C module に内蔵 (auth_request RTT を 0 に)
- nginx 未定義変数 ($serve_bot_challenge / $bot_challenge_passed) 解消
- $serve_bot_challenge を `map $request_uri` 化 + honeypot.map 同梱
- GitHub Actions CI/release workflow
- Prometheus /metrics endpoint
- handler integration test (httptest + sqlite tempdir)
- docs/getting-started.md
- multi-site (= /unmask/admin/<site>/, /unmask/api/<site>/...)
- 30 日推移 chart (= 本家相当 stacked bar + hover popover)
- 国別 horizontal bar chart (= geoip.mmdb_path 任意設定)
- レート制限ヒット card (= phase=serve + payload.rl=1 を IP/path 別集計)
- 説明 popover 35+ 箇所 (= 本家 bootstrap popover 相当)
- dashboard 全 card を本家 HTML/CSS に揃える
