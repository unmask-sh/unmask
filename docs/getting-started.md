# Getting started

unmask を新しい nginx box に入れて bot challenge を有効化するまでの手順.
動作確認は internal-dev (RHEL 9, nginx 1.26.2 ソース build) で実施済み.

## 1. パッケージを入れる

GitHub Releases から arch / OS family に合った package を取得 (= rpm / deb / apk).

```sh
# RHEL / Rocky / AlmaLinux 9+
sudo dnf install ./unmask-0.1.0.x86_64.rpm

# Debian / Ubuntu
sudo apt install ./unmask_0.1.0_amd64.deb

# Alpine
sudo apk add --allow-untrusted ./unmask_0.1.0_x86_64.apk
```

入る物:

| path | 内容 |
|---|---|
| `/usr/sbin/unmask-admin` | Go static binary (admin server + CLI) |
| `/usr/lib/nginx/modules/ngx_http_ja4_module.so` | JA4 + BV 検証 dynamic module |
| `/usr/share/unmask/challenge/challenge.html` | challenge HTML (admin に embed もされている) |
| `/etc/unmask/config.yml` | admin app の config (random secret 自動生成済) |
| `/etc/unmask/nginx/*.conf` `*.map` | nginx include 用 snippets |
| `/etc/unmask/nginx/secret.conf` | `unmask_bv_secret` directive (config.yml と同期) |
| `/usr/lib/systemd/system/unmask-admin.service` | admin server 用 unit |
| `/usr/lib/systemd/system/unmask-aggregate.timer` | 毎時 aggregate |

## 2. nginx に module と include を足す

`/etc/nginx/nginx.conf` (= ディストロにより `/etc/nginx/conf.d/*` 等) を編集:

```nginx
# 一番上 (events / http の前). dynamic module の load.
load_module /usr/lib/nginx/modules/ngx_http_ja4_module.so;

http {
    # unmask の map / zone / upstream 定義 (= http main scope).
    include /etc/unmask/nginx/unmask.conf;

    server {
        listen 443 ssl http2;
        server_name example.com;
        ssl_certificate     /etc/letsencrypt/live/example.com/fullchain.pem;
        ssl_certificate_key /etc/letsencrypt/live/example.com/privkey.pem;

        # challenge endpoint と rate-limit 経路の定義.
        include /etc/unmask/nginx/unmask-server.conf;

        location / {
            # rate-limit (100r/min) → 越えたら CAPTCHA 直行
            limit_req zone=unmask_rate burst=50 nodelay;
            error_page 429 = @unmask_rate_challenge;

            # JA4 で偽装露呈した browser を challenge へ
            if ($final_challenge = 1) {
                rewrite ^ /unmask/challenge/ last;
            }

            # 元の handling
            proxy_pass http://backend;
        }
    }
}
```

`nginx -t` で syntax check, OK なら `systemctl reload nginx`.

## 3. 動作確認

### admin server

```sh
sudo systemctl status unmask-admin
curl http://127.0.0.1:8765/unmask/healthz
# -> ok
```

### JA4 module が動いているか

任意の location に `add_header X-JA4 $client_ja4 always;` を一時的に入れて、 普通の
ブラウザでアクセスし response header を見る:

```sh
curl -sk -I https://example.com/ | grep -i x-ja4
# X-JA4: t13d1517h2_8daaf6152771_b0da82dd1658
```

### challenge が出るか

`?_test_ja4=1` を付けると強制的に bot 判定で challenge HTML を踏める:

```sh
curl -sk "https://example.com/unmask/challenge/?_test_ja4=1" -o /dev/null -w "%{http_code}\n"
# -> 403  (= 中身は 403 だが challenge HTML 本文)
```

### Prometheus metrics

`/unmask/metrics` が Prometheus text format で expose される.

```yaml
# prometheus.yml の scrape config 例
scrape_configs:
  - job_name: unmask
    static_configs:
      - targets: ['127.0.0.1:8765']
    metrics_path: /unmask/metrics
    scrape_interval: 30s
```

主要 metric:

| name | type | 内容 |
|---|---|---|
| `unmask_event_total{phase,verdict}` | counter | challenge funnel の累積件数 |
| `unmask_event_unique_ip` | gauge | 直近 24h の unique IP 数 |
| `unmask_verify_score_*` | histogram | behavioral score 分布 |
| `unmask_db_query_seconds_*` | counter | DB クエリの sum/count |

DB から読む counter は 30 秒キャッシュされる (= scrape 間隔より短いので scrape ごとには更新).

### dashboard

```sh
# bind=127.0.0.1 default なので、 server から SSH tunnel 等で見る
ssh -L 8765:127.0.0.1:8765 example.com
# ブラウザで http://localhost:8765/unmask/admin/?days=7
```

外部から見たい場合は `/etc/unmask/config.yml` の `server.admin_token` に
ランダム文字列を設定し、 `?token=...` を付けて access する.

## 4. JA4 verdict map を運用する

`/etc/unmask/nginx/ja4-verdict.map` には初期で十数個の bot fingerprint しか
入っていない. **自分の site のログから新種を発見して追記する** のが運用の核.

dashboard の「JA4 verdict 分布」 で `ok` で総数の多い fingerprint が出てきたら、
ブラウザ実機で出る fingerprint と比べて偽装か判定する.

新種を見つけたら map に 1 行追記して `nginx -t && systemctl reload nginx`:

```nginx
"~^t13d521100_b262b3658495_"     "bot_noalpn_521";
```

## 5. Google IP range を最新化する

`/etc/unmask/nginx/google-ip.conf` は初期は placeholder (default 0 のみ). 公式 JSON
から実 IP range を埋める:

```sh
sudo /usr/sbin/unmask-admin build-google-ip -out /etc/unmask/nginx/google-ip.conf
sudo nginx -t && sudo systemctl reload nginx
```

これを cron で日次実行するのを推奨:

```cron
17 4 * * * /usr/sbin/unmask-admin build-google-ip -out /etc/unmask/nginx/google-ip.conf && /usr/sbin/nginx -t && /bin/systemctl reload nginx
```

### GeoIP (国別 chart) を有効化する

dashboard の「30 日推移」 card に国別 horizontal bar を出す任意機能。 MaxMind
GeoLite2-Country.mmdb (= 無料で取得可能) を指定:

```yaml
# /etc/unmask/config.yml
geoip:
  mmdb_path: /usr/share/GeoIP/GeoLite2-Country.mmdb
```

`unmask-admin restart` 後、 dashboard の右側に国別 bar が出る。 mmdb が無ければ
chart は出ない (= 起動には影響しない).

mmdb の取得は MaxMind の license に従う (= 配布はできない).

### crawler-user-agents.json を最新化する

monperrus/crawler-user-agents (= upstream) は週次で更新される. binary 再 build
なしで反映するには、 外部 path に書き出して環境変数で読ませる:

```sh
sudo /usr/sbin/unmask-admin update-crawler-list -out /etc/unmask/crawler-user-agents.json
```

`unmask-admin.service` の `[Service]` に以下を追加:

```ini
Environment=UNMASK_CRAWLER_UA_JSON=/etc/unmask/crawler-user-agents.json
```

`systemctl daemon-reload && systemctl restart unmask-admin` で反映. cron で日次:

```cron
33 4 * * * /usr/sbin/unmask-admin update-crawler-list -out /etc/unmask/crawler-user-agents.json && /bin/systemctl restart unmask-admin
```

## 6. secret rotation

`bv_secret` が漏れた場合 (= scraper が cookie 偽造に成功し始めた場合) は両方を
同時に rotate する:

```sh
# 1. 新しい secret を生成して config.yml に書く
NEW=$(openssl rand -hex 24)
sudo sed -i "s/^  bv_secret:.*/  bv_secret: \"$NEW\"/" /etc/unmask/config.yml

# 2. nginx 側の secret.conf も同期
sudo sed -i "s/^unmask_bv_secret.*/unmask_bv_secret      \"$NEW\";/" /etc/unmask/nginx/secret.conf

# 3. 同時 reload
sudo systemctl restart unmask-admin
sudo systemctl reload nginx
```

旧 cookie は全て invalidate される (= 全ユーザは次のリクエストで再 challenge).

## 7. トラブルシューティング

- **challenge HTML が 200 で返る** → `proxy_intercept_errors off;` が
  `/unmask/challenge/` の location に入っているか確認 (= unmask-server.conf
  に元から入っている)
- **ブラウザで JS 動作せず loop** → dashboard の `cookie_err` 列が増えていれば
  3rd-party cookie 制限. SameSite 周りを再確認
- **検索順位が下がった** → `/etc/unmask/nginx/search-bots.conf` に検索 bot UA を
  追加. dashboard で `verdict=ok` なのに `phase=serve` の Googlebot UA が居たら
  漏れている
- **`$client_ja4` が空** → TLS 1.2 / 1.3 のみ対応. plain HTTP では出ない
- **`$unmask_bv_valid` が常に 0** → `unmask_bv_secret` directive が
  `/etc/unmask/nginx/secret.conf` 経由で読まれているか, admin の
  `bv_secret` と同期しているか確認
