# CLAUDE.md

ガイダンス for Claude Code working in this repo.

## このプロジェクトは何

**unmask**: JA4 TLS-fingerprint ベースの bot challenge system. 配布物 (RPM)
として nginx に追加できる形を目指す.

## 出自と「親」 リポジトリ

設計と検証は `<internal-codebase>` の Mojolicious コードベースで行われた.
ロジック・テンプレート・SQL は `tool` の以下に存在する:

| 元ファイル (= <internal-codebase>/) | unmask での対応 |
|---|---|
| `lib/Tool/Controller/BotChallenge.pm`        | `admin/` の challenge serve endpoint |
| `lib/Tool/Controller/Api/BotChallenge.pm`    | `admin/` の verify endpoints |
| `lib/Tool/Controller/Admin/BotChallengeDebug.pm` | `admin/` のダッシュボード |
| `templates/tool/admin/bot_challenge_debug/`  | `admin/templates/` |
| `data/bot-challenge.html`                    | `challenge/challenge.html` ← コピー済 (rename 済) |
| `conf/middle/nginx/nginx-front_reverse_proxy-production.conf` の bot 関連 | `nginx/` の snippets |
| `lib/Tool/Command/AggregateAccessLog.pm` の verdict 判定部分 | `admin/internal/classify/` + `admin/cmd/unmask-admin/` の aggregate sub-command |
| `data/runtime/crawler-user-agents.json`      | `admin/assets/` で `embed` (同じ format) |

`tool` 側を読んで動作仕様を確認するのは OK. ただし **コードのコピペは
最小限にとどめ、 unmask 用に書き直す** こと. 理由:
- ライセンスが Apache 2.0 (= tool は社内 Mojolicious code)
- Perl/Mojolicious 依存を引きずらない (Python/FastAPI で再実装)
- nginx 純正配布のため OpenResty 依存を切る

## 言語選定

| 層 | 言語 | 理由 |
|---|---|---|
| nginx module | C | 1 種類しかないし dynamic module は C 必須 |
| challenge JS | プレーン JS | PoW / CAPTCHA UI は外部依存ゼロ. polyfill 不要 |
| admin app    | **Go** (stdlib + 3rd party 3 個) | 単一 static binary で RPM/deb/Alpine 全部行ける. Python venv 依存を引きずらない |
| CLI         | Go (admin と同 binary or 兄弟 binary) | `unmask-admin serve / migrate / aggregate` |

### Go 採用理由 (= 2026-05-04 Python から切替)

- 配布対象が **RHEL/Rocky 9+ に限らない** (Debian/Ubuntu/Alpine/Arch 等も) ため、 OS 標準 Python を借りる前提が崩れる
- Go なら CGO 無しで pure-Go static binary になり、 musl ベースの Alpine でも動く
- third-party は 3 個だけ:
  - `modernc.org/sqlite` (pure-Go SQLite. CGO 不要)
  - `github.com/go-sql-driver/mysql` (MariaDB driver, pure Go)
  - `gopkg.in/yaml.v3` (config 読み)
- `embed` で challenge HTML / template / crawler-user-agents.json を binary に同梱できる
- パッケージングは **nfpm** で同じ YAML から rpm/deb 両方ビルド

## 重要な設計原則

1. **nginx は stock のまま** — module 追加だけで動くこと. OpenResty / haproxy 等
   の外部依存はゼロ.
2. **admin app は単一 static binary** — Go (`unmask-admin`) を `/usr/sbin/`
   に置くだけ. ランタイム依存は libc のみ. Alpine 用に MUSL build も用意.
3. **SQLite default** — 小規模 site で外部 DB なしで動く. MariaDB / Postgres は
   設定で切替可能.
4. **検索 bot は絶対通す** — Googlebot / GPTBot 等で順位事故は再発させない.
   crawler-user-agents.json + Google IP range の二段救済必須.
5. **rate_limit と challenge は分離** — rate_limit ヒット時は CAPTCHA 直行
   (PoW スキップ). 真の人間にも CAPTCHA を出す覚悟で実装.

## 既存実装の品質情報 (= tool 側で経験済み)

- challenge ページは `Mojolicious::Plugin::Static` のような static 配信で
  routing をすり抜ける現象あり → 直接 controller で render しないと値が
  hit しない.
- JA4 verdict は `bot_*` で始まるものが「真の bot」、 `suspect_*` は
  「Chrome 風だが ALPN h1 (= 古い)」 等の補完判定.
- HMAC-SHA1 の _bv cookie は `day.signature.0.c` 形式. 3 日有効.
- PoW は djb2 hash で十分. SHA-256 だと CPU 重く、 hash 計算で離脱率↑.
- behavioral CAPTCHA の閾値は 0.5 (= score). mouseTrail / scrolls /
  keyboard / windowSize / clickAt の 5 軸.

## 開発ワークフロー

internal-dev の本番動作中システム (= <internal-codebase> 経由) を眺めて要件確認できる.
admin 画面は https://example.invalid/admin/tool/bot_challenge_debug/ (= 要 UID 認証).

## やってはいけないこと

- **<internal-codebase>/ を勝手に変更しない** — このプロジェクトとは別物
- **commit せずにコピペコードを大量に置かない** — clean-room を維持
- **FoxIO の ja4-nginx-module ソースを参照しない** — BSL 汚染回避.
  仕様 (https://github.com/FoxIO-LLC/ja4/blob/main/technical_details/JA4.md)
  からのみ実装する
