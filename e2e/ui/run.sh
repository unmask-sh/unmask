#!/bin/bash
# Browser-level UI checks against a throwaway admin instance.
#
# Boots the admin binary with a fresh SQLite in a temp dir, seeds the
# access-log counters the composition card reads, creates a login, then runs
# every *.test.js in this directory under node + puppeteer-core against it.
# Nothing here touches an existing install: own config, own DB, own port.
#
# usage:
#   ./run.sh                       # builds the binary from ../../admin
#   UNMASK_BIN=/path/to/unmask ./run.sh
#   CHROME_BIN=/usr/bin/google-chrome ./run.sh
#
# Requirements: go (unless UNMASK_BIN is set), node + node_modules (npm ci),
# python3 (seeding), and a Chromium/Chrome binary.

set -eu
DIR="$(cd "$(dirname "$0")" && pwd)"
REPO="$(cd "$DIR/../.." && pwd)"

# ---- toolchain discovery -------------------------------------------------
CHROME_BIN="${CHROME_BIN:-}"
if [ -z "$CHROME_BIN" ]; then
    for c in chromium-browser chromium google-chrome google-chrome-stable; do
        if command -v "$c" >/dev/null 2>&1; then CHROME_BIN="$(command -v "$c")"; break; fi
    done
fi
[ -n "$CHROME_BIN" ] || { echo "FAIL: no Chromium/Chrome found (set CHROME_BIN)"; exit 99; }
[ -d "$DIR/node_modules/puppeteer-core" ] || { echo "FAIL: run 'npm ci' in e2e/ui first"; exit 99; }

WORK="$(mktemp -d)"
SERVE_PID=""
cleanup() {
    [ -n "$SERVE_PID" ] && kill "$SERVE_PID" 2>/dev/null || true
    rm -rf "$WORK"
}
trap cleanup EXIT

# ---- binary --------------------------------------------------------------
BIN="${UNMASK_BIN:-}"
if [ -z "$BIN" ]; then
    echo "== building admin binary"
    (cd "$REPO/admin" && CGO_ENABLED=0 go build -o "$WORK/unmask" ./cmd/unmask)
    BIN="$WORK/unmask"
fi

# ---- throwaway instance --------------------------------------------------
PORT="$(python3 -c 'import socket; s=socket.socket(); s.bind(("127.0.0.1",0)); print(s.getsockname()[1]); s.close()')"
PASS="ui-e2e-$(head -c 9 /dev/urandom | base64 | tr -dc 'a-zA-Z0-9' | head -c 12)Aa1"
mkdir -p "$WORK/data" "$WORK/nginx-out" "$WORK/out"
cat > "$WORK/config.yml" <<EOF
db:
  driver: sqlite
  sqlite_path: $WORK/data/unmask.sqlite
secret:
  bv_secret: "ui-e2e-throwaway-secret-1"
  captcha_secret_base: "ui-e2e-throwaway-secret-2"
server:
  bind: 127.0.0.1
  port: $PORT
  base_path: /unmask
nginx_log:
  socket_path: $WORK/log.sock
nginx:
  output_dir: $WORK/nginx-out
EOF

"$BIN" migrate -config "$WORK/config.yml" >/dev/null
"$BIN" user create ui-e2e -role superadmin -password "$PASS" -config "$WORK/config.yml" >/dev/null

# Counters behind the composition card: every segment non-zero so all five
# chips render, plus rebind/passthrough so the breakdown popover has its
# conditional rows.
python3 - "$WORK/data/unmask.sqlite" <<'PY'
import sqlite3, sys, time
c = sqlite3.connect(sys.argv[1])
c.execute("""CREATE TABLE IF NOT EXISTS unmask_cookie_minute (
    bucket_min INTEGER NOT NULL, site TEXT NOT NULL, kind TEXT NOT NULL, cnt INTEGER NOT NULL)""")
m = int(time.time()) // 60 - 5
for kind, n in [("total", 100000), ("bypass_pass", 20000), ("crawler_pass", 8000),
                ("challenge_served", 25000), ("pow", 30000), ("captcha", 2000),
                ("rebind", 1500), ("passthrough", 300)]:
    c.execute("INSERT INTO unmask_cookie_minute (bucket_min, site, kind, cnt) VALUES (?,?,?,?)",
              (m, "", kind, n))
c.commit()
PY

"$BIN" serve -config "$WORK/config.yml" > "$WORK/serve.log" 2>&1 &
SERVE_PID=$!
for i in $(seq 1 30); do
    if curl -s -o /dev/null -w '%{http_code}' "http://127.0.0.1:$PORT/unmask/healthz" | grep -q '^200$'; then
        break
    fi
    kill -0 "$SERVE_PID" 2>/dev/null || { echo "FAIL: admin died at startup"; tail -20 "$WORK/serve.log"; exit 99; }
    sleep 1
done

# ---- run the tests -------------------------------------------------------
export UI_E2E_BASE="http://127.0.0.1:$PORT/unmask"
export UI_E2E_USER="ui-e2e"
export UI_E2E_PASS="$PASS"
export UI_E2E_OUT="$WORK/out"
export CHROME_BIN

fail=0
for t in "$DIR"/*.test.js; do
    echo "== $(basename "$t")"
    if ! node "$t"; then
        fail=$((fail + 1))
        # Keep the artifacts of a failing run out of the trap's rm.
        KEEP="$(mktemp -d /tmp/unmask-ui-e2e.XXXXXX)"
        cp -r "$WORK/out" "$WORK/serve.log" "$KEEP/" 2>/dev/null || true
        echo "   artifacts: $KEEP"
    fi
done

[ "$fail" -eq 0 ] && echo "ui e2e: all green"
exit "$fail"
