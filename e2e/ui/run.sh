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
# Defined mode with exactly one declared site: the shape where a badge gated on
# the site picker's length can never appear, which is what site-badge.test.js
# covers.
sites:
  mode: defined
  defined:
    - ui-e2e.example
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

# One hunt session for the collapse check: the rate-limit zone and the
# LB-misconfiguration warning are recorded on the SERVE (where they are
# detected), and two more phases follow -- so the row the collapse picks as the
# representative is the last one, which carries neither.  The abandon row
# carries the returned badge and a reload count for the same reason.
c.execute("""CREATE TABLE IF NOT EXISTS unmask_event (
    id INTEGER PRIMARY KEY AUTOINCREMENT, site TEXT NOT NULL DEFAULT '',
    host TEXT NOT NULL DEFAULT '', scheme TEXT NOT NULL DEFAULT '',
    port INTEGER NOT NULL DEFAULT 0, ip_address BLOB NOT NULL,
    user_agent TEXT, ja4 TEXT, ja4_verdict TEXT, ja4_verdict_id INTEGER,
    phase TEXT NOT NULL, flags INTEGER NOT NULL DEFAULT 0,
    reload_count INTEGER NOT NULL DEFAULT 0, cookie_bv TEXT, cookie_br TEXT,
    payload_json TEXT, date_created DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP)""")
# (the rate-limit zone and the LB warning are surfaced on phase=check only --
#  they are what the forward-auth check reports -- so the session starts there,
#  which is also the real shape: check -> serve -> load -> abandon.)
# Distinct timestamps: the collapse orders the chain by time, and rows sharing
# one second leave the representative pick ambiguous.
for phase, payload, reloads, ago in [
        ("check", '{"bt":"uiCollapse","action":"block","rl_zone":"perip",'
                  '"lb_warning":"X-Client-JA4 from an untrusted peer"}', 0, 40),
        ("serve", '{"bt":"uiCollapse","force_reason":"rate_limit"}', 0, 39),
        ("load", '{"bt":"uiCollapse"}', 0, 35),
        ("abandon", '{"bt":"uiCollapse","abandon_phase":"pow","returned":1}', 2, 20)]:
    c.execute("""INSERT INTO unmask_event
        (site,host,scheme,port,ip_address,user_agent,ja4,ja4_verdict,ja4_verdict_id,
         phase,flags,reload_count,cookie_bv,cookie_br,payload_json,date_created)
        VALUES ('','','',0,x'7f000001','UI-E2E','','',0,?,0,?,'','',?,
                datetime('now', '-' || ? || ' seconds'))""",
        (phase, reloads, payload, ago))
# A record for a Host nobody declared: in defined mode the site picker lists
# only declared sites, so a badge gated on the picker's length never appears --
# exactly the install where the operator most needs to know which Host a row
# came from.
c.execute("""INSERT INTO unmask_event
    (site,host,scheme,port,ip_address,user_agent,ja4,ja4_verdict,ja4_verdict_id,
     phase,flags,reload_count,cookie_bv,cookie_br,payload_json,date_created)
    VALUES ('203.0.113.77','','https',443,x'7f000002','UI-E2E-ghost','','',0,
            'serve',0,0,'','','{"bt":"uiGhost","orig_path":"/vpnsvc/connect.cgi"}',
            datetime('now','-15 seconds'))""")
# A session whose beacons arrived out of order.  pow_pass and captcha are
# emitted by the same JS tick, sent as separate requests microseconds apart and
# stamped on arrival, so which lands first is a race -- observed in production
# as captcha .574 / pow_pass .576.  Seeded with those timestamps inverted so the
# chain has to put them back in the order the visitor walked.
# Sub-second precision matters: the inversion is 2 MILLISECONDS, and the hunt
# rows carry ts_ms.  sqlite's datetime() truncates to the second, so the stamps
# are written with explicit millis the way the server records them.
import datetime as _dt
import json
_base = _dt.datetime.utcnow() - _dt.timedelta(seconds=30)
def _at(offset_ms):
    return (_base + _dt.timedelta(milliseconds=offset_ms)).strftime("%Y-%m-%d %H:%M:%S.") + \
           "%03d" % ((_base + _dt.timedelta(milliseconds=offset_ms)).microsecond // 1000)
# The pair that matters carries the SAME elapsed_ms: pow_pass and the CAPTCHA
# it hands off to leave in one JS tick, so the browser's own millisecond clock
# cannot separate them either.  Only seq can -- and the arrival times are
# inverted, exactly as observed in production.
#
# (phase, seq, elapsed_ms, arrival offset ms)
for phase, seq, el, off in [
        ("serve",               None, None, 0),
        ("load",                0,    500,  507),
        ("captcha",             2,    725,  725),   # arrived FIRST
        ("pow_pass",            1,    725,  727),   # sent first, arrived second
        ("bv_pow_then_captcha", 3,    900,  900)]:
    pl = {"bt": "uiRace"}
    if phase == "serve":
        pl["force_reason"] = "ua_target"
        pl["ch_mode"] = "pow_then_captcha"
    if seq is not None:
        pl["seq"] = seq
        pl["elapsed_ms"] = el
    # separators matter: the server's payload readers are hand-rolled and
    # match what JSON.stringify emits, which has no space after the colon.
    if phase == "pow_pass":
        pl["next"] = "captcha"
    c.execute("""INSERT INTO unmask_event
        (site,host,scheme,port,ip_address,user_agent,ja4,ja4_verdict,ja4_verdict_id,
         phase,flags,reload_count,cookie_bv,cookie_br,payload_json,date_created)
        VALUES ('','','https',443,x'7f000004','UI-E2E-race','t13d_race','',0,?,0,0,'','',?,?)""",
        (phase, json.dumps(pl, separators=(',', ':')), _at(off)))

# A second session where the phase order alone cannot be the answer: a CAPTCHA
# shown, failed, and shown again.  Every beacon here arrives in the order it
# was sent -- nothing is racing -- but the two captcha rows carry the same
# phase and therefore the same weight, so ordering by weight puts them
# side by side and buries the verify_ng that happened between them.  The page
# is the only party that can say which captcha came after the failure, and it
# says so with seq.
for phase, seq, el, off in [
        ("serve",           None, None, 0),
        ("load",            0,    500,  505),
        ("captcha",         1,    1000, 1005),
        ("verify_ng",       2,    3000, 3005),
        ("captcha",         3,    3200, 3205),   # a second attempt, after the failure
        ("bv_captcha_only", 4,    5000, 5005)]:
    pl = {"bt": "uiRetry"}
    if phase == "serve":
        pl["force_reason"] = "rate_limit"
        pl["ch_mode"] = "captcha_only"
    if seq is not None:
        pl["seq"] = seq
        pl["elapsed_ms"] = el
    c.execute("""INSERT INTO unmask_event
        (site,host,scheme,port,ip_address,user_agent,ja4,ja4_verdict,ja4_verdict_id,
         phase,flags,reload_count,cookie_bv,cookie_br,payload_json,date_created)
        VALUES ('','','https',443,x'7f000005','UI-E2E-retry','t13d_retry','',0,?,0,0,'','',?,?)""",
        (phase, json.dumps(pl, separators=(',', ':')), _at(off)))
c.commit()

# A row whose UA is far too long for the column: the cellpop popover only
# exists for values the cell cannot show, so without a clipped cell there is
# nothing to test.  Long enough that it is truncated at any plausible width.
c.execute("""INSERT INTO unmask_event
    (site,host,scheme,port,ip_address,user_agent,ja4,ja4_verdict,ja4_verdict_id,
     phase,flags,reload_count,cookie_bv,cookie_br,payload_json,date_created)
    VALUES ('','','https',443,x'7f000003',
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/151.0.0.0 Safari/537.36 UI-E2E-longua-padding-so-the-cell-must-truncate-no-matter-how-wide-the-viewport-is',
            't13d1516h2_8daaf6152771_02713d6af862','ok',0,
            'serve',0,0,'','','{"bt":"uiCellpop"}',
            datetime('now','-10 seconds'))""")
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
