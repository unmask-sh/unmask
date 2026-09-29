#!/bin/bash
# 63: a schema update left for the operator -- and the challenge goes on
# working while it is applied.
#
# The daemon applies migrations before it listens.  Building an index over a
# large events table takes minutes, so it leaves such a build unapplied, says
# so, and the operator applies it when it suits them (the notice in the admin
# UI, or `unmask migrate`).  This scenario is the whole of that on the real
# stack:
#
#   1. turn the database into one an upgrade across the index migration finds:
#      the index gone, its migrations unrecorded, a table large enough that the
#      build is one to leave
#   2. start the daemon: it comes up at once, WITHOUT the index, and says what
#      it left; `unmask migrate -status` lists it as waiting
#   3. apply it with `unmask migrate` while visitors keep arriving: every one
#      of them gets the challenge (never a 5xx), and a visitor who solves the
#      proof-of-work during the build passes
#   4. afterwards nothing is pending, and the daemon has written the events it
#      kept while the write lock was held
#
# What is on trial in step 3 is SQLite's single writer: the build holds the
# write lock for its whole length, and anything on the visitor's path that
# wrote to the database would stand still behind it.
#
# Needs the docker e2e stack (it stops and starts the unmask container and
# rewrites its database) and SQLite; skips cleanly otherwise.  E2E_SCHEMA_ROWS
# sets the size of the table (default 1000000).

set -u
DIR="$(cd "$(dirname "$0")/.." && pwd)"
. "$DIR/lib/env.sh"
. "$DIR/lib/assert.sh"
. "$DIR/lib/stack.sh"

COMPOSE="${COMPOSE:-$DIR/docker/docker-compose.yml}"
if ! command -v docker >/dev/null 2>&1 || \
   [ -z "$(docker compose -f "$COMPOSE" ps -q unmask 2>/dev/null)" ]; then
    log_skip "63-schema-update needs the docker e2e stack (unmask container) — skipped"
    exit 0
fi
dc() { docker compose -f "$COMPOSE" "$@"; }
CFG=/etc/unmask/config.yml
DBDIR=/var/lib/unmask
ROWS="${E2E_SCHEMA_ROWS:-1000000}"

if ! dc exec -T unmask grep -qE '^\s*driver:\s*sqlite' "$CFG" 2>/dev/null; then
    log_skip "63-schema-update rewrites a SQLite database; this stack runs another driver — skipped"
    exit 0
fi
if ! python3 -c 'import sqlite3' 2>/dev/null; then
    log_skip "63-schema-update needs python3 with sqlite3 on the host — skipped"
    exit 0
fi

WORK=$(mktemp -d)
HAMMER=""
healthz() { curl -sk -o /dev/null -w '%{http_code}' --max-time 3 "${BASE_URL}/unmask/healthz"; }
wait_healthz() {
    local tries="$1" i
    for i in $(seq 1 "$tries"); do
        [ "$(healthz)" = 200 ] && return 0
        sleep 1
    done
    return 1
}
status() { dc exec -T unmask /usr/local/bin/unmask migrate -status -config "$CFG" 2>&1; }
# The stack as it was, whatever happened above: its own database back (the
# million rows made here would otherwise stay for every scenario after this
# one, and grow with every re-run on a stack left up), the daemon answering.
DB_REPLACED=""
cleanup() {
    local rc=$?
    [ -n "$HAMMER" ] && { touch "$WORK/stop"; kill "$HAMMER" 2>/dev/null; }
    if [ -n "$DB_REPLACED" ] && [ -f "$WORK/orig.tar" ]; then
        if stack_stop "$COMPOSE" && [ -z "$(dc ps -q unmask 2>/dev/null)" ]; then
            dc run --rm --no-deps -T unmask sh -c "cd $DBDIR && rm -f unmask.sqlite unmask.sqlite-wal unmask.sqlite-shm && tar -xf - && sync" \
                < "$WORK/orig.tar" >/dev/null 2>&1 || { log_fail "cleanup: could not put the stack's database back"; rc=1; }
        else
            log_fail "cleanup: could not stop the unmask container to put its database back"; rc=1
        fi
        stack_start "$COMPOSE" || true
        wait_healthz 60 || { log_fail "cleanup: the daemon did not come back healthy"; rc=1; }
    elif [ "$(healthz)" != 200 ]; then
        stack_start "$COMPOSE" || true
        wait_healthz 60 || { log_fail "cleanup: the daemon did not come back healthy"; rc=1; }
    fi
    if ! status | grep -q 'up to date'; then
        dc exec -T unmask /usr/local/bin/unmask migrate -config "$CFG" >/dev/null 2>&1 || true
    fi
    rm -rf "$WORK"
    if [ "$rc" -eq 0 ] && [ "${_E2E_FAILS:-0}" -gt 0 ]; then
        printf '%b\n' "  ${RED}FAIL${RESET}  ${_E2E_FAILS} assertion(s) failed earlier in this scenario" >&2
        exit 1
    fi
    exit "$rc"
}
trap cleanup EXIT

# 0. where we start
assert_in "up to date" "$(status)" "before: nothing is pending" || exit 1

# 1. the database of an install that has just been upgraded across the index
# Its files are rewritten below, which the daemon must not have open.
stack_stop "$COMPOSE" || { log_fail "could not stop the unmask container; its database is left alone"; exit 1; }
if [ -n "$(dc ps -q unmask 2>/dev/null)" ]; then
    log_fail "the unmask container is still running; its database is left alone"
    exit 1
fi
dc run --rm --no-deps -T unmask sh -c "cd $DBDIR && tar -cf - unmask.sqlite*" > "$WORK/db.tar" 2>/dev/null
cp "$WORK/db.tar" "$WORK/orig.tar"
tar -C "$WORK" -xf "$WORK/db.tar" || { log_fail "could not copy the database out of the container"; exit 1; }
t0=$(date +%s)
python3 - "$WORK/unmask.sqlite" "$ROWS" <<'PY' || { log_fail "could not prepare the database"; exit 1; }
import sqlite3, sys
db, rows = sys.argv[1], int(sys.argv[2])
c = sqlite3.connect(db, isolation_level=None)
# The table is filled with its indexes off and they are put back afterwards:
# maintaining eight indexes row by row is most of what an insert costs.
idx = c.execute("SELECT name, sql FROM sqlite_master WHERE type='index' AND tbl_name='unmask_event' AND sql IS NOT NULL").fetchall()
for name, _ in idx:
    c.execute('DROP INDEX "%s"' % name)
# The last five days, so that the retention prune leaves them alone.
c.execute("""WITH RECURSIVE n(i) AS (SELECT 1 UNION ALL SELECT i+1 FROM n WHERE i < ?)
INSERT INTO unmask_event (site, host, scheme, port, ip_address, user_agent, ja4, ja4_verdict, phase, payload_json, date_created)
SELECT 'e2e-schema.example', 'seed', 'https', 443, x'c6336407',
       'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/140.0.0.0 Safari/537.36',
       't13d' || printf('%04d', i % 977) || 'h2_e2e000000000_e2e000000000', 'ok',
       CASE i % 10 WHEN 0 THEN 'load' WHEN 1 THEN 'bv_pow_only' ELSE 'serve' END,
       '{"bt":"e2eschema' || i || '","orig_path":"/articles/' || i || '/","ch_mode":"pow_only","pad":"xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"}',
       strftime('%Y-%m-%d %H:%M:%f', 'now', '-' || (i % 400000) || ' seconds') FROM n""", (rows,))
for name, sql in idx:
    if name != 'idx_unmask_event_ja4_phase':
        c.execute(sql)
c.execute("DELETE FROM schema_migrations WHERE version IN (32, 33)")
c.execute("DELETE FROM unmask_maint_state WHERE name IN ('schema_update', 'schema_rate')")
c.execute("PRAGMA wal_checkpoint(TRUNCATE)")
left = c.execute("SELECT COUNT(*) FROM sqlite_master WHERE name='idx_unmask_event_ja4_phase'").fetchone()[0]
assert left == 0, "the index is still there"
c.close()
PY
log "prepared a table of $ROWS events in $(( $(date +%s) - t0 ))s ($(du -h "$WORK/unmask.sqlite" | cut -f1))"
# sync: the copy leaves its size in dirty pages, and the start that follows
# (render-nginx writes its files with fsync) would wait behind their writeback
# -- a wait that belongs to this preparation, not to the start being measured.
DB_REPLACED=1
dc run --rm --no-deps -T unmask sh -c "cd $DBDIR && rm -f unmask.sqlite-wal unmask.sqlite-shm && cat > unmask.sqlite && sync" < "$WORK/unmask.sqlite" \
    || { log_fail "could not copy the database back into the container"; exit 1; }
rm -f "$WORK"/unmask.sqlite* "$WORK/db.tar" # orig.tar stays, for the cleanup

# 2. the daemon starts without building it
t0=$(date +%s)
stack_start "$COMPOSE" || { log_fail "docker could not start the unmask container"; exit 1; }
wait_healthz 60 || { log_fail "the daemon did not come up within 60s of the start"; exit 1; }
up=$(( $(date +%s) - t0 ))
log_pass "the daemon answers ${up}s after the start, the index build not among what it did first"
st=$(status)
assert_in "0032_event_ja4_index" "$st" "after the start: the index migration is listed as pending" || { printf '%s\n' "$st"; exit 1; }
assert_in "waits for you" "$st" "after the start: it waits for the operator (the daemon does not apply it)"
logs=$(dc logs --no-color --since 3m unmask 2>/dev/null | grep -E "left for the operator|applied automatically|schema" | tail -20)
assert_in "left for the operator" "$logs" "the daemon's log says what it left unapplied"
assert_in "NOT applied automatically" "$logs" "the start printed the notice an upgrade shows"
c0=$(http_get / -A "$UA_CURL" -H "X-Forwarded-For: 203.0.113.9")
assert_eq 403 "$c0" "with the update waiting: curl UA is challenged on / (403)"

# What a visitor waits when nothing is going on, to read the figures of step 3
# against.
BASE="$WORK/base"; : > "$BASE"
for i in $(seq 1 30); do
    curl -sk -o /dev/null -w '%{http_code} %{time_total}\n' --max-time 8 \
        -A "$UA_CURL" -H "X-Forwarded-For: 203.0.113.$((10 + i % 200))" "${BASE_URL}/" >> "$BASE" 2>&1
    sleep 0.05
done
log "before the update: $(awk '{ print $2 }' "$BASE" | sort -n | awk '{ a[NR] = $1 } END { if (NR) printf "median %.0f ms, slowest %.0f ms", a[int((NR + 1) / 2)] * 1000, a[NR] * 1000 }') over $(wc -l < "$BASE") requests"

# 3. apply it, with visitors arriving throughout
OUT="$WORK/codes"; : > "$OUT"
# Stopped by a flag, not a signal: a killed loop leaves its last curl running,
# and that curl's line lands in the file while it is being counted.
rm -f "$WORK/stop"
(
    i=0
    while [ ! -e "$WORK/stop" ]; do
        i=$((i + 1))
        curl -sk -o /dev/null -w '%{http_code} %{time_total}\n' --max-time 8 \
            -A "$UA_CURL" -H "X-Forwarded-For: 203.0.113.$((10 + i % 200))" "${BASE_URL}/" >> "$OUT" 2>&1
        sleep 0.05
    done
) &
HAMMER=$!
t0=$(date +%s.%N)
dc exec -T unmask /usr/local/bin/unmask migrate -config "$CFG" > "$WORK/migrate.out" 2>&1 &
MIG=$!
sleep 1
# A visitor who meets the challenge during the build, solves it and passes.
CLIENT_IP=198.51.100.163
ch=$(curl -sk --max-time 8 -A "$UA_BROWSER" -H "X-Forwarded-For: $CLIENT_IP" "${BASE_URL}/unmask/challenge/")
seed=$(printf '%s' "$ch" | grep -oE '__POW_SEED__\*/"[0-9a-f]+' | grep -oE '[0-9a-f]{40}' | head -1)
issued=$(printf '%s' "$ch" | grep -oE '__ISSUED_AT__\*/[0-9]+' | grep -oE '[0-9]{6,}' | head -1)
diff=$(printf '%s' "$ch" | grep -oE '__POW_DIFFICULTY__\*/[0-9]+' | grep -oE '[0-9]+$' | head -1)
pow_code=000
if [ -n "$seed" ] && [ -n "$issued" ]; then
    bv=$(python3 "$DIR/lib/powsolve.py" "$seed" "$issued" "${diff:-18}")
    [ -n "$bv" ] && pow_code=$(curl -sk --max-time 8 -A "$UA_BROWSER" -H "X-Forwarded-For: $CLIENT_IP" -H "Cookie: _bv=$bv" \
        -o /dev/null -w '%{http_code}' "${BASE_URL}/wp-login.php")
fi
during="no"; kill -0 "$MIG" 2>/dev/null && during="yes"
wait "$MIG"; mig_rc=$?
took=$(python3 -c "import time,sys; print('%.1f' % (time.time() - float(sys.argv[1])))" "$t0")
sleep 1
touch "$WORK/stop"; wait "$HAMMER" 2>/dev/null; HAMMER=""

assert_eq 0 "$mig_rc" "\`unmask migrate\` ended well" || cat "$WORK/migrate.out"
mig_out=$(cat "$WORK/migrate.out")
assert_in "schema applied" "$mig_out" "\`unmask migrate\` says the schema is applied"
log_note "63 schema update: index over $ROWS events built in ${took}s with the daemon serving"
assert_eq 200 "$pow_code" "a visitor who solves the proof-of-work passes (200; the build was still running: $during)"

total=$(wc -l < "$OUT")
n5xx=$(grep -cE '^5[0-9][0-9] ' "$OUT")
n403=$(grep -c '^403 ' "$OUT")
n200=$(grep -c '^200 ' "$OUT")
slow=$(awk '$2 > 2.0' "$OUT" | wc -l)
# How long a visitor waited, in the middle and at worst: the pass mark below
# is generous, and this is what shows a slowdown that stays under it.
lat=$(awk '{ print $2 }' "$OUT" | sort -n | awk '{ a[NR] = $1 } END { if (NR) printf "median %.0f ms, slowest %.0f ms", a[int((NR + 1) / 2)] * 1000, a[NR] * 1000 }')
log "during the update: $total requests -> 403=$n403 200=$n200 5xx=$n5xx, slower than 2s: $slow ($lat)"
[ "$total" -ge 10 ] && log_pass "visitors kept arriving during the update ($total requests)" \
    || log_fail "the hammer made only $total requests; the update was not under load"
assert_eq 0 "$n5xx" "no visitor got a 5xx while the index was built"
assert_eq "$total" "$((n403 + n200))" "every visitor got the challenge (403) or the page (200)"
assert_eq 0 "$slow" "no visitor waited more than 2s: nothing on their path stood behind the write lock"

# 4. afterwards
assert_in "up to date" "$(status)" "after: nothing is pending"
assert_eq 200 "$(healthz)" "after: the daemon answers"
c1=$(http_get / -A "$UA_CURL" -H "X-Forwarded-For: 203.0.113.9")
assert_eq 403 "$c1" "after: curl UA is challenged on / (403)"
# The daemon watches for a run it did not start (every two seconds while an
# update waits).  A build shorter than that may be over before it looks, and
# then there is nothing in its log to find.
if python3 -c "import sys; sys.exit(0 if float(sys.argv[1]) >= 6 else 1)" "$took"; then
    logs=""
    for _ in $(seq 1 20); do
        logs=$(dc logs --no-color --since 5m unmask 2>/dev/null | grep -E "events flusher|schema update" | tail -20)
        printf '%s' "$logs" | grep -q "kept meanwhile" && break
        sleep 1
    done
    assert_in "a schema update holds the write lock" "$logs" "the daemon noticed the run and kept its events back"
    assert_in "kept meanwhile" "$logs" "the daemon wrote the events it had kept once the lock was free"
else
    log_skip "the build took ${took}s: too short for the daemon to have had to keep events back"
fi
