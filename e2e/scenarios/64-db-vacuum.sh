#!/bin/bash
# 64: a database compaction -- and the challenge goes on working while it runs.
#
# The retention prune deletes rows; SQLite keeps their pages and the file never
# shrinks, with the table scattered through it.  `unmask db-vacuum` (or the
# retention tab's button) compacts it with the daemon running: the daemon
# holds its writes while the VACUUM holds SQLite's write lock, serves the
# challenge as before, and writes what it kept once the run has ended.  This
# scenario is the whole of that on the real stack:
#
#   1. give the stack a database with a large share of free pages: events
#      written, every other one deleted
#   2. `unmask db-vacuum -plan` says what a run gives back and needs
#   3. run it while visitors keep arriving: every one gets the challenge
#      (never a 5xx, never a wait behind the write lock), and a visitor who
#      solves the proof-of-work during the run passes
#   4. afterwards the file is smaller, the daemon answers, and its log says it
#      held its writes and wrote what it kept
#
# Needs the docker e2e stack (it stops and starts the unmask container and
# rewrites its database) and SQLite; skips cleanly otherwise.  E2E_VACUUM_ROWS
# sets the size of the table (default 600000).

set -u
DIR="$(cd "$(dirname "$0")/.." && pwd)"
. "$DIR/lib/env.sh"
. "$DIR/lib/assert.sh"
. "$DIR/lib/stack.sh"

COMPOSE="${COMPOSE:-$DIR/docker/docker-compose.yml}"
if ! command -v docker >/dev/null 2>&1 || \
   [ -z "$(docker compose -f "$COMPOSE" ps -q unmask 2>/dev/null)" ]; then
    log_skip "64-db-vacuum needs the docker e2e stack (unmask container) — skipped"
    exit 0
fi
dc() { docker compose -f "$COMPOSE" "$@"; }
CFG=/etc/unmask/config.yml
DBDIR=/var/lib/unmask
ROWS="${E2E_VACUUM_ROWS:-600000}"

if ! dc exec -T unmask grep -qE '^\s*driver:\s*sqlite' "$CFG" 2>/dev/null; then
    log_skip "64-db-vacuum compacts a SQLite database; this stack runs another driver — skipped"
    exit 0
fi
if ! python3 -c 'import sqlite3' 2>/dev/null; then
    log_skip "64-db-vacuum needs python3 with sqlite3 on the host — skipped"
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
dbsize() { dc exec -T unmask sh -c "stat -c %s $DBDIR/unmask.sqlite" 2>/dev/null | tr -d '\r'; }
# The stack as it was, whatever happened above: its own database back, the
# daemon answering.
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
    rm -rf "$WORK"
    if [ "$rc" -eq 0 ] && [ "${_E2E_FAILS:-0}" -gt 0 ]; then
        printf '%b\n' "  ${RED}FAIL${RESET}  ${_E2E_FAILS} assertion(s) failed earlier in this scenario" >&2
        exit 1
    fi
    exit "$rc"
}
trap cleanup EXIT

# 1. a database with a large share of free pages.  Its files are rewritten
# below, which the daemon must not have open.
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
# The last five days, so that the retention prune leaves them alone; then
# every other one deleted, as the prune leaves a table: its free pages
# scattered through the file.
c.execute("""WITH RECURSIVE n(i) AS (SELECT 1 UNION ALL SELECT i+1 FROM n WHERE i < ?)
INSERT INTO unmask_event (site, host, scheme, port, ip_address, user_agent, ja4, ja4_verdict, phase, payload_json, date_created)
SELECT 'e2e-vacuum.example', 'seed', 'https', 443, x'c6336407',
       'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/140.0.0.0 Safari/537.36',
       't13d' || printf('%04d', i % 977) || 'h2_e2e000000000_e2e000000000', 'ok',
       CASE i % 10 WHEN 0 THEN 'load' WHEN 1 THEN 'bv_pow_only' ELSE 'serve' END,
       '{"bt":"e2evacuum' || i || '","orig_path":"/articles/' || i || '/","ch_mode":"pow_only","pad":"xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"}',
       strftime('%Y-%m-%d %H:%M:%f', 'now', '-' || (i % 400000) || ' seconds') FROM n""", (rows,))
c.execute("DELETE FROM unmask_event WHERE site = 'e2e-vacuum.example' AND id % 2 = 0")
c.execute("DELETE FROM unmask_maint_state WHERE name IN ('vacuum', 'vacuum_rate')")
c.execute("PRAGMA wal_checkpoint(TRUNCATE)")
free = c.execute("PRAGMA freelist_count").fetchone()[0] * c.execute("PRAGMA page_size").fetchone()[0]
assert free > 64 << 20, "too little free space to be worth a compaction: %d" % free
c.close()
PY
log "prepared $ROWS events, half deleted, in $(( $(date +%s) - t0 ))s ($(du -h "$WORK/unmask.sqlite" | cut -f1))"
DB_REPLACED=1
dc run --rm --no-deps -T unmask sh -c "cd $DBDIR && rm -f unmask.sqlite-wal unmask.sqlite-shm && cat > unmask.sqlite && sync" < "$WORK/unmask.sqlite" \
    || { log_fail "could not copy the database back into the container"; exit 1; }
rm -f "$WORK"/unmask.sqlite* "$WORK/db.tar" # orig.tar stays, for the cleanup
stack_start "$COMPOSE" || { log_fail "docker could not start the unmask container"; exit 1; }
wait_healthz 60 || { log_fail "the daemon did not come up within 60s of the start"; exit 1; }

# 2. the plan
plan=$(dc exec -T unmask /usr/local/bin/unmask db-vacuum -plan -config "$CFG" 2>&1)
assert_in "gives back about" "$plan" "\`db-vacuum -plan\` says what a run gives back" || printf '%s\n' "$plan"
assert_in "needs about" "$plan" "\`db-vacuum -plan\` says the disk a run needs"
assert_in "expected to take" "$plan" "\`db-vacuum -plan\` says how long"
assert_in "holds its writes" "$plan" "\`db-vacuum -plan\` says the daemon holds its writes meanwhile"
before=$(dbsize)

# 3. run it, with visitors arriving throughout
OUT="$WORK/codes"; : > "$OUT"
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
dc exec -T unmask /usr/local/bin/unmask db-vacuum -config "$CFG" > "$WORK/vacuum.out" 2>&1 &
VAC=$!
sleep 1
# A visitor who meets the challenge during the run, solves it and passes.
CLIENT_IP=198.51.100.164
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
during="no"; kill -0 "$VAC" 2>/dev/null && during="yes"
wait "$VAC"; vac_rc=$?
took=$(python3 -c "import time,sys; print('%.1f' % (time.time() - float(sys.argv[1])))" "$t0")
sleep 1
touch "$WORK/stop"; wait "$HAMMER" 2>/dev/null; HAMMER=""

assert_eq 0 "$vac_rc" "\`unmask db-vacuum\` ended well" || cat "$WORK/vacuum.out"
vac_out=$(cat "$WORK/vacuum.out")
assert_in "has stopped writing" "$vac_out" "the run waited for the daemon to hold its writes"
assert_in "done: the file went from" "$vac_out" "\`unmask db-vacuum\` says how the file changed"
log_note "64 db vacuum: $ROWS events (half deleted) compacted in ${took}s with the daemon serving"
assert_eq 200 "$pow_code" "a visitor who solves the proof-of-work passes (200; the run was still going: $during)"

total=$(wc -l < "$OUT")
n5xx=$(grep -cE '^5[0-9][0-9] ' "$OUT")
n403=$(grep -c '^403 ' "$OUT")
n200=$(grep -c '^200 ' "$OUT")
slow=$(awk '$2 > 2.0' "$OUT" | wc -l)
lat=$(awk '{ print $2 }' "$OUT" | sort -n | awk '{ a[NR] = $1 } END { if (NR) printf "median %.0f ms, slowest %.0f ms", a[int((NR + 1) / 2)] * 1000, a[NR] * 1000 }')
log "during the compaction: $total requests -> 403=$n403 200=$n200 5xx=$n5xx, slower than 2s: $slow ($lat)"
[ "$total" -ge 10 ] && log_pass "visitors kept arriving during the compaction ($total requests)" \
    || log_fail "the hammer made only $total requests; the compaction was not under load"
assert_eq 0 "$n5xx" "no visitor got a 5xx while the database was compacted"
assert_eq "$total" "$((n403 + n200))" "every visitor got the challenge (403) or the page (200)"
assert_eq 0 "$slow" "no visitor waited more than 2s: nothing on their path stood behind the write lock"

# 4. afterwards
after=$(dbsize)
if [ -n "$before" ] && [ -n "$after" ] && [ "$after" -lt "$before" ]; then
    log_pass "the file is smaller: $before -> $after bytes"
else
    log_fail "the file did not shrink: $before -> $after bytes"
fi
assert_eq 200 "$(healthz)" "after: the daemon answers"
c1=$(http_get / -A "$UA_CURL" -H "X-Forwarded-For: 203.0.113.9")
assert_eq 403 "$c1" "after: curl UA is challenged on / (403)"
logs=""
for _ in $(seq 1 20); do
    logs=$(dc logs --no-color --since 5m unmask 2>/dev/null | grep -E "db vacuum|events flusher" | tail -20)
    printf '%s' "$logs" | grep -q "kept meanwhile" && break
    sleep 1
done
assert_in "writes are held until it ends" "$logs" "the daemon noticed the run and held its writes"
assert_in "kept meanwhile" "$logs" "the daemon wrote the events it had kept once the run ended"
