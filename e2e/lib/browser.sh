# Shared helper for the browser-driven scenarios (27/28/31).  Runs a Playwright
# test script in the official image via `docker run`, so no host install is
# needed.  Skips gracefully (returns 0) if docker / the image is unavailable.
#
# Usage: run_playwright_test <script_basename_in_lib> <assert_desc>
# Requires DIR, BASE_URL (env.sh) and assert_eq/log (assert.sh) to be in scope.
run_playwright_test() {
    local script="$1" desc="$2"
    if ! command -v docker >/dev/null 2>&1; then
        log "SKIP: docker not available (need the Playwright image to drive a real browser)"
        return 0
    fi
    local img="${PLAYWRIGHT_IMAGE:-mcr.microsoft.com/playwright/python:v1.49.0-jammy}"
    if ! docker image inspect "$img" >/dev/null 2>&1 && ! docker pull "$img" >/dev/null 2>&1; then
        log "SKIP: Playwright image $img unavailable (set PLAYWRIGHT_IMAGE or pre-pull it)"
        return 0
    fi
    # The python image ships browsers under /ms-playwright but not the pip module,
    # so install it (matching the image's browser build) and run against the cache.
    # --network host lets the container reach the compose's nginx on localhost:8443.
    local pv="${PLAYWRIGHT_VERSION:-1.49.0}"
    local out rc
    out=$(docker run --rm --network host \
        -e BASE_URL="$BASE_URL" -e APACHE_URL="${APACHE_URL:-}" -e PLAYWRIGHT_BROWSERS_PATH=/ms-playwright \
        -v "$DIR/lib/$script:/t/$script:ro" \
        "$img" sh -c "pip install -q playwright==$pv >/dev/null 2>&1 && python3 /t/$script" 2>&1)
    rc=$?
    printf '%s\n' "$out" | sed 's/^/    /'
    assert_eq 0 "$rc" "$desc"
}
