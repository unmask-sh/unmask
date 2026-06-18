-- unmask auth handler for Apache 2.4+ mod_lua.
--
-- Flow:
--   client → Apache → handle_request(r)
--                   ├→ HTTP GET to unmask /api/check (via luasocket)
--                   └→ branch on status / X-Unmask-Action:
--                       pass      → apache2.DECLINED  (= forward as usual)
--                       challenge → 302 to /unmask/challenge/
--                       block     → 302 to /unmask/_ban/ (branded "blocked" page)
--
-- Requires the `lua-socket` package (RHEL: EPEL `lua-socket` /
-- Debian: `lua-socket`).  mod_lua itself has no HTTP client and no subrequest
-- API, so the outbound call to unmask goes through luasocket.
--
-- Installation:
--   Put `LuaHookAccessChecker /etc/httpd/unmask.lua handle_request` in
--   /etc/httpd/conf.d/unmask.conf, and drop this file at /etc/httpd/unmask.lua.

local http  = require("socket.http")
local ltn12 = require("ltn12")

-- unmask /api/check URL.  Rewrite the host:port if admin does not run
-- on the same host (= server.port in /etc/unmask/config.yml).
local UNMASK_API = "http://127.0.0.1:9477/unmask/api/check"

-- Hard cap the admin round-trip so a stalled admin cannot pile up Apache
-- workers.  On timeout the handler fails open (= forwards as usual).
http.TIMEOUT = 2

-- /unmask/* is proxied straight to unmask (challenge page / static
-- assets / verify API).  Never run the auth check on it, or the challenge
-- page itself would be challenged.
local function should_skip(uri)
    return uri:match("^/unmask/") ~= nil
end

function handle_request(r)
    if should_skip(r.uri) then
        return apache2.DECLINED
    end

    -- Forward the original request context to unmask as headers.
    -- Apache mode cannot supply a JA4 (no TLS handshake access); every other
    -- axis (UA filter / honeypot / BAN / CAPTCHA / protected paths / search
    -- rescue / rate_limit) works from these.
    local ok, code, headers = http.request{
        url    = UNMASK_API,
        method = "GET",
        headers = {
            ["X-Original-URI"]  = r.unparsed_uri or r.uri,
            ["X-Original-IP"]   = r.useragent_ip or "",
            ["X-Original-UA"]   = r.headers_in["User-Agent"] or "",
            ["X-Original-Host"] = r.headers_in["Host"] or r.hostname or "",
            ["Cookie"]          = r.headers_in["Cookie"] or "",
            -- Client JA4 (forward-auth mode). Apache cannot read the TLS
            -- handshake, so this carries a value only when a JA4-aware layer
            -- in front of Apache already set the X-Client-JA4 request header.
            -- ANTI-SPOOF: r.headers_in returns whatever the client sent, so a
            -- directly-reachable Apache lets a client forge this. Neutralize
            -- it in apache-forward-auth.conf unless a trusted front layer
            -- guarantees it. unmask also honors it only with
            -- challenge.ja4_source=header from a trusted peer.
            ["X-Client-JA4"]    = r.headers_in["X-Client-JA4"] or "",
        },
        -- The verdict is carried by the status code + headers; the response
        -- body is not needed, so it is discarded.
        sink = ltn12.sink.null(),
    }

    -- ok is nil when admin is unreachable or times out → fail open.
    if not ok then
        r:info("[unmask] admin unreachable, failing open: " .. tostring(code))
        return apache2.DECLINED
    end

    -- luasocket lowercases response header keys.
    local action = string.lower(headers and headers["x-unmask-action"] or "")

    if code == 200 or action == "pass" then
        return apache2.DECLINED -- forward as usual
    end
    if code == 403 or action == "block" then
        r:err("[unmask] block: " .. (headers["x-unmask-reason"] or ""))
        -- Serve the branded, localized "blocked" page the same way the
        -- challenge is served in this mode: redirect to the unmask-hosted page.
        -- /unmask/_ban returns it with a 403 (the same page native + nginx
        -- forward-auth render).  This is the persistent-block surface (ban /
        -- geo / honeypot); a rate-limit deny lands here too in pure Apache mode
        -- (no nginx limit_req in front), shown as "blocked".
        r.headers_out["Location"] = "/unmask/_ban/"
        return 302
    end
    if code == 401 or action == "challenge" then
        -- Redirect to the challenge HTML served by unmask.
        r.headers_out["Location"] = "/unmask/challenge/"
        return 302
    end
    -- unknown → fail open.
    return apache2.DECLINED
end
