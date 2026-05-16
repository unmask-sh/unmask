-- unmask auth handler for Apache 2.4+ mod_lua.
--
-- Flow:
--   client → Apache → handle_request(r)
--                   ├→ subrequest to unmask-admin /api/check
--                   ├→ branch on the X-Unmask-Action header
--                   │   pass     → r:return DECLINED   (= forward as usual)
--                   │   challenge→ redirect to /unmask/challenge/
--                   │   block    → 403
--
-- Installation:
--   Put `LuaHookAccessChecker /etc/httpd/unmask.lua handle_request` in
--   /etc/httpd/conf.d/unmask.conf, and drop this file at /etc/httpd/unmask.lua.

-- Listen URL for unmask-admin.  Rewrite if needed.
local UNMASK_API = "http://127.0.0.1:9477/unmask/api/check"

-- /unmask/* and /_unmask/* are passed through to prevent self-loop.
-- Run auth check for every other URI.
local function should_skip(uri)
    if uri:match("^/unmask/") or uri:match("^/_unmask/") then
        return true
    end
    return false
end

function handle_request(r)
    if should_skip(r.uri) then
        return apache2.DECLINED
    end

    -- External HTTP calls via mod_lua r:request_get / wsapi are inherently
    -- heavy.  Assuming mod_proxy_http (= dynamic forward) is configured for
    -- same-host loopback, Apache's own subrequest is lighter.  Subrequests
    -- are limited to the same vhost, so the unmask call uses HTTP over loopback.
    --
    -- requires: lua-socket (= unnecessary if we used apr_socket_t, but
    -- luaSocket is not standard across distros, so we use Apache's built-in
    -- `r:make_subrequest` instead).

    -- Use Apache's internal subrequest for the call to unmask.
    -- Assumes the location that proxy_passes /unmask/api/check (in
    -- unmask-proxy.conf) is exposed under the internal alias /_unmask/check.
    local sub = r:lookup_uri("/_unmask/check")
    if not sub then
        -- subrequest impossible = unmask config is broken; fail-open (= forward as usual).
        return apache2.DECLINED
    end

    -- Pass the original request context to the subrequest via headers.
    -- Apache's r:lookup_uri is for GET subrequests and does not carry a body,
    -- so use headers.
    local original_uri = r.unparsed_uri or r.uri
    local original_ip  = r.useragent_ip or r.connection.client_ip or ""
    local original_ua  = r.headers_in["User-Agent"] or ""
    local original_host = r.headers_in["Host"] or r.hostname or ""
    local cookie_hdr   = r.headers_in["Cookie"] or ""

    sub.headers_in["X-Original-URI"]  = original_uri
    sub.headers_in["X-Original-IP"]   = original_ip
    sub.headers_in["X-Original-UA"]   = original_ua
    sub.headers_in["X-Original-Host"] = original_host
    sub.headers_in["Cookie"]          = cookie_hdr

    sub:run()
    local status = sub.status
    local action = (sub.headers_out["X-Unmask-Action"] or "pass"):lower()

    if status == 200 or action == "pass" then
        return apache2.DECLINED -- forward as usual
    end
    if status == 403 or action == "block" then
        r:err("[unmask] block: " .. (sub.headers_out["X-Unmask-Reason"] or ""))
        return 403
    end
    if status == 401 or action == "challenge" then
        -- Redirect to the challenge HTML.
        r.headers_out["Location"] = "/unmask/challenge/"
        return 302
    end
    -- unknown → fail-open.
    return apache2.DECLINED
end
