#!/bin/sh
# Shared by 10-unmask-gateway.envsh (start) and 30-unmask-autoreload.sh
# (every change of the rendered includes): writes the two nginx-local
# includes the gateway servers use, choosing between what the admin rendered
# (settings > Gateway) and this container's environment.
#
#   /etc/nginx/unmask-gateway-location.inc  the proxy location
#     - the admin's /etc/unmask/gateway-location.inc when it names an
#       upstream (settings > Gateway > upstream)
#     - else a block built from UNMASK_UPSTREAM (the 0.1.37 way)
#     - else a notice pointing at settings > Gateway
#   /etc/nginx/unmask-gateway-proxies.inc   set_real_ip_from for a balancer
#     - the admin's /etc/unmask/gateway-proxies.inc when it lists ranges
#     - else built from UNMASK_TRUSTED_PROXIES
#
# It also leaves /run/unmask/gateway-nginx.status for the admin, so the tab
# can say what an empty field falls back to.

# unmask_gateway_template: pick the gateway template for what settings >
# Gateway > listen says (markers in gateway-vhosts.inc): both servers, :80
# only (no https here), or :443 only.  Returns 0 when the choice changed
# (the caller re-runs envsubst), 1 when it did not.
unmask_gateway_template() {
    vh=/etc/unmask/gateway-vhosts.inc
    src=/usr/share/unmask/gateway.conf.template
    UNMASK_GATEWAY_LISTEN=":80+:443"
    UNMASK_GATEWAY_TLS=files
    grep -q 'acme_certificate' "$vh" 2>/dev/null && UNMASK_GATEWAY_TLS=ACME
    if grep -q '^# unmask-gateway-tls: none' "$vh" 2>/dev/null; then
        src=/usr/share/unmask/gateway-http.conf.template
        UNMASK_GATEWAY_LISTEN=":80"
        UNMASK_GATEWAY_TLS=none
    elif grep -q '^# unmask-gateway-http: none' "$vh" 2>/dev/null; then
        src=/usr/share/unmask/gateway-https.conf.template
        UNMASK_GATEWAY_LISTEN=":443"
    fi
    dst=/etc/nginx/templates/unmask-gateway.conf.template
    mkdir -p /etc/nginx/templates
    if [ -f "$dst" ] && cmp -s "$src" "$dst"; then
        return 1
    fi
    cp "$src" "$dst"
    return 0
}

unmask_gateway_includes() {
    adm_loc=/etc/unmask/gateway-location.inc
    adm_prx=/etc/unmask/gateway-proxies.inc
    loc_src=none
    if [ -f "$adm_loc" ] && ! grep -q '^# unmask-gateway-upstream: none' "$adm_loc"; then
        loc_src=admin
        printf '# written by gateway-includes.sh: the admin-rendered location\ninclude %s;\n' "$adm_loc" > /etc/nginx/unmask-gateway-location.inc
    elif [ -n "${UNMASK_UPSTREAM:-}" ]; then
        loc_src=env
        cat > /etc/nginx/unmask-gateway-location.inc <<LOCATION
# written by gateway-includes.sh from UNMASK_UPSTREAM (settings > Gateway >
# upstream is empty)
location / {
    include /etc/unmask/protect.inc;
    proxy_pass ${UNMASK_UPSTREAM};
    proxy_http_version 1.1;
    proxy_read_timeout 1h;
    proxy_send_timeout 1h;
    proxy_ssl_server_name on;
    proxy_ssl_name \$host;
    proxy_set_header Host              \$host;
    proxy_set_header X-Real-IP         \$remote_addr;
    proxy_set_header X-Forwarded-For   \$proxy_add_x_forwarded_for;
    proxy_set_header X-Forwarded-Proto \$unmask_gw_xfp;
    proxy_set_header Upgrade           \$http_upgrade;
    proxy_set_header Connection        \$connection_upgrade;
}
LOCATION
    else
        cat > /etc/nginx/unmask-gateway-location.inc <<'LOCATION'
# written by gateway-includes.sh: no upstream configured yet (settings >
# Gateway > upstream, or UNMASK_UPSTREAM on this container)
location / {
    include /etc/unmask/protect.inc;
    default_type text/html;
    return 503 '<!doctype html><meta charset="utf-8"><title>unmask gateway</title><body style="font-family:system-ui,sans-serif;max-width:40rem;margin:4rem auto;line-height:1.5"><h1>unmask gateway: no upstream yet</h1><p>This gateway is up, but nothing tells it where your site is. Open <a href="/unmask/admin/">the admin</a> and set the upstream under <b>Settings &rarr; Gateway</b> (for example <code>http://host.docker.internal:8080</code> for a server on this host).</p></body>';
}
LOCATION
    fi
    {
        printf '# written by gateway-includes.sh\n'
        trusted=""
        if [ -f "$adm_prx" ] && ! grep -q '^# unmask-gateway-proxies: none' "$adm_prx"; then
            printf 'include %s;\n' "$adm_prx"
            trusted=" (settings > Gateway)"
        else
            for cidr in ${UNMASK_TRUSTED_PROXIES:-}; do
                case "$cidr" in
                    *[!0-9a-fA-F:./]*) echo "unmask-gateway: ignoring UNMASK_TRUSTED_PROXIES entry '$cidr' (not an address or CIDR)" >&2; continue ;;
                esac
                trusted="$trusted $cidr"
                printf 'set_real_ip_from %s;\n' "$cidr"
            done
            [ -n "$trusted" ] && printf 'real_ip_header X-Forwarded-For;\nreal_ip_recursive on;\n'
        fi
    } > /etc/nginx/unmask-gateway-proxies.inc
    UNMASK_GATEWAY_LOCATION_SOURCE=$loc_src
    UNMASK_GATEWAY_TRUSTED=$trusted
    # For the admin's Gateway tab (best effort: /run/unmask is the shared
    # socket volume; a module-only container may not have it).
    if [ -d /run/unmask ]; then
        {
            printf 'location_source=%s\n' "$loc_src"
            printf 'upstream_env=%s\n' "${UNMASK_UPSTREAM:-}"
            printf 'trusted_proxies_env=%s\n' "${UNMASK_TRUSTED_PROXIES:-}"
            printf 'nginx_version=%s\n' "$(nginx -v 2>&1 | sed 's,.*nginx/,,')"
        } > /run/unmask/gateway-nginx.status.tmp 2>/dev/null && mv -f /run/unmask/gateway-nginx.status.tmp /run/unmask/gateway-nginx.status 2>/dev/null
    fi
}
