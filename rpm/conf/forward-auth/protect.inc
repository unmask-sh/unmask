# /etc/unmask/forward-auth/protect.inc — thin snippet that turns protection on.
#
# Usage:
#   - Place inside any location to protect just that location
#     location / {
#         include /etc/unmask/forward-auth/protect.inc;
#         root /var/www;
#     }
#   - Place in server scope to protect every location in the vhost
#     server {
#         include /etc/unmask/forward-auth/server.inc;   # admin UI + challenge
#         include /etc/unmask/forward-auth/protect.inc;  # protect all locations
#     }
#
# Native-mode installs (= ngx_http_unmask_module) include
# /etc/unmask/native/protect.inc instead of `auth_request`.  This file is for
# forward-auth mode.
#
# /unmask/* and /_unmask/check declare `auth_request off;` explicitly in
# server.inc, so enabling this include on a higher server does not create a
# self-check loop.

auth_request /_unmask/check;
# Pull X-Unmask-Chmode set by AuthCheck into a variable so the named
# location below can forward it to /unmask/challenge/ as ?chm=.
auth_request_set $unmask_chmode $upstream_http_x_unmask_chmode;
error_page 401 = @unmask_to_challenge;
# AuthCheck returns 403 for a block (ban / geo-deny / honeypot-deny / rate-deny);
# route it to the daemon's branded "blocked" page (DenyTheme / branding apply),
# the same surface native + apache mode serve -- not nginx's bare 403.  Matches
# the documented snippet pattern (snippets/nginx-forward-auth.conf).
error_page 403 = @unmask_blocked;
