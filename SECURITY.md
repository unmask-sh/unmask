# Security Policy

## Reporting a Vulnerability

**Please do not open a public issue for security vulnerabilities.**

Report security issues privately through GitHub: on the repository's
[Security tab](https://github.com/unmask-sh/unmask/security), choose
**Report a vulnerability**
([direct link](https://github.com/unmask-sh/unmask/security/advisories/new)).
Only you and the maintainers can see the report.

What we will do:

- Acknowledge your report within **48 hours** (best effort).
- Investigate and provide updates as we go.
- Coordinate a fix and a disclosure timeline with you.

If you do not hear back within 7 days, please escalate by opening a
public issue **without disclosing the vulnerability** (just say "I have
a security report awaiting acknowledgement").

## Coordinated Disclosure

We follow a coordinated disclosure process:

- **90-day window** from the initial report to public disclosure.
- We may publish details earlier once a fix has shipped.
- We do not pursue legal action against good-faith researchers who:
  - report responsibly through the channel above,
  - do not access or modify data beyond what is necessary to demonstrate the issue,
  - do not run testing against production deployments of other users.

## Supported Versions

While unmask is pre-release (v0.x), we only provide security fixes for
the **latest released version**. After v1.0 we expect to support the
latest minor release; older releases will be best-effort.

## Threat Model

What unmask defends against, what it does not, and what it relies on --
so that a report, and a deployment, can be weighed against the design
rather than against a guess at it.

**In scope.** Automated clients that fetch a site's pages at a volume or
pace no visitor keeps: scrapers, crawlers that ignore the operator's
wishes, credential-stuffing and form-abuse scripts, and botnets that
spread the same work over many addresses.  The defence is a cost (a
proof-of-work a real browser pays once, a CAPTCHA where the cost must be
higher), a set of signals read from the request (the TLS fingerprint, the
User-Agent against the fingerprint, the network, the rate, the paths a
bot touches and a visitor never does), and the record of what each one
did, so the operator can see and decide.  Every decision is made on the
server; the client's cooperation is never assumed.

**Out of scope.** Volumetric and network-layer denial of service (that
is the provider's job upstream); abuse by an authenticated user of the
protected application; a client that behaves exactly like a browser
because it is one, driven by a person; and attribution of a request to a
person or a device.  A JA4 fingerprint names a TLS stack, not an
individual -- a browser and a bot built on the same stack share it -- so
it is a signal among others, never a verdict on its own.  A proof-of-work
is a cost, not a proof of anything: a client that can afford it gets a
pass, and the budgets on what a pass is used for (per pass and per
address) are what bound the client that pays.

**Trust boundaries.** The daemon and nginx share one secret
(`secret.bv_secret`); every node that verifies passes for a site must
hold it, and a node that leaks it can mint passes for every other.  The
admin's own signatures -- the session cookie, the CSRF tokens -- derive
from a second secret (`secret.admin_secret`) that only the daemon holds
and that no rendered nginx file carries, so a node that leaks `bv_secret`
mints passes but cannot sign an admin session (`unmask doctor` checks
that the rendered files do not carry it).  A
pass cookie is a bearer token bound to the client's address (an IPv6
client by its /64), the site's host and a window; within those it can
be replayed from the same address, which is why what a pass is used for
is counted.  The module trusts the address nginx hands it: behind a load
balancer or a CDN the operator names the trusted ranges
(`nginx.trusted_lb_realip`), and a range named wrongly lets a client
choose its address.  nginx's own `set_real_ip_from`, in a server block,
replaces the list unmask renders; `unmask doctor` names any of its
public ranges that no trusted load balancer covers, with the file and
line.  The admin is reachable by whoever reaches its
listener; the operator binds it, lists the hosts it answers to
(`nginx.admin_allowed_hosts`) and, where needed, the addresses.  The
access log the daemon reads arrives over a local socket from nginx; the
daemon counts what nginx logged.

**Assumptions and known limits.**  When the daemon is down, nginx lets
judged requests through rather than refuse every visitor (fail-open, by
design; the module says so in nginx's error log and the admin's
notifications).  Budgets are counted per node: behind a load balancer the
total is that many times the figure.  The module reads the TLS
ClientHello through OpenSSL's message callback, of which an SSL context
holds one: another nginx module that sets the same callback after unmask
replaces it, and JA4-based decisions silently stop applying (the module
logs it, `unmask doctor` reports it).  nginx's QUIC compatibility layer
on OpenSSL older than 3.5 does the same for HTTP/3.  Community Bans are
fetched by default and applied with limits on what one pull can switch
on; submitting is opt-in.  Signatures are HMAC (SHA-1 today, SHA-256
selectable; both verified during the move) cut to 64 bits -- enough for
an online guess to be hopeless, not for an offline one against a leaked
secret, which is the secret's job to prevent.  That signature is what
the nginx module checks on every request; within its binding (the
address or the /64, the host, the window) a pass is a bearer token and
may be presented again, by the same client or by another in the same
/64, up to the reuse budget the operator sets -- a narrower binding
would cut off the visitor whose address moves, which is why the budget,
not the binding, is the limit.

**Rescue by name.**  A request from a crawler the operator chose to let
through is exempt from the challenge.  As shipped, the search engines
and the AI crawlers on that list are recognised by their published
address ranges (`$is_bypass_ip`), never by the User-Agent alone; a
client that merely claims one of their names is treated as any other
client.  A User-Agent pattern the operator adds by hand to the name-only
list is trusted on the name alone, for GET and HEAD, at the name-only
rate -- the honeypot, the ban list, the country and ASN rules and the
custom rules still apply to it -- so an added pattern is a decision to
trust whoever can type that name, and the shipped configuration makes
none.

## Out of Scope

The following are not in scope for this project's security advisories:

- Vulnerabilities in nginx, OpenSSL, MariaDB, or other upstream
  dependencies — please report those to the respective upstream.
- Operator misconfiguration of unmask (e.g. exposing the admin UI to
  the public internet without authentication).
- Issues that require running unmask on an end-of-life OS or with
  rate-limiting disabled.
- Denial-of-service attacks at the network layer (use your provider's
  network-layer DDoS protection upstream).

## Recognition

Reporters are credited in the release notes for the fix, unless they
ask to remain anonymous.
