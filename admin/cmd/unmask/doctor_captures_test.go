package main

import (
	"strings"
	"testing"
)

// The regex locations whose $1..$9 unmask's maps reset: where protect.inc is
// included in the location (or a parent location), or at server scope.  A
// named capture keeps its value, and a rewrite's or a regex if's $N are
// their own.
func TestCapturesAtRisk(t *testing.T) {
	const head = "nginx: the configuration file /etc/nginx/nginx.conf syntax is ok\n# configuration file /etc/nginx/nginx.conf:\nhttp {\n    include /etc/nginx/conf.d/*.conf;\n}\n"
	file := func(body string) string { return head + "# configuration file /etc/nginx/conf.d/site.conf:\n" + body }
	cases := []struct {
		name string
		dump string
		want []string // substrings of the findings, in order; nil = none
	}{
		{"location include, proxy_pass $1", file(`server {
    listen 80;
    location ~ ^/api/(.+)$ {
        include /var/lib/unmask/nginx/protect.inc;
        proxy_pass http://backend/backend/$1;
    }
}`), []string{"/etc/nginx/conf.d/site.conf:3 `location ~ ^/api/(.+)$` (proxy_pass reads"}},
		{"named capture", file(`server {
    location ~ ^/api/(?<rest>.+)$ {
        include /var/lib/unmask/nginx/protect.inc;
        proxy_pass http://backend/backend/$rest;
    }
}`), nil},
		{"server-scope include reaches every location", file(`server {
    include /var/lib/unmask/nginx/protect.inc;
    location / { proxy_pass http://backend; }
    location ~* "^/img/([a-z]+)\.png$" { try_files /static/${1}.png =404; }
}`), []string{"site.conf:4 `location ~* ^/img/([a-z]+)\\.png$` (try_files reads"}},
		{"an unprotected server", file(`server {
    location ~ ^/api/(.+)$ { proxy_pass http://backend/$1; }
}
server {
    location / { include /var/lib/unmask/nginx/protect.inc; proxy_pass http://b; }
}`), nil},
		{"nested in a protected location", file(`server {
    location / {
        include /var/lib/unmask/nginx/protect.inc;
        location ~ ^/dl/(.+)$ { alias /srv/files/$1; }
    }
}`), []string{"site.conf:4 `location ~ ^/dl/(.+)$` (alias reads"}},
		{"rewrite and regex if read their own", file(`server {
    location ~ ^/old/(.*)$ {
        include /var/lib/unmask/nginx/protect.inc;
        rewrite ^/old/(.*)$ /new/$1 break;
        if ($http_referer ~ "^https://([^/]+)/") { set $ref_host $1; }
        proxy_pass http://backend;
    }
}`), nil},
		{"non-capturing and class parens", file(`server {
    location ~ ^/(?:a|b)/[(]x[)]$ {
        include /var/lib/unmask/nginx/protect.inc;
        return 301 https://example.com/$1;
    }
}`), nil},
		{"return inside a plain if", file(`server {
    location ~ ^/go/(\d+)$ {
        include /var/lib/unmask/nginx/protect.inc;
        if ($request_method = POST) { return 307 /post/$1; }
    }
}`), []string{"`location ~ ^/go/(\\d+)$` (return reads"}},
		{"a snippet location with a server-scope include elsewhere", head +
			"# configuration file /etc/nginx/conf.d/site.conf:\nserver {\n    include /var/lib/unmask/nginx/protect.inc;\n    include /etc/nginx/snippets/api.conf;\n}\n" +
			"# configuration file /etc/nginx/snippets/api.conf:\nlocation ~ ^/v1/(.+)$ { proxy_pass http://api/$1; }\n",
			[]string{"/etc/nginx/snippets/api.conf:1 `location ~ ^/v1/(.+)$`"}},
		{"server scope: a return runs before the rate-limit keys", file(`server {
    include /var/lib/unmask/nginx/protect.inc;
    location ~ ^/r/(.+)$ { return 301 https://example.com/$1; }
    location ~ ^/p/(.+)$ { proxy_pass http://backend/$1; }
}`), []string{"site.conf:4 `location ~ ^/p/(.+)$` (proxy_pass reads"}},
		{"a return before the include runs before the gate", file(`server {
    location ~ ^/a/(.+)$ {
        if ($request_method = OPTIONS) { return 204 /a/$1; }
        include /var/lib/unmask/nginx/protect.inc;
        set $tail $1;
    }
}`), []string{"site.conf:2 `location ~ ^/a/(.+)$` (set reads"}},
		{"the single-word form", file(`server {
    location ~^/s/(.+)$ { include /var/lib/unmask/nginx/protect.inc; proxy_pass http://b/$1; }
}`), []string{"`location ~^/s/(.+)$`"}},
	}
	for _, c := range cases {
		got := capturesAtRisk(c.dump)
		if len(got) != len(c.want) {
			t.Errorf("%s: %d finding(s) %q, want %d", c.name, len(got), got, len(c.want))
			continue
		}
		for i, w := range c.want {
			if !strings.Contains(got[i], w) {
				t.Errorf("%s: finding %q does not contain %q", c.name, got[i], w)
			}
		}
	}
}

func TestWarnNumberedCapturesSaysTheFix(t *testing.T) {
	dump := "# configuration file /etc/nginx/conf.d/a.conf:\nserver {\n location ~ ^/a/(.+)$ { include /x/protect.inc; proxy_pass http://b/$1; }\n}\n"
	var title, msg string
	warnNumberedCaptures(dump, func(t, m string) { title, msg = t, m })
	if title == "" || !strings.Contains(msg, "(?<rest>.+)") || !strings.Contains(msg, "a.conf:2") {
		t.Errorf("warning: %q %q", title, msg)
	}
	title = ""
	warnNumberedCaptures("# configuration file /etc/nginx/nginx.conf:\nhttp { }\n", func(t, m string) { title = t })
	if title != "" {
		t.Errorf("a dump with nothing at risk warned: %q", title)
	}
}
