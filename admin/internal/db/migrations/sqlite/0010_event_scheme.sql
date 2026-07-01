-- 0010 unmask_event.scheme: request scheme ("http" / "https") captured at
-- ingest time from X-Forwarded-Proto.  Used by the hunt table's URL popover
-- (= "open in new tab" / "copy URL" buttons) so the admin builds the public
-- URL from a server-controlled value instead of trusting the client payload.
--
-- nginx-rendered.conf sets `proxy_set_header X-Forwarded-Proto $scheme;` on
-- the admin upstream unconditionally, so the value is whatever nginx itself
-- terminated on (http/https) and can not be influenced by the client.
ALTER TABLE unmask_event ADD COLUMN scheme VARCHAR(8) NOT NULL DEFAULT '';
