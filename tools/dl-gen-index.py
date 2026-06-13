#!/usr/bin/env python3
"""Generate a styled static index.html for each directory under a /dl/ repo tree.

The download area (unmask.sh/dl/) is a static, publish-driven repository, so we
can render the directory listings ahead of time as final HTML instead of relying
on nginx autoindex + client-side JS. Serving the pre-rendered table means the
first paint IS the finished table (no flash of the raw listing, no DOM swap).

Output markup mirrors the .dlx-* structure that dlindex.css styles, so the same
stylesheet themes both these static pages and (as a fallback) any autoindex dir
that lacks a generated index.

Usage:
    dl-gen-index.py <root_dir> [url_base]

    root_dir   filesystem dir mapped to url_base (e.g. /var/www/unmask.sh/dl)
    url_base   URL path of root_dir (default: /dl)

The root dir itself is skipped (it keeps the hand-written landing page); every
directory strictly below it gets an index.html.
"""
import html
import os
import sys
import time

ASSET_NAMES = {"index.html", "dlindex.css", "dlindex.js", "dl-index.html"}

# Top-level dirs updated out-of-band (feed by cron, ipgeo by a mirror job): a
# static snapshot index would go stale, so leave them on dynamic autoindex.
EXCLUDE_TOP = {"feed", "ipgeo"}


def human_size(n):
    if n < 1024:
        return "%d B" % n
    units = ["KB", "MB", "GB", "TB"]
    i, v = -1, float(n)
    while v >= 1024 and i < len(units) - 1:
        v /= 1024
        i += 1
    return ("%d %s" % (round(v), units[i])) if v >= 100 else ("%.1f %s" % (v, units[i]))


def classify(name, is_dir):
    if is_dir:
        return "dir", "DIR"
    ext = name.rsplit(".", 1)[-1].lower() if "." in name else ""
    if ext in ("rpm", "deb", "apk"):
        return "pkg", ext.upper()
    if ext in ("asc", "gpg", "pub", "rsa", "key"):
        return "key", "KEY"
    return "meta", (ext or "•")[:4].upper()


def breadcrumb(url_base, rel):
    # url_base="/dl", rel="rpm/x86_64" -> unmask / dl / rpm / x86_64 (last = current)
    segs = [url_base.strip("/")] + ([] if rel == "." else rel.split("/"))
    acc = "/"
    out = []
    for i, seg in enumerate(segs):
        acc += seg + "/"
        if i:
            out.append('<span class="sep">/</span>')
        if i == len(segs) - 1:
            out.append('<span class="cur">%s</span>' % html.escape(seg))
        else:
            out.append('<a href="%s">%s</a>' % (html.escape(acc), html.escape(seg)))
    return "".join(out)


def row(href, name, is_dir, size_cell, date_cell):
    cls, tag = classify(name, is_dir)
    label = html.escape(name) + ("/" if is_dir else "")
    return (
        '<tr class="%s"><td><span class="dlx-name">'
        '<span class="dlx-ico %s">%s</span>'
        '<a href="%s">%s</a></span></td>'
        '<td class="dlx-size">%s</td><td class="dlx-date">%s</td></tr>'
    ) % (
        "dlx-dir" if is_dir else "",
        cls, html.escape(tag),
        html.escape(href), label,
        size_cell, html.escape(date_cell),
    )


def render(url_path, url_base, rel, entries):
    DASH = "—"
    title = "unmask /dl/ — " + ("" if rel == "." else rel + "/")
    rows = ['<tr class="dlx-dir dlx-up"><td><span class="dlx-name">'
            '<span class="dlx-ico up">↑</span><a href="../">..</a></span></td>'
            '<td class="dlx-size">%s</td><td class="dlx-date"></td></tr>' % DASH]
    for name, is_dir, size, mtime in entries:
        href = name + ("/" if is_dir else "")
        size_cell = DASH if is_dir else human_size(size)
        date_cell = time.strftime("%d-%b-%Y %H:%M", time.localtime(mtime))
        rows.append(row(href, name, is_dir, size_cell, date_cell))
    n = len(entries)
    count = "%d %s" % (n, "item" if n == 1 else "items")
    return """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>%s</title>
<meta name="robots" content="noindex">
<link rel="icon" type="image/png" href="/static/icon.png">
<link rel="stylesheet" href="%s/dlindex.css">
</head>
<body>
<div class="dlx-root">
<div class="dlx-head">
<a class="dlx-brand" href="%s/">unmask</a>
<span class="dlx-crumbs">%s</span>
<span class="dlx-spacer"></span>
<span class="dlx-count">%s</span>
</div>
<table class="dlx-table">
<thead><tr><th class="col-name">Name</th><th class="col-size">Size</th><th class="col-date">Modified</th></tr></thead>
<tbody>
%s
</tbody>
</table>
</div>
</body>
</html>
""" % (
        html.escape(title),
        html.escape(url_base.rstrip("/")),
        html.escape(url_base.rstrip("/")),
        breadcrumb(url_base, rel),
        html.escape(count),
        "\n".join(rows),
    )


def gen_dir(dirpath, root, url_base):
    rel = os.path.relpath(dirpath, root).replace(os.sep, "/")
    url_path = url_base.rstrip("/") + ("/" if rel == "." else "/" + rel + "/")
    entries = []
    for name in os.listdir(dirpath):
        if rel == "." and name in ASSET_NAMES:
            continue
        if name == "index.html":
            continue
        full = os.path.join(dirpath, name)
        if os.path.islink(full):
            continue
        is_dir = os.path.isdir(full)
        try:
            st = os.stat(full)
        except OSError:
            continue
        entries.append((name, is_dir, st.st_size, st.st_mtime))
    entries.sort(key=lambda e: (not e[1], e[0].lower()))  # dirs first, then name
    out = render(url_path, url_base, rel, entries)
    with open(os.path.join(dirpath, "index.html"), "w", encoding="utf-8") as f:
        f.write(out)


def main():
    if len(sys.argv) < 2:
        sys.stderr.write(__doc__)
        sys.exit(2)
    root = os.path.abspath(sys.argv[1])
    url_base = sys.argv[2] if len(sys.argv) > 2 else "/dl"
    if not os.path.isdir(root):
        sys.stderr.write("not a directory: %s\n" % root)
        sys.exit(2)
    count = 0
    for dirpath, dirnames, _ in os.walk(root):
        dirnames.sort()
        if os.path.abspath(dirpath) == root:
            dirnames[:] = [d for d in dirnames if d not in EXCLUDE_TOP]
            continue  # root keeps its hand-written landing page
        gen_dir(dirpath, root, url_base)
        count += 1
    print("generated %d directory index%s under %s" % (count, "" if count == 1 else "es", root))


if __name__ == "__main__":
    main()
