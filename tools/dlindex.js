/* dlindex.js - progressive enhancement for nginx autoindex pages under /dl/.
 * Injected (with dlindex.css) via sub_filter into the stock autoindex HTML.
 * It reads the <a> entries nginx already rendered and rebuilds them as a
 * themed, sortable, filterable table with a breadcrumb. Pure DOM, no deps.
 *
 * Safe by construction:
 *   - no-ops unless the page is an autoindex listing (has <pre> + "Index of"),
 *     so the hand-written /dl/ landing page is untouched;
 *   - package managers (dnf/apt/apk) never execute JS, so they see the raw
 *     listing exactly as before;
 *   - names/links come from the <a> href (authoritative); size/date are parsed
 *     from the trailing text purely for display and are best-effort.
 *
 * The /dl/ location sends this with charset=utf-8 (nginx `charset utf-8;`), so
 * the literal glyphs below (arrows, dashes) decode correctly. */
(function () {
  "use strict";

  var DASH = "—"; // em dash

  var pre = document.querySelector("pre");
  var h1 = document.querySelector("h1");
  if (!pre || !h1 || !/Index of/i.test(h1.textContent || "")) return;

  // ---- parse entries from the autoindex <pre> ----
  var entries = [];
  var nodes = pre.childNodes;
  for (var i = 0; i < nodes.length; i++) {
    var n = nodes[i];
    if (!(n.nodeType === 1 && n.tagName === "A")) continue;
    var href = n.getAttribute("href") || "";
    if (href === "../" || href === "" || /^[a-z]+:\/\//i.test(href)) continue;
    var isDir = /\/$/.test(href);
    var name;
    try { name = decodeURIComponent(href.replace(/\/$/, "")); }
    catch (e) { name = href.replace(/\/$/, ""); }
    var meta = "";
    var t = nodes[i + 1];
    if (t && t.nodeType === 3) meta = t.nodeValue || "";
    var parts = meta.replace(/ /g, " ").trim().split(/\s+/).filter(Boolean);
    var size = "", date = "";
    if (parts.length >= 3) { date = parts[0] + " " + parts[1]; size = parts[2]; }
    else if (parts.length === 1) { size = parts[0]; }
    entries.push({ name: name, href: href, isDir: isDir, size: size, date: date });
  }
  if (!entries.length) return;

  // ---- helpers ----
  function sizeBytes(s) {
    if (!s || s === "-") return -1;
    var m = /^([\d.]+)\s*([KMGTP])?B?$/i.exec(s);
    if (!m) return -1;
    var mult = { "": 1, K: 1024, M: 1048576, G: 1073741824, T: 1099511627776, P: 1125899906842624 };
    return parseFloat(m[1]) * (mult[(m[2] || "").toUpperCase()] || 1);
  }
  function fmtSize(s) {
    if (!s || s === "-") return DASH;
    if (!/^\d+$/.test(s)) return s; // already human (e.g. "9M") -> show as-is
    var n = parseInt(s, 10);
    if (n < 1024) return n + " B";
    var u = ["KB", "MB", "GB", "TB"], idx = -1, v = n;
    do { v /= 1024; idx++; } while (v >= 1024 && idx < u.length - 1);
    return (v >= 100 ? Math.round(v) : v.toFixed(1)) + " " + u[idx];
  }
  function dateMs(d) {
    var m = /^(\d{1,2})-([A-Za-z]{3})-(\d{4})\s+(\d{1,2}):(\d{2})/.exec(d || "");
    if (!m) return -1;
    var mo = "JanFebMarAprMayJunJulAugSepOctNovDec".indexOf(m[2]) / 3;
    if (mo < 0) return -1;
    return Date.UTC(+m[3], mo, +m[1], +m[4], +m[5]);
  }
  function classify(e) {
    if (e.isDir) return { cls: "dir", tag: "DIR" };
    var ext = (e.name.split(".").pop() || "").toLowerCase();
    if (ext === "rpm" || ext === "deb" || ext === "apk") return { cls: "pkg", tag: ext.toUpperCase() };
    if (ext === "asc" || ext === "gpg" || ext === "pub" || ext === "rsa" || ext === "key") return { cls: "key", tag: "KEY" };
    return { cls: "meta", tag: (ext || "•").slice(0, 4).toUpperCase() };
  }
  function el(tag, cls, txt) {
    var x = document.createElement(tag);
    if (cls) x.className = cls;
    if (txt != null) x.textContent = txt;
    return x;
  }

  // ---- breadcrumb (always rooted at /dl/) ----
  var path = location.pathname.replace(/\/+$/, "/");
  var segs = path.split("/").filter(Boolean); // e.g. ["dl","rpm","x86_64"]
  var crumbs = el("span", "dlx-crumbs");
  var acc = "/";
  for (var s = 0; s < segs.length; s++) {
    acc += segs[s] + "/";
    if (s) crumbs.appendChild(el("span", "sep", "/"));
    if (s === segs.length - 1) {
      crumbs.appendChild(el("span", "cur", segs[s]));
    } else {
      var a = el("a", null, segs[s]);
      a.href = acc;
      crumbs.appendChild(a);
    }
  }

  var root = el("div", "dlx-root");

  var head = el("div", "dlx-head");
  var brand = el("a", "dlx-brand", "unmask");
  brand.href = "/dl/";
  head.appendChild(brand);
  head.appendChild(crumbs);
  head.appendChild(el("span", "dlx-spacer"));
  var count = el("span", "dlx-count", "");
  head.appendChild(count);
  root.appendChild(head);

  // ---- filter ----
  var tools = el("div", "dlx-tools");
  var filter = el("input", "dlx-filter");
  filter.type = "search";
  filter.placeholder = "Filter…";
  filter.setAttribute("aria-label", "filter files");
  tools.appendChild(filter);
  root.appendChild(tools);

  // ---- table ----
  var table = el("table", "dlx-table");
  var thead = el("thead");
  var htr = el("tr");
  var cols = [
    { key: "name", label: "Name", cls: "col-name" },
    { key: "size", label: "Size", cls: "col-size" },
    { key: "date", label: "Modified", cls: "col-date" }
  ];
  var ths = {};
  cols.forEach(function (c) {
    var th = el("th", c.cls, c.label);
    var arr = el("span", "arr", "");
    th.appendChild(arr);
    th._arr = arr;
    th.addEventListener("click", function () { setSort(c.key); });
    htr.appendChild(th);
    ths[c.key] = th;
  });
  thead.appendChild(htr);
  table.appendChild(thead);
  var tbody = el("tbody");
  table.appendChild(tbody);
  root.appendChild(table);

  var hasParent = segs.length > 1; // don't offer ".." above the /dl/ repo root

  // ---- sort state + render ----
  var sortKey = "name", sortDir = 1; // dirs always float to the top within name sort
  function setSort(key) {
    if (sortKey === key) sortDir = -sortDir;
    else { sortKey = key; sortDir = 1; }
    render();
  }
  function sorted() {
    var arr = entries.slice();
    arr.sort(function (a, b) {
      if (a.isDir !== b.isDir) return a.isDir ? -1 : 1; // dirs first, always
      var r;
      if (sortKey === "size") r = sizeBytes(a.size) - sizeBytes(b.size);
      else if (sortKey === "date") r = dateMs(a.date) - dateMs(b.date);
      else r = a.name.localeCompare(b.name, undefined, { numeric: true, sensitivity: "base" });
      return r * sortDir;
    });
    return arr;
  }
  function render() {
    cols.forEach(function (c) {
      ths[c.key].classList.toggle("sorted", c.key === sortKey);
      ths[c.key]._arr.textContent = c.key === sortKey ? (sortDir > 0 ? "▲" : "▼") : "";
    });
    var q = filter.value.trim().toLowerCase();
    tbody.textContent = "";
    if (hasParent) { // pinned ".." row, first and unfiltered
      var up = el("tr", "dlx-dir dlx-up");
      var utd = el("td");
      var uw = el("span", "dlx-name");
      uw.appendChild(el("span", "dlx-ico up", "↑"));
      var ua = el("a", null, "..");
      ua.href = "../";
      uw.appendChild(ua);
      utd.appendChild(uw);
      up.appendChild(utd);
      up.appendChild(el("td", "dlx-size", DASH));
      up.appendChild(el("td", "dlx-date", ""));
      tbody.appendChild(up);
    }
    var shown = 0;
    sorted().forEach(function (e) {
      if (q && e.name.toLowerCase().indexOf(q) < 0) return;
      shown++;
      var k = classify(e);
      var tr = el("tr", e.isDir ? "dlx-dir" : null);
      var tdN = el("td");
      var nameWrap = el("span", "dlx-name");
      nameWrap.appendChild(el("span", "dlx-ico " + k.cls, k.tag));
      var a = el("a", null, e.name + (e.isDir ? "/" : ""));
      a.href = e.href;
      nameWrap.appendChild(a);
      tdN.appendChild(nameWrap);
      var tdS = el("td", "dlx-size", e.isDir ? DASH : fmtSize(e.size));
      var tdD = el("td", "dlx-date", e.date || "");
      tr.appendChild(tdN); tr.appendChild(tdS); tr.appendChild(tdD);
      tbody.appendChild(tr);
    });
    if (!shown) {
      var tr2 = el("tr");
      var td2 = el("td", "dlx-empty");
      td2.colSpan = 3;
      td2.textContent = q ? "No match for “" + filter.value + "”" : "Empty directory.";
      tr2.appendChild(td2);
      tbody.appendChild(tr2);
    }
    count.textContent = (q ? shown + " / " + entries.length : String(entries.length)) +
      (entries.length === 1 && !q ? " item" : " items");
  }
  filter.addEventListener("input", render);

  // ---- swap in ----
  document.title = "unmask /dl/ — " + segs.slice(1).join("/") + (segs.length > 1 ? "/" : "");
  document.body.textContent = "";
  document.body.appendChild(root);
  render();
  filter.focus();
})();
