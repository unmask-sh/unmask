// popover-pin.js — shared popover pin/drag/collapse implementation across all admin pages.
//
// Exposes:
//   window.popoverPin.install(primary)
//     primary is the base popup element (= carries the [data-popover] attribute; a transient
//     popover shown on hover).  Click-pinning generates a clone under the body with a 3-button
//     toolbar: drag handle + collapse toggle + close.  Multi-pin is supported (= multiple pins
//     on the same page are fine).
//
//   Returned object:
//     showHover(html, x, y)       : display the transient popover (= primary) for hover
//     hideHover()                 : hide the transient popover
//     hasPinFor(trigger)          : whether there's a pinned clone for this trigger element
//     handleClick(html, x, y, trg): click toggle (= close if pinned, otherwise pin)
//
//   Esc key closes all pinned popovers at once.
//
// CSS lives in a separate file (= popover-pin.css).  [data-popover]-family elements combine
// per-page styling with the additional CSS in this file.

// padding-top reserved for tools when pinned (= px).  Matches the CSS:
//   [data-popover].is-pinned { padding-top: 1.85rem }  (= 1.25rem more than hover's .6rem)
// converted to px (= 20px at 16px base).  Offset the clone upward from the hover popover's
// position so the content's visual location stays put while it "grows upward".
window.POPOVER_PIN_TOP_SHIFT_PX = 20;

// clampToViewport: shared helper.  Given a desired anchor (x, y) in page coords
// and the popover's measured (w, h), return adjusted (x, y) so the popover
// stays inside the viewport with an 8 px margin.  Bottom-overflow first tries
// flipping above the anchor; falls back to clamping when flipping also overflows.
window.popoverClampToViewport = window.popoverClampToViewport || function(x, y, w, h){
  var vw = document.documentElement.clientWidth;
  var vh = document.documentElement.clientHeight;
  var sx = window.scrollX, sy = window.scrollY;
  var ax = x + 12, ay = y + 12;
  if (ax + w > sx + vw - 8) {
    ax = Math.max(sx + 8, sx + vw - w - 8);
  }
  if (ay + h > sy + vh - 8) {
    var flipped = y - h - 12;
    if (flipped >= sy + 8) {
      ay = flipped;
    } else {
      ay = Math.max(sy + 8, sy + vh - h - 8);
    }
  }
  return { x: ax, y: ay };
};

window.popoverPin = window.popoverPin || (function(){
  // helper that builds the tools (= top-right action buttons).
  // [drag handle] [collapse toggle] [close].  drag uses mousedown to move the popover.
  // collapse toggles the popover-collapsed class.
  // raiseToFront re-appends the clone to its parent so its DOM-tail position
  // wins the stacking contest against other pinned clones at the same
  // z-index.  Triggered by mousedown anywhere on the clone (= title bar,
  // body, hint line) so clicking a popover always brings it forward like
  // a real window.  No-op when the clone is already last.
  function raiseToFront(clone){
    var p = clone.parentNode;
    if (!p) return;
    if (p.lastElementChild === clone) return;
    p.appendChild(clone);
  }
  function attachRaiseOnFocus(clone){
    // Capture phase so the raise happens before drag / button handlers run.
    // mousedown (not click) so the focus order is set before a potential
    // text selection / drag starts.
    clone.addEventListener('mousedown', function(){ raiseToFront(clone); }, true);
  }
  // Exposed for the info-tip flavor below.
  window._popoverRaiseToFront = raiseToFront;
  window._popoverAttachRaiseOnFocus = attachRaiseOnFocus;
  // attachDragToBar wires the Windows-style title-bar drag: mousedown anywhere
  // on the bar (except on a child <button>) starts the drag.  Hoisted so both
  // the popoverPin clone and the info-tip clone use the same teardown path.
  function attachDragToBar(bar, clone){
    bar.addEventListener('mousedown', function(e){
      // Let clicks on the action buttons (collapse / close) through.
      if (e.target.closest('button')) return;
      e.preventDefault();
      var rect = clone.getBoundingClientRect();
      var sx = e.clientX, sy = e.clientY;
      var ox = rect.left + window.scrollX, oy = rect.top + window.scrollY;
      function onMove(ev){
        clone.style.left = (ox + ev.clientX - sx) + 'px';
        clone.style.top  = (oy + ev.clientY - sy) + 'px';
      }
      function onUp(){
        document.removeEventListener('mousemove', onMove);
        document.removeEventListener('mouseup', onUp);
      }
      document.addEventListener('mousemove', onMove);
      document.addEventListener('mouseup', onUp);
    });
  }
  // extractVisibleText returns the user-visible text of an element, skipping
  // hidden / chrome / sibling-help nodes so a heading like
  //   <h1>honeypot <button class="ua-help-trigger">?</button>
  //       <script type="text/html">long help body...</script>
  //       <a class="settings-tab-preview">live preview ↗</a></h1>
  // resolves to just "honeypot".  Operates on a deep clone so the live DOM
  // is untouched.
  function extractVisibleText(el){
    if (!el || !el.cloneNode) return '';
    var c = el.cloneNode(true);
    var hidden = c.querySelectorAll(
      'script, style, template, ' +              // not visible
      '.ua-help-trigger, .info-tip, .info-popup, ' + // the trigger itself + its hover popup
      '.settings-tab-preview, ' +                 // settings.html: live-preview link sits inside h1
      '.added, .new-badge, .badge, ' +            // version chips / "new" markers
      '[hidden]'
    );
    hidden.forEach(function(n){ n.remove(); });
    return (c.textContent || '').replace(/\s+/g, ' ').trim();
  }
  // Cap title text so a paragraph never lands in the title bar.
  function capTitle(text){
    if (!text) return '';
    if (text.length > 60) return text.slice(0, 60).trim() + '…';
    return text;
  }
  // titleFromTrigger climbs from the `?` button up to the nearest labelling
  // context -- prefer narrow, label-only ancestors before falling back to
  // broader containers.  Most forms in settings.html wrap the label + `?`
  // pair in a small `.field-label` row separate from the input + unit hint,
  // so checking that class before `.field` keeps the title focused on the
  // label and out of the "秒 (= 0 で永久, ...)" hint text that lives below it.
  function titleFromTrigger(trigger){
    if (!trigger || !trigger.closest) return '';
    var anchor = trigger.closest(
      'h1,h2,h3,h4,h5,h6, legend, th, label, ' +
      '.field-label, .field, .bcd-card'
    );
    if (!anchor) return '';
    return capTitle(extractVisibleText(anchor));
  }
  // Exposed for the info-tip flavor below.
  window._popoverExtractVisibleText = extractVisibleText;
  window._popoverCapTitle = capTitle;
  // Shared clipboard handler attached to the title-bar copy button.  Pulls
  // the visible body text (= textContent, so embedded HTML / <code> markup
  // becomes plain) and writes it via the async Clipboard API.  Falls back to
  // an old-school `document.execCommand('copy')` path on browsers that block
  // navigator.clipboard outside a user gesture or over plain HTTP.
  function copyCloneBody(clone, btn){
    var body = clone.querySelector('.popover-body');
    if (!body) return;
    var text = (body.innerText || body.textContent || '').trim();
    if (!text) return;
    function flashOk(){
      var prev = btn.textContent;
      btn.textContent = '✓';
      btn.classList.add('popover-copy-ok');
      setTimeout(function(){
        btn.textContent = prev;
        btn.classList.remove('popover-copy-ok');
      }, 900);
    }
    if (navigator.clipboard && navigator.clipboard.writeText){
      navigator.clipboard.writeText(text).then(flashOk, function(){
        // Promise rejection (e.g. permission denied) → fall through to legacy.
        legacyCopy(text, flashOk);
      });
      return;
    }
    legacyCopy(text, flashOk);
  }
  function legacyCopy(text, onOk){
    try {
      var ta = document.createElement('textarea');
      ta.value = text;
      ta.style.position = 'fixed';
      ta.style.opacity = '0';
      document.body.appendChild(ta);
      ta.select();
      document.execCommand('copy');
      document.body.removeChild(ta);
      onOk();
    } catch (_){}
  }
  function buildTools(clone, onClose, title){
    var tools = document.createElement('div');
    tools.className = 'popover-tools';
    attachDragToBar(tools, clone);
    if (title){
      var t = document.createElement('span');
      t.className = 'popover-title';
      t.textContent = title;
      tools.appendChild(t);
    }
    // copy-to-clipboard
    var copy = document.createElement('button');
    copy.type = 'button';
    copy.className = 'popover-copy';
    copy.setAttribute('aria-label', 'copy');
    copy.textContent = '⧉';
    copy.addEventListener('click', function(e){
      e.preventDefault(); e.stopPropagation();
      copyCloneBody(clone, copy);
    });
    tools.appendChild(copy);
    // collapse toggle.  Shared with the bar's dblclick handler below so the
    // button glyph stays in sync no matter which path collapsed the popover.
    var col = document.createElement('button');
    col.type = 'button';
    col.className = 'popover-collapse';
    col.setAttribute('aria-label', 'collapse');
    col.textContent = '▾';
    function toggleCollapse(){
      // Freeze the rendered width on the way down so the bar doesn't snap
      // back to the popover's natural narrow size once the body is hidden.
      // Restore on expand so the popover can grow again if the body / title
      // text would have changed.
      var willCollapse = !clone.classList.contains('popover-collapsed');
      if (willCollapse){
        clone.style.width = clone.getBoundingClientRect().width + 'px';
      } else {
        clone.style.width = '';
      }
      var on = clone.classList.toggle('popover-collapsed');
      col.textContent = on ? '▸' : '▾';
    }
    col.addEventListener('click', function(e){
      e.preventDefault(); e.stopPropagation();
      toggleCollapse();
    });
    tools.appendChild(col);
    // Windows-style title-bar shortcut: double-click anywhere on the bar
    // (except a button) toggles collapse.  Same code path as the collapse
    // button so the chevron glyph flips correctly.
    tools.addEventListener('dblclick', function(e){
      if (e.target.closest('button')) return;
      e.preventDefault();
      toggleCollapse();
    });
    // close
    var btn = document.createElement('button');
    btn.type = 'button';
    btn.className = 'popover-close';
    btn.setAttribute('aria-label', 'close');
    btn.textContent = '×';
    btn.addEventListener('click', function(e){
      e.preventDefault(); e.stopPropagation();
      onClose();
    });
    tools.appendChild(btn);
    return tools;
  }
  // Exposed for the info-tip flavor below.
  window._popoverCopyCloneBody = copyCloneBody;
  // Exposed so installInfoTipPinning can reuse the same drag wiring.
  window._popoverAttachDragToBar = attachDragToBar;
  var clampToViewport = window.popoverClampToViewport;
  function install(primary){
    var pins = new Map();
    function showAt(p, html, x, y){
      p.innerHTML = html;
      // measure off-screen with visibility:hidden so we can pre-clamp before paint
      p.style.visibility = 'hidden';
      p.style.left = '0px';
      p.style.top  = '0px';
      p.style.display = 'block';
      var rect = p.getBoundingClientRect();
      var pos = clampToViewport(x, y, rect.width, rect.height);
      p.style.left = pos.x + 'px';
      p.style.top  = pos.y + 'px';
      p.style.visibility = '';
    }
    function makeClone(html, x, y, trigger){
      var clone = document.createElement('div');
      var dp = primary.getAttribute('data-popover');
      if (dp) clone.setAttribute('data-popover', dp);
      clone.classList.add('is-pinned', 'popover-clone');
      clone.style.position = 'absolute';
      clone.style.visibility = 'hidden';
      // Render at (0,0) to measure, then clamp to viewport.  Pinning adds padding-top
      // for the tools, but we don't want the content's visual position to shift, so
      // we shift up by POPOVER_PIN_TOP_SHIFT_PX after clamping.
      clone.style.left = '0px';
      clone.style.top  = '0px';
      clone.style.display = 'block';
      // body wrapper — CSS target for collapse mode.  Wraps flat text + <br> in a single element.
      var body = document.createElement('div');
      body.className = 'popover-body';
      body.innerHTML = html;
      clone.appendChild(body);
      // Self-unpin callback the global ESC handler invokes for LIFO close.
      // Mirrors what the close-button does so map state stays consistent.
      clone._popoverUnpin = function(){
        clone.remove();
        pins.delete(trigger);
      };
      var tools = buildTools(clone, clone._popoverUnpin, titleFromTrigger(trigger));
      clone.appendChild(tools);
      document.body.appendChild(clone);
      // Bring this clone to the front whenever the user interacts with it,
      // so a stack of pinned popovers behaves like a stack of windows.
      attachRaiseOnFocus(clone);
      // Now that the clone is in the DOM with content + tools, measure + clamp.
      var rect = clone.getBoundingClientRect();
      var pos = clampToViewport(x, y, rect.width, rect.height);
      // Shift up by tools padding so the content lands where the hover popover was.
      clone.style.left = pos.x + 'px';
      clone.style.top  = (pos.y - window.POPOVER_PIN_TOP_SHIFT_PX) + 'px';
      clone.style.visibility = '';
      return clone;
    }
    return {
      showHover: function(html, x, y){ showAt(primary, html, x, y); },
      hideHover: function(){ primary.style.display = 'none'; },
      hasPinFor: function(trigger){
        var c = pins.get(trigger);
        if (c && c.isConnected) return true;
        if (c) pins.delete(trigger);
        return false;
      },
      handleClick: function(html, x, y, trigger){
        var existing = pins.get(trigger);
        if (existing && existing.isConnected){
          // unpin: remove the clone and, assuming we're still over the same trigger, re-show the
          // primary popover in the hover state (= auto-dismisses on mouseleave).  "click again =
          // fully close" makes the pinned -> hover return awkward UX-wise, so we behave as
          // "click again = unpin only".
          existing.remove(); pins.delete(trigger);
          if (html) showAt(primary, html, x, y);
          return;
        }
        if (existing) pins.delete(trigger);
        var clone = makeClone(html, x, y, trigger);
        pins.set(trigger, clone);
        primary.style.display = 'none';
      }
    };
  }
  // ESC closes pinned popovers LIFO: each press peels off the most recently
  // opened clone, so users can incrementally walk back through a stack of
  // pinned helps without nuking the whole working set with one keystroke.
  // Each clone carries a _popoverUnpin callback (set by makeClone /
  // installInfoTipPinning) that also cleans up the install()'s pins Map or
  // the info-tip's pinned class -- the handler just invokes it.
  document.addEventListener('keydown', function(e){
    if (e.key !== 'Escape') return;
    var clones = document.querySelectorAll('.popover-clone');
    if (clones.length === 0){
      // Edge case: a transient .pinned class lingers without a body-level
      // clone (e.g. inline-only popovers).  Clean it so ESC still feels
      // responsive.
      document.querySelectorAll('.info-tip.pinned').forEach(function(t){
        t.classList.remove('pinned');
      });
      return;
    }
    var last = clones[clones.length - 1];
    if (typeof last._popoverUnpin === 'function'){
      last._popoverUnpin();
    } else {
      last.remove();
    }
    // Don't bubble so a higher-level ESC binding (= future modal close,
    // search-bar dismiss, etc.) doesn't also fire on the same press.
    e.preventDefault();
    e.stopPropagation();
  });
  return { install: install };
})();

// shared wrapper that makes info-tip-family elements pinnable (= settings' `?` ball / help
// buttons elsewhere).  Click toggles .info-tip.pinned + extracts the .info-popup into a
// body-level clone and adds drag/collapse tools.  The primary info-popup keeps using its
// existing CSS shown via .info-tip:hover (= the clone is a separate absolute element).
//
// usage: auto-wires .info-tip elements with the data-pinnable attribute.  Designed to coexist
// with pages whose existing hover/click logic already toggles .pinned (e.g. settings.html).
window.installInfoTipPinning = window.installInfoTipPinning || function(root){
  root = root || document;
  var tips = root.querySelectorAll('.info-tip');
  tips.forEach(function(tip){
    if (tip.dataset.pinWired === '1') return;
    tip.dataset.pinWired = '1';
    tip.addEventListener('click', function(e){
      // let clicks on links / child elements inside the popup through.  Only the tip ball itself toggles the pin.
      if (e.target !== tip && !e.target.classList.contains('info-popup')) {
        if (e.target.closest('.info-popup')) return;
      }
      e.preventDefault(); e.stopPropagation();
      var existing = tip._pinClone;
      if (existing && existing.isConnected){
        existing.remove(); tip._pinClone = null;
        tip.classList.remove('pinned');
        // blur the tip.  Without this, :focus CSS re-shows the inline popup,
        // which reads as "click doesn't dismiss it" (= fixes a user-reported bug).
        if (typeof tip.blur === 'function') tip.blur();
        return;
      }
      var popup = tip.querySelector('.info-popup');
      if (!popup) return;
      var rect = tip.getBoundingClientRect();
      var x = rect.left + window.scrollX;
      // the hover popup sits at tip.bottom + 4px.  The pinned clone adds padding-top for the tools,
      // so shift up by the tools size to keep the content's visual position unchanged.
      var y = rect.bottom + window.scrollY + 4 - window.POPOVER_PIN_TOP_SHIFT_PX;

      var clone = document.createElement('div');
      clone.classList.add('info-popup', 'info-popup-pinned', 'popover-clone', 'is-pinned');
      clone.setAttribute('data-popover', 'info');
      clone.style.position = 'absolute';
      clone.style.left = x + 'px';
      clone.style.top  = y + 'px';
      clone.style.display = 'block';
      var body = document.createElement('div');
      body.className = 'popover-body';
      body.innerHTML = popup.innerHTML;
      clone.appendChild(body);
      // tools = Windows-style title bar (= full-width strip, drag region on
      // the bar itself, collapse + close at the right).  Mirrors the bar
      // built by popoverPin.buildTools so behavior and styling stay shared.
      var tools = (function(){
        var t = document.createElement('div');
        t.className = 'popover-tools';
        if (typeof window._popoverAttachDragToBar === 'function'){
          window._popoverAttachDragToBar(t, clone);
        }
        // Title from the nearest labelling context -- same precedence as the
        // popoverPin flavor so stacked pins behave identically.
        var anchor = tip.closest && tip.closest(
          'h1,h2,h3,h4,h5,h6, legend, th, label, ' +
          '.field-label, .field, .bcd-card'
        );
        var titleText = '';
        if (anchor && typeof window._popoverExtractVisibleText === 'function'){
          titleText = window._popoverExtractVisibleText(anchor);
        }
        if (typeof window._popoverCapTitle === 'function'){
          titleText = window._popoverCapTitle(titleText);
        }
        if (titleText){
          var ti = document.createElement('span');
          ti.className = 'popover-title';
          ti.textContent = titleText;
          t.appendChild(ti);
        }
        function btn(cls, label, _unused_title, text, handler){
          var b = document.createElement('button');
          b.type = 'button'; b.className = cls;
          b.setAttribute('aria-label', label); b.textContent = text;
          b.addEventListener('click', handler);
          return b;
        }
        // copy-to-clipboard (= shares the helper from popoverPin so behavior /
        // visual feedback match across both pinning flavors).
        var cp = btn('popover-copy', 'copy', 'copy contents to clipboard', '⧉', function(e){
          e.preventDefault(); e.stopPropagation();
          if (typeof window._popoverCopyCloneBody === 'function'){
            window._popoverCopyCloneBody(clone, cp);
          }
        });
        t.appendChild(cp);
        // collapse.  Title-bar double-click below shares the toggle so the
        // glyph stays in sync whichever path fired it.  Width is frozen on
        // collapse so the bar keeps its current horizontal footprint -- same
        // pattern as the popoverPin flavor.
        function toggleCollapse(){
          var willCollapse = !clone.classList.contains('popover-collapsed');
          if (willCollapse){
            clone.style.width = clone.getBoundingClientRect().width + 'px';
          } else {
            clone.style.width = '';
          }
          var on = clone.classList.toggle('popover-collapsed');
          col.textContent = on ? '▸' : '▾';
        }
        var col = btn('popover-collapse', 'collapse',
          'toggle one-line / full (double-click title bar also works)',
          '▾',
          function(e){ e.preventDefault(); e.stopPropagation(); toggleCollapse(); }
        );
        t.appendChild(col);
        t.addEventListener('dblclick', function(e){
          if (e.target.closest('button')) return;
          e.preventDefault();
          toggleCollapse();
        });
        // close.  Defer to the shared _popoverUnpin callback so click and ESC
        // run the same teardown (= clone DOM remove + tip state reset).
        var cl = btn('popover-close', 'close', 'close', '×', function(e){
          e.preventDefault(); e.stopPropagation();
          if (typeof clone._popoverUnpin === 'function') clone._popoverUnpin();
        });
        t.appendChild(cl);
        return t;
      })();
      // ESC handler in popoverPin invokes this to peel pinned info-tip clones
      // off in LIFO order.  Mirrors the close-button logic.
      clone._popoverUnpin = function(){
        clone.remove();
        tip._pinClone = null;
        tip.classList.remove('pinned');
        if (typeof tip.blur === 'function') tip.blur();
      };
      clone.appendChild(tools);
      document.body.appendChild(clone);
      if (typeof window._popoverAttachRaiseOnFocus === 'function'){
        window._popoverAttachRaiseOnFocus(clone);
      }
      // Edge-aware reposition: measure now that the clone is in the DOM, then
      // clamp so it doesn't overflow.  We pass the trigger's rect (= original
      // anchor) so the clamp can flip above if there's no room below.
      if (window.popoverClampToViewport) {
        var clrect = clone.getBoundingClientRect();
        var pos = window.popoverClampToViewport(
          rect.left + window.scrollX - 12,   // popoverClampToViewport adds +12 internally
          rect.bottom + window.scrollY + 4 - 12,
          clrect.width, clrect.height);
        clone.style.left = pos.x + 'px';
        clone.style.top  = (pos.y - window.POPOVER_PIN_TOP_SHIFT_PX) + 'px';
      }
      tip._pinClone = clone;
      tip.classList.add('pinned');
    });
  });
};

// Edge-aware positioning for the inline hover .info-popup.  Without this,
// tips near the right or bottom of the viewport show their popups clipped
// (= cut off) or pushed off-screen.  We listen on the capture phase so the
// flip classes land before the :hover style transition is painted.
//
//   .info-popup-flip-x : popup would overflow right → anchor on the right edge instead
//   .info-popup-flip-y : popup would overflow bottom → anchor above the tip instead
//
// Measurement happens with visibility:hidden + display:block to avoid a flash;
// classes are reset on mouseleave / focusout so the same tip can re-evaluate
// on the next interaction (= viewport / page scroll may have moved it).
window.installInfoPopupEdgeFlip = window.installInfoPopupEdgeFlip || function(){
  function position(tip){
    var popup = tip.querySelector(':scope > .info-popup');
    if (!popup) return;
    popup.classList.remove('info-popup-flip-x', 'info-popup-flip-y');
    // measure without showing
    var prevVis = popup.style.visibility;
    var prevDis = popup.style.display;
    popup.style.visibility = 'hidden';
    popup.style.display = 'block';
    var tipR = tip.getBoundingClientRect();
    var popR = popup.getBoundingClientRect();
    var vw = document.documentElement.clientWidth;
    var vh = document.documentElement.clientHeight;
    // horizontal: popup anchored at tip.left.  Overflow if right edge spills past vw.
    if (tipR.left + popR.width > vw - 8) {
      popup.classList.add('info-popup-flip-x');
    }
    // vertical: popup anchored at tip.bottom + 30% of tip height.  Overflow if popup
    // bottom spills past vh.
    var popTop = tipR.bottom + tipR.height * 0.3;
    if (popTop + popR.height > vh - 8) {
      popup.classList.add('info-popup-flip-y');
    }
    popup.style.visibility = prevVis;
    popup.style.display = prevDis;
  }
  // capture so the class lands before :hover paint
  document.addEventListener('mouseenter', function(e){
    var t = e.target;
    if (t && t.nodeType === 1 && t.classList && t.classList.contains('info-tip')) position(t);
  }, true);
  document.addEventListener('focusin', function(e){
    var t = e.target;
    if (t && t.closest) {
      var tip = t.closest('.info-tip');
      if (tip) position(tip);
    }
  });
};

// auto-wire on DOMContentLoaded (= any page with an info-tip becomes pinnable automatically).
document.addEventListener('DOMContentLoaded', function(){
  if (window.installInfoTipPinning) window.installInfoTipPinning();
  if (window.installInfoPopupEdgeFlip) window.installInfoPopupEdgeFlip();
});
