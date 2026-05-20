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
  function buildTools(clone, onClose){
    var tools = document.createElement('div');
    tools.className = 'popover-tools';
    // drag handle
    var drag = document.createElement('button');
    drag.type = 'button';
    drag.className = 'popover-drag';
    drag.setAttribute('aria-label', 'drag');
    drag.title = 'drag to move';
    drag.textContent = '⠿';
    drag.addEventListener('mousedown', function(e){
      e.preventDefault(); e.stopPropagation();
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
    tools.appendChild(drag);
    // collapse toggle
    var col = document.createElement('button');
    col.type = 'button';
    col.className = 'popover-collapse';
    col.setAttribute('aria-label', 'collapse');
    col.title = 'toggle one-line / full';
    col.textContent = '▾';
    col.addEventListener('click', function(e){
      e.preventDefault(); e.stopPropagation();
      var on = clone.classList.toggle('popover-collapsed');
      col.textContent = on ? '▸' : '▾';
    });
    tools.appendChild(col);
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
      var tools = buildTools(clone, function(){
        clone.remove(); pins.delete(trigger);
      });
      clone.appendChild(tools);
      document.body.appendChild(clone);
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
  document.addEventListener('keydown', function(e){
    if (e.key === 'Escape'){
      document.querySelectorAll('.popover-clone').forEach(function(p){ p.remove(); });
      document.querySelectorAll('.info-tip.pinned').forEach(function(t){
        t.classList.remove('pinned');
      });
    }
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
      // tools (= drag / collapse / close)
      var pinHelper = window.popoverPin && window.popoverPin.install
        ? window.popoverPin.install(popup) : null;
      // build the tools directly (= popoverPin.install builds clones via primary, so for info-tip
      // we go through a different path: create the clone separately and just attach the tools).
      var tools = (function(){
        var t = document.createElement('div');
        t.className = 'popover-tools';
        function btn(cls, label, title, text, handler){
          var b = document.createElement('button');
          b.type = 'button'; b.className = cls;
          b.setAttribute('aria-label', label); b.title = title; b.textContent = text;
          b.addEventListener('click', handler);
          return b;
        }
        // drag
        var dr = btn('popover-drag', 'drag', 'drag to move', '⠿', function(e){});
        dr.addEventListener('mousedown', function(e){
          e.preventDefault(); e.stopPropagation();
          var rect2 = clone.getBoundingClientRect();
          var sx = e.clientX, sy = e.clientY;
          var ox = rect2.left + window.scrollX, oy = rect2.top + window.scrollY;
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
        t.appendChild(dr);
        // collapse
        var col = btn('popover-collapse', 'collapse', 'toggle one-line / full', '▾', function(e){
          e.preventDefault(); e.stopPropagation();
          var on = clone.classList.toggle('popover-collapsed');
          col.textContent = on ? '▸' : '▾';
        });
        t.appendChild(col);
        // close
        var cl = btn('popover-close', 'close', '', '×', function(e){
          e.preventDefault(); e.stopPropagation();
          clone.remove(); tip._pinClone = null;
          tip.classList.remove('pinned');
        });
        t.appendChild(cl);
        return t;
      })();
      clone.appendChild(tools);
      document.body.appendChild(clone);
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
