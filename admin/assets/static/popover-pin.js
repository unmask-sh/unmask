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
  function install(primary){
    var pins = new Map();
    function showAt(p, html, x, y){
      p.innerHTML = html;
      p.style.left = (x + 12) + 'px';
      p.style.top  = (y + 12) + 'px';
      p.style.display = 'block';
    }
    function makeClone(html, x, y, trigger){
      var clone = document.createElement('div');
      var dp = primary.getAttribute('data-popover');
      if (dp) clone.setAttribute('data-popover', dp);
      clone.classList.add('is-pinned', 'popover-clone');
      clone.style.position = 'absolute';
      clone.style.left = (x + 12) + 'px';
      // the hover popover (= primary) was shown at (x+12, y+12).  Pinning adds padding-top for the
      // tools, but we don't want the content's visual position to shift, so offset the clone's top
      // upward by the tools size (= POPOVER_PIN_TOP_SHIFT_PX).
      clone.style.top  = (y + 12 - window.POPOVER_PIN_TOP_SHIFT_PX) + 'px';
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
      tip._pinClone = clone;
      tip.classList.add('pinned');
    });
  });
};

// auto-wire on DOMContentLoaded (= any page with an info-tip becomes pinnable automatically).
document.addEventListener('DOMContentLoaded', function(){
  if (window.installInfoTipPinning) window.installInfoTipPinning();
});
