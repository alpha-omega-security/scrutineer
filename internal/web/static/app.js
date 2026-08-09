(function () {
  'use strict';

  function icons() {
    // Icons are decorative: every interactive control has visible text or an
    // aria-label, so hide the generated SVGs from assistive tech to avoid noise.
    if (window.lucide) {
      lucide.createIcons({ attrs: { 'aria-hidden': 'true', focusable: 'false' } });
    }
  }

  function highlight() {
    if (window.hljs) {
      document.querySelectorAll('pre code:not(.hljs)').forEach(function (el) {
        hljs.highlightElement(el);
      });
    }
  }

  // A panel can be opened from a tab in the tablist or from an entry in an
  // overflow ("More") menu beside it, and a panel may hold a nested tab bar of
  // its own. Basecoat only knows about the tabs of a single tablist, so
  // selection is settled here; it runs after basecoat's own handler and
  // reconciles whatever that missed.
  function tabBar(tabs) {
    return tabs.querySelector(':scope > .tab-bar') ||
           tabs.querySelector(':scope > [role="tablist"]');
  }

  function selectTab(el) {
    var tabs = el.closest('.tabs');
    var bar = tabs && tabBar(tabs);
    if (!bar) return;
    var id = el.getAttribute('aria-controls');
    tabs.querySelectorAll(':scope > [role="tabpanel"]').forEach(function (p) {
      p.hidden = p.id !== id;
    });
    bar.querySelectorAll('[role="tab"]').forEach(function (t) {
      var sel = t === el;
      t.setAttribute('aria-selected', sel);
      t.setAttribute('tabindex', sel ? '0' : '-1');
    });
    bar.querySelectorAll('[role="menuitem"][aria-controls]').forEach(function (m) {
      if (m === el) m.setAttribute('aria-current', 'true');
      else m.removeAttribute('aria-current');
    });
    // The overflow trigger stands in for whichever of its panels is showing.
    bar.querySelectorAll('.dropdown-menu > button').forEach(function (b) {
      var owns = !!b.parentElement.querySelector('[role="menuitem"][aria-current="true"]');
      b.toggleAttribute('data-active', owns);
    });
  }

  // Deep links name a tab or menu entry by id; a nested one has to open its
  // ancestors on the way down.
  function restoreTab() {
    var h = location.hash.slice(1);
    if (!h) return;
    var el = document.getElementById(h);
    if (!el || !el.hasAttribute('aria-controls')) return;
    var role = el.getAttribute('role');
    if (role !== 'tab' && role !== 'menuitem') return;
    while (el) {
      selectTab(el);
      var tabs = el.closest('.tabs');
      var panel = tabs && tabs.parentElement && tabs.parentElement.closest('[role="tabpanel"]');
      el = panel ? document.querySelector('[aria-controls="' + panel.id + '"]') : null;
    }
  }

  // The message list is the only thing that scrolls on a conversation page, so
  // it opens on the newest message rather than on the start of the transcript.
  function chatToBottom() {
    var list = document.querySelector('.chat-messages');
    if (list) list.scrollTop = list.scrollHeight;
  }

  function init() {
    icons();
    highlight();
    restoreTab();
    chatToBottom();
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', init);
    window.addEventListener('load', restoreTab);
  } else {
    init();
  }

  document.addEventListener('htmx:afterSwap', function () { icons(); highlight(); });
  document.addEventListener('htmx:historyRestore', init);
  document.addEventListener('htmx:oobAfterSwap', function () { icons(); highlight(); });

  // Arrow keys inside a tablist are basecoat's to handle, and it selects the
  // new tab before focusing it — so reconcile from the focus that follows,
  // otherwise a panel opened from the overflow menu stays on screen alongside.
  document.addEventListener('focusin', function (e) {
    var tab = e.target.closest && e.target.closest('[role="tab"]');
    if (tab && tab.getAttribute('aria-selected') === 'true') selectTab(tab);
  });

  document.body.addEventListener('htmx:sseMessage', function (e) {
    var el = e.target.closest('[data-reload-on-sse]');
    if (el && e.detail.type === el.getAttribute('data-reload-on-sse')) location.reload();
  });

  document.addEventListener('click', function (e) {
    var copyBtn = e.target.closest('[data-copy]');
    if (copyBtn && navigator.clipboard) {
      e.preventDefault();
      navigator.clipboard.writeText(copyBtn.getAttribute('data-copy')).then(function () {
        // Flash a check for ~1s; CSS swaps the icon while data-copied is set.
        copyBtn.setAttribute('data-copied', '');
        setTimeout(function () { copyBtn.removeAttribute('data-copied'); }, 1200);
      });
      return;
    }

    var tr = e.target.closest('.table tbody tr');
    if (tr && !e.target.closest('a, button, form, input')) {
      var a = tr.querySelector('a[href]');
      if (a) { a.click(); return; }
    }

    var picker = e.target.closest('[role="tab"], [role="menuitem"][aria-controls]');
    if (picker && picker.closest('.tabs')) {
      selectTab(picker);
      if (picker.id) history.replaceState(null, '', '#' + picker.id);
    }

    if (e.target.nodeName === 'DIALOG') e.target.close();

    var closer = e.target.closest('[data-close]');
    if (closer) {
      var dlgToClose = closer.closest('dialog');
      if (dlgToClose) { e.preventDefault(); dlgToClose.close(); return; }
    }

    var dismiss = e.target.closest('[data-dismiss]');
    if (dismiss) {
      var toClear = document.getElementById(dismiss.getAttribute('data-dismiss'));
      if (toClear) { e.preventDefault(); toClear.replaceChildren(); return; }
    }

    var opener = e.target.closest('[data-dialog]');
    if (opener) {
      var dlg = document.getElementById(opener.getAttribute('data-dialog'));
      if (dlg && dlg.showModal) {
        e.preventDefault();
        var cur = opener.closest('dialog');
        if (cur) cur.close();
        dlg.showModal();
      }
    }
  });
})();
