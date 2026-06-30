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

  function restoreTab() {
    var h = location.hash.slice(1);
    if (!h) return;
    var tab = document.getElementById(h);
    if (!tab || tab.getAttribute('role') !== 'tab') return;
    var list = tab.closest('[role="tablist"]');
    if (!list) return;
    list.querySelectorAll('[role="tab"]').forEach(function (t) {
      var sel = t.id === h;
      t.setAttribute('aria-selected', sel);
      var p = document.getElementById(t.getAttribute('aria-controls'));
      if (p) p.hidden = !sel;
    });
  }

  function init() {
    icons();
    highlight();
    restoreTab();
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

    var tab = e.target.closest('[role="tab"]');
    if (tab && tab.id) history.replaceState(null, '', '#' + tab.id);

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
