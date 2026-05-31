(function () {
  var scheme = (document.cookie.match(/(?:^|; )color_scheme=(\w+)/) || [])[1] || 'system';
  var mq = matchMedia('(prefers-color-scheme: dark)');
  var isDark = function () {
    return scheme === 'dark' || (scheme === 'system' && mq.matches);
  };
  // Toggle the .dark class before first paint to avoid a flash of the
  // light theme.
  var applyClass = function () {
    document.documentElement.classList.toggle('dark', isDark());
  };
  // The hljs light/dark stylesheets are declared later in <head>, so they
  // do not exist yet on this first synchronous run. Enable the right one
  // once they are in the DOM, otherwise the light theme stays active in
  // dark mode and code renders dark-on-dark.
  var applyHljs = function () {
    var dark = isDark();
    var hl = document.getElementById('hljs-light');
    var hd = document.getElementById('hljs-dark');
    if (hl) hl.disabled = dark;
    if (hd) hd.disabled = !dark;
  };
  var apply = function () {
    applyClass();
    applyHljs();
  };
  applyClass();
  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', applyHljs);
  } else {
    applyHljs();
  }
  mq.addEventListener('change', apply);
})();
