(function () {
  var scheme = (document.cookie.match(/(?:^|; )color_scheme=(\w+)/) || [])[1] || 'system';
  var mq = matchMedia('(prefers-color-scheme: dark)');
  var apply = function () {
    var dark = scheme === 'dark' || (scheme === 'system' && mq.matches);
    document.documentElement.classList.toggle('dark', dark);
    var hl = document.getElementById('hljs-light');
    var hd = document.getElementById('hljs-dark');
    if (hl) hl.disabled = dark;
    if (hd) hd.disabled = !dark;
  };
  apply();
  mq.addEventListener('change', apply);
})();
