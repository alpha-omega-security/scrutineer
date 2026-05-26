(function () {
  'use strict';

  var code = document.getElementById('blob');
  if (!code) return;
  if (window.hljs && !code.classList.contains('hljs')) {
    hljs.highlightElement(code);
  }

  // hljs may emit one <span> covering multiple source lines (raw strings,
  // multi-line comments). Splitting innerHTML on '\n' to wrap each line
  // would leave such spans open and the browser nests every subsequent
  // .hl-line inside them, accumulating padding-left on each line.
  var html = balanceSpansAtNewlines(code.innerHTML);
  var lines = html.split('\n').map(function (line, i) {
    var n = i + 1;
    return '<span class="hl-line" id="L' + n + '"><span class="hl-num">' + n + '</span>' + line + '</span>';
  });
  code.innerHTML = lines.join('\n');

  var wrap = code.parentElement.parentElement;
  var from = parseInt(wrap.getAttribute('data-hl-from'), 10) || 0;
  var to = parseInt(wrap.getAttribute('data-hl-to'), 10) || 0;
  if (from > 0) {
    for (var i = from; i <= to; i++) {
      var el = document.getElementById('L' + i);
      if (el) { el.classList.add('hl-on'); }
    }
    var anchor = document.getElementById('L' + from);
    if (anchor) { anchor.scrollIntoView({ block: 'center' }); }
  }

  function balanceSpansAtNewlines(s) {
    var out = '';
    var stack = [];
    var i = 0;
    while (i < s.length) {
      var c = s.charAt(i);
      if (c === '<') {
        var end = s.indexOf('>', i);
        if (end === -1) {
          out += s.substring(i);
          break;
        }
        var tag = s.substring(i, end + 1);
        if (tag.charAt(1) === '/') {
          out += tag;
          stack.pop();
        } else {
          out += tag;
          stack.push(tag);
        }
        i = end + 1;
      } else if (c === '\n') {
        for (var j = stack.length - 1; j >= 0; j--) {
          out += '</span>';
        }
        out += '\n';
        for (var k = 0; k < stack.length; k++) {
          out += stack[k];
        }
        i++;
      } else {
        out += c;
        i++;
      }
    }
    return out;
  }
})();
