package web

import (
	"bytes"
	"html/template"
	"strings"

	"github.com/yuin/goldmark/v2/extension"
	"github.com/yuin/goldmark/v2/parser"
	"github.com/yuin/goldmark/v2/renderer/html"
)

var mdParser = parser.New(parser.WithExtensions(extension.NewGFMParser()))
var mdRenderer = html.New(html.WithExtensions(extension.NewGFMHTMLRenderer()))

func renderMarkdown(src string) template.HTML {
	var buf bytes.Buffer
	source := []byte(src)
	if err := mdRenderer.Render(&buf, source, mdParser.Parse(source)); err != nil {
		return template.HTML("<pre>" + template.HTMLEscapeString(src) + "</pre>")
	}
	return template.HTML(buf.String()) //nolint:gosec
}

// unmark drops the delimiters of markdown code spans from a one-line excerpt,
// which is shown as escaped text so tags the excerpt names stay visible. A span
// opened by N backticks closes on the next run of exactly N, so a backtick inside
// a double-backtick span is part of the text and stays, as does an unclosed run.
// A backtick after an odd number of backslashes is escaped and cannot open a span,
// while inside a span a backslash escapes nothing.
func unmark(s string) string {
	var b strings.Builder
	for {
		i := strings.IndexByte(s, '`')
		if i < 0 {
			b.WriteString(s)
			return b.String()
		}
		if p := s[:i]; (len(p)-len(strings.TrimRight(p, "\\")))%2 == 1 {
			b.WriteString(s[:i+1])
			s = s[i+1:]
			continue
		}
		b.WriteString(s[:i])
		n := backtickRun(s[i:])
		open, rest := s[i:i+n], s[i+n:]
		end := closingRun(rest, n)
		if end < 0 {
			b.WriteString(open)
			s = rest
			continue
		}
		code := rest[:end]
		if len(code) > 1 && code[0] == ' ' && code[len(code)-1] == ' ' && strings.Trim(code, " ") != "" {
			code = code[1 : len(code)-1]
		}
		b.WriteString(code)
		s = rest[end+n:]
	}
}

func backtickRun(s string) int { return len(s) - len(strings.TrimLeft(s, "`")) }

// closingRun returns the offset of the first run of exactly n backticks in s,
// or -1 when there is none.
func closingRun(s string, n int) int {
	for off := 0; ; {
		i := strings.IndexByte(s[off:], '`')
		if i < 0 {
			return -1
		}
		off += i
		m := backtickRun(s[off:])
		if m == n {
			return off
		}
		off += m
	}
}
