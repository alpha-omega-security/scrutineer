package web

import (
	"fmt"
	"html/template"
	"net/http"
	"regexp"
	"strconv"
	"strings"

	"scrutineer/internal/db"
)

// Inline styles for the tags Gmail keeps when rendered HTML is pasted into a
// compose window. Gmail strips <style> blocks on paste, so every visual
// affordance the disclosure draft needs — monospace code, code blocks, bold,
// quotes, links — has to ride on a style= attribute on the tag itself.
const (
	styleInlineCode = "font-family:monospace;background:#f0f0f0;padding:1px 4px;border-radius:3px"
	styleCodeBlock  = "font-family:monospace;background:#f6f8fa;padding:12px;border-radius:6px;white-space:pre;overflow-x:auto"
	styleStrong     = "font-weight:600"
	styleBlockquote = "border-left:4px solid #d0d7de;margin:0;padding-left:12px;color:#57606a"
	styleLink       = "color:#0969da"
)

var codeBlockOpen = regexp.MustCompile(`<pre><code[^>]*>`)

// inlineGmailStyles rewrites goldmark's output so the formatting survives a
// paste into Gmail. Code blocks are collapsed to a single styled <pre> (the
// nested <code> is dropped so the block doesn't get a box-in-a-box), then the
// remaining standalone <code> become inline spans. Order matters: the block
// pass must run before the inline <code> pass.
func inlineGmailStyles(h string) string {
	h = codeBlockOpen.ReplaceAllString(h, `<pre style="`+styleCodeBlock+`">`)
	h = strings.ReplaceAll(h, "</code></pre>", "</pre>")
	return strings.NewReplacer(
		"<code>", `<code style="`+styleInlineCode+`">`,
		"<strong>", `<strong style="`+styleStrong+`">`,
		"<blockquote>", `<blockquote style="`+styleBlockquote+`">`,
		"<a href=", `<a style="`+styleLink+`" href=`,
	).Replace(h)
}

const disclosureHTMLPage = `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>%s</title>
</head>
<body style="font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;font-size:14px;line-height:1.5;color:#1f2328;max-width:760px;margin:24px auto;padding:0 16px">
%s
</body>
</html>
`

// findingDisclosureHTML serves the finding's disclosure draft as a standalone
// HTML page with inline styles, so an analyst can select-all and paste it into
// a Gmail compose window with the formatting intact. It is the fallback
// for projects without private vulnerability reporting, where the draft goes
// out as a plain email body rather than a GitHub advisory.
func (s *Server) findingDisclosureHTML(w http.ResponseWriter, r *http.Request) {
	var f db.Finding
	id, err := strconv.Atoi(r.PathValue("id"))
	if err != nil {
		http.NotFound(w, r)
		return
	}
	if err := s.DB.First(&f, id).Error; err != nil {
		http.NotFound(w, r)
		return
	}
	draft := strings.TrimSpace(f.DisclosureDraft)
	if draft == "" {
		http.Error(w, "no disclosure draft stored for this finding", http.StatusNotFound)
		return
	}

	body := inlineGmailStyles(string(renderMarkdown(draft)))
	// Prepend a To: line from the suggested recipients: this page is the
	// PVR-less fallback where the draft goes out as a plain email, so the
	// analyst needs to see who to send it to right above the body.
	if rec := strings.TrimSpace(f.SuggestedRecipients); rec != "" {
		body = fmt.Sprintf(`<p style="margin:0 0 16px"><strong style="%s">To:</strong> %s</p>`,
			styleStrong, template.HTMLEscapeString(rec)) + body
	}
	title := template.HTMLEscapeString(fmt.Sprintf("Disclosure draft — finding #%d: %s", f.ID, f.Title))
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = fmt.Fprintf(w, disclosureHTMLPage, title, body)
}
