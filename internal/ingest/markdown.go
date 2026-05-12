package ingest

import (
	"bytes"
	"fmt"
	"regexp"
	"strings"
)

// Findings-markdown export shape: each finding is an H1 title followed
// by H2 sections (Details, Location, Impact, Reproduction steps,
// Recommended fix) and a fenced metadata block of "**Key:** value"
// lines between two "---" rules. Findings are separated by the closing
// rule of the previous metadata block.

func isFindingsMarkdown(data []byte) bool {
	return bytes.HasPrefix(bytes.TrimSpace(data), []byte("# ")) &&
		mdMetaRe.Match(data) &&
		bytes.Contains(data, []byte("\n## "))
}

var (
	mdH1Re       = regexp.MustCompile(`(?m)^# +(.+)$`)
	mdH2Re       = regexp.MustCompile(`(?m)^## +(.+)$`)
	mdMetaRe     = regexp.MustCompile(`(?m)^\*\*([A-Za-z ]+):\*\* *(.*)$`)
	mdLocationRe = regexp.MustCompile(`\[([^\]]+)\]\(([^)]+)\)`)
	mdRepoURLRe  = regexp.MustCompile(`^(https?://[^/]+/[^/]+/[^/]+)/`)
)

func parseMarkdown(data []byte) ([]Result, error) {
	text := strings.ReplaceAll(string(bytes.TrimSpace(data)), "\r\n", "\n")
	h1s := mdH1Re.FindAllStringIndex(text, -1)
	if len(h1s) == 0 {
		return nil, wrapErr(FormatMarkdown, fmt.Errorf("no H1 headings"))
	}

	type entry struct {
		repoURL string
		f       Finding
	}
	var entries []entry
	for i, m := range h1s {
		end := len(text)
		if i+1 < len(h1s) {
			end = h1s[i+1][0]
		}
		title := strings.TrimSpace(mdH1Re.FindStringSubmatch(text[m[0]:m[1]])[1])
		body := text[m[1]:end]
		sections, meta := splitMarkdownFinding(body)

		loc, repoURL := parseMarkdownLocation(sections["Location"])
		if repoURL == "" {
			repoURL = expandRepoSlug(meta["Repository"])
		}
		entries = append(entries, entry{
			repoURL: repoURL,
			f: Finding{
				Title:        title,
				Description:  buildMarkdownDescription(sections),
				Severity:     normaliseSeverity(meta["Severity"]),
				CWE:          normaliseCWE(meta["CWE"]),
				Location:     loc,
				SuggestedFix: strings.TrimSpace(sections["Recommended fix"]),
			},
		})
	}

	byRepo := map[string]*Result{}
	var order []string
	for _, e := range entries {
		res, ok := byRepo[e.repoURL]
		if !ok {
			res = &Result{RepoURL: e.repoURL, Tool: string(FormatMarkdown)}
			byRepo[e.repoURL] = res
			order = append(order, e.repoURL)
		}
		res.Findings = append(res.Findings, e.f)
	}
	out := make([]Result, 0, len(order))
	for _, k := range order {
		out = append(out, *byRepo[k])
	}
	return out, nil
}

// splitMarkdownFinding separates a single finding's body into its H2
// sections and the **Key:** metadata block. The metadata block sits
// between two --- rules; everything before the first rule is sections.
func splitMarkdownFinding(body string) (sections, meta map[string]string) {
	sections = map[string]string{}
	meta = map[string]string{}
	content, metaPart, _ := strings.Cut(body, "\n---\n")
	h2s := mdH2Re.FindAllStringSubmatchIndex(content, -1)
	for i, m := range h2s {
		end := len(content)
		if i+1 < len(h2s) {
			end = h2s[i+1][0]
		}
		name := strings.TrimSpace(content[m[2]:m[3]])
		sections[name] = strings.TrimSpace(content[m[1]:end])
	}
	for _, m := range mdMetaRe.FindAllStringSubmatch(metaPart, -1) {
		meta[strings.TrimSpace(m[1])] = strings.TrimSpace(m[2])
	}
	return sections, meta
}

// parseMarkdownLocation extracts "file:line" and, when the link target
// is a forge blob URL, the bare repository URL.
func parseMarkdownLocation(s string) (loc, repoURL string) {
	m := mdLocationRe.FindStringSubmatch(s)
	if m == nil {
		return strings.TrimSpace(s), ""
	}
	loc = strings.TrimSpace(m[1])
	if rm := mdRepoURLRe.FindStringSubmatch(m[2]); rm != nil {
		repoURL = rm[1]
	}
	return loc, repoURL
}

func buildMarkdownDescription(sections map[string]string) string {
	var b strings.Builder
	b.WriteString(sections["Details"])
	for _, h := range []string{"Impact", "Reproduction steps"} {
		if v := strings.TrimSpace(sections[h]); v != "" {
			b.WriteString("\n\n## ")
			b.WriteString(h)
			b.WriteString("\n")
			b.WriteString(v)
		}
	}
	return strings.TrimSpace(b.String())
}
