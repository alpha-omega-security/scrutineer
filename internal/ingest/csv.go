package ingest

import (
	"bytes"
	"encoding/csv"
	"fmt"
	"net/url"
	"strings"
)

// csvRequired is the minimal set of header columns that identifies a
// findings-CSV export. Detection requires all of these; parsing
// tolerates any superset.
var csvRequired = []string{"Severity", "Repository", "Name", "Description"}

func isFindingsCSV(data []byte) bool {
	r := csv.NewReader(bytes.NewReader(data))
	r.LazyQuotes = true
	header, err := r.Read()
	if err != nil {
		return false
	}
	cols := make(map[string]bool, len(header))
	for _, h := range header {
		cols[strings.TrimSpace(h)] = true
	}
	for _, req := range csvRequired {
		if !cols[req] {
			return false
		}
	}
	return true
}

func parseCSV(data []byte) ([]Result, error) {
	r := csv.NewReader(bytes.NewReader(bytes.TrimPrefix(data, []byte{0xef, 0xbb, 0xbf})))
	r.LazyQuotes = true
	r.FieldsPerRecord = -1
	header, err := r.Read()
	if err != nil {
		return nil, wrapErr(FormatCSV, err)
	}
	rows, err := r.ReadAll()
	if err != nil {
		return nil, wrapErr(FormatCSV, err)
	}
	idx := make(map[string]int, len(header))
	for i, h := range header {
		idx[strings.TrimSpace(h)] = i
	}
	col := func(row []string, name string) string {
		i, ok := idx[name]
		if !ok || i >= len(row) {
			return ""
		}
		return strings.TrimSpace(row[i])
	}

	byRepo := map[string]*Result{}
	var order []string
	for _, row := range rows {
		if s := col(row, "Status"); s != "" && !strings.EqualFold(s, "open") {
			continue
		}
		repo := col(row, "Repository")
		res, ok := byRepo[repo]
		if !ok {
			res = &Result{
				RepoURL: repo,
				Tool:    hostOf(col(row, "Finding URL")),
			}
			byRepo[repo] = res
			order = append(order, repo)
		}
		res.Findings = append(res.Findings, Finding{
			RuleID:      col(row, "Finding URL"),
			Title:       firstNonEmpty(col(row, "Name"), col(row, "Category")),
			Description: col(row, "Description"),
			Severity:    strings.ToLower(col(row, "Severity")),
			Confidence:  strings.ToLower(col(row, "Confidence")),
			CWE:         normaliseCWE(col(row, "CWE")),
			Location:    joinLocation(col(row, "File path"), col(row, "Line")),
		})
	}
	if len(order) == 0 {
		return nil, wrapErr(FormatCSV, fmt.Errorf("no open findings"))
	}
	out := make([]Result, 0, len(order))
	for _, repo := range order {
		out = append(out, *byRepo[repo])
	}
	return out, nil
}

func joinLocation(path, line string) string {
	if path == "" {
		return ""
	}
	if line == "" {
		return path
	}
	return path + ":" + line
}

func normaliseCWE(s string) string {
	if m := cweRe.FindStringSubmatch(s); m != nil {
		return "CWE-" + strings.TrimLeft(m[1], "0")
	}
	return ""
}

// hostOf returns the host component of raw, used as the Tool name when
// the export carries a per-finding URL but no explicit producer field.
func hostOf(raw string) string {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return string(FormatCSV)
	}
	return u.Host
}
