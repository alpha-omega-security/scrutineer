package ingest

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"

	"github.com/git-pkgs/sarif"
)

func parseSARIF(data []byte) ([]Result, error) {
	f, err := sarif.Parse(data)
	if err != nil {
		return nil, wrapErr(FormatSARIF, err)
	}
	if len(f.Runs) == 0 {
		return nil, wrapErr(FormatSARIF, fmt.Errorf("no runs"))
	}
	out := make([]Result, 0, len(f.Runs))
	for _, run := range f.Runs {
		out = append(out, sarifRunResult(run))
	}
	return out, nil
}

func sarifRunResult(r sarif.Run) Result {
	res := Result{Tool: r.Tool.Driver.Name}
	if res.Tool == "" {
		res.Tool = "sarif"
	}
	if len(r.VersionControlProvenance) > 0 {
		res.RepoURL = r.VersionControlProvenance[0].RepositoryURI
		res.Commit = r.VersionControlProvenance[0].RevisionID
	}
	byID := sarifRuleIndex(r)
	for _, sr := range r.Results {
		res.Findings = append(res.Findings, sarifFinding(sr, byID, r.Tool.Driver.Rules))
	}
	return res
}

// ruleIndex builds the id→rule map for the ruleId reference path.
func sarifRuleIndex(r sarif.Run) map[string]sarif.ReportingDescriptor {
	m := make(map[string]sarif.ReportingDescriptor, len(r.Tool.Driver.Rules))
	for _, rule := range r.Tool.Driver.Rules {
		m[rule.ID] = rule
	}
	return m
}

// SARIF lets a result reference its rule by ruleId, by ruleIndex into
// tool.driver.rules, or both. Some emitters set only ruleIndex, so
// fall back to it when ruleId yields nothing.
func sarifFinding(sr sarif.Result, byID map[string]sarif.ReportingDescriptor, rules []sarif.ReportingDescriptor) Finding {
	rule, ok := byID[sr.RuleID]
	if !ok && sr.RuleIndex >= 0 && sr.RuleIndex < len(rules) {
		rule = rules[sr.RuleIndex]
	}
	f := Finding{
		RuleID:      sr.RuleID,
		Title:       firstNonEmpty(rule.ShortDescription.Text, rule.Name, sr.Message.Text, sr.RuleID),
		Description: firstNonEmpty(sr.Message.Text, rule.FullDescription.Text),
		Severity:    sarifSeverity(sr.Level, sarifPropertyString(rule.Properties, "security-severity")),
		Confidence:  sarifConfidence(sarifPropertyString(rule.Properties, "precision")),
		CWE:         cweFromTags(sarifPropertyStrings(rule.Properties, "tags")),
		Location:    sarifLocation(sr),
	}
	if len(sr.Fixes) > 0 {
		f.SuggestedFix = sr.Fixes[0].Description.Text
	}
	return f
}

func sarifLocation(sr sarif.Result) string {
	if len(sr.Locations) == 0 {
		return ""
	}
	pl := sr.Locations[0].PhysicalLocation
	loc := pl.ArtifactLocation.URI
	if loc == "" {
		return ""
	}
	if pl.Region.StartLine > 0 {
		loc += ":" + strconv.Itoa(pl.Region.StartLine)
		if pl.Region.StartColumn > 0 {
			loc += ":" + strconv.Itoa(pl.Region.StartColumn)
		}
	}
	return loc
}

func sarifPropertyString(props sarif.PropertyBag, key string) string {
	switch v := props[key].(type) {
	case string:
		return v
	case fmt.Stringer:
		return v.String()
	case float64:
		return strconv.FormatFloat(v, 'f', -1, 64)
	case int:
		return strconv.Itoa(v)
	default:
		return ""
	}
}

func sarifPropertyStrings(props sarif.PropertyBag, key string) []string {
	switch v := props[key].(type) {
	case []string:
		return v
	case []any:
		out := make([]string, 0, len(v))
		for _, item := range v {
			if s, ok := item.(string); ok {
				out = append(out, s)
			}
		}
		return out
	case string:
		return []string{v}
	default:
		return nil
	}
}

// CVSS v3 qualitative-severity boundaries (FIRST.org spec table 14).
const (
	cvssCritical = 9.0
	cvssHigh     = 7.0
	cvssMedium   = 4.0
)

// sarifSeverity maps a result.level plus the GitHub-convention
// properties.security-severity score onto scrutineer's
// critical/high/medium/low scale. The numeric score wins when present
// because level is often left at the tool default.
func sarifSeverity(level, score string) string {
	if s, err := strconv.ParseFloat(score, 64); err == nil {
		switch {
		case s >= cvssCritical:
			return "Critical"
		case s >= cvssHigh:
			return "High"
		case s >= cvssMedium:
			return "Medium"
		case s > 0:
			return "Low"
		}
	}
	switch strings.ToLower(level) {
	case "error":
		return "High"
	case "warning":
		return "Medium"
	case "note", "none":
		return "Low"
	}
	return ""
}

// sarifConfidence maps SARIF properties.precision onto scrutineer's
// high/medium/low. Absent precision means the source did not say, so
// leave it empty and let the handler default it.
func sarifConfidence(precision string) string {
	switch strings.ToLower(precision) {
	case "very-high", "high":
		return "high"
	case "medium":
		return "medium"
	case "low":
		return "low"
	}
	return ""
}

var cweRe = regexp.MustCompile(`(?i)\bcwe[-/ ]?(\d{1,5})\b`)

// cweFromTags extracts a single CWE id from SARIF rule tags. CodeQL
// emits "external/cwe/cwe-079", other tools emit "CWE-79"; both match.
func cweFromTags(tags []string) string {
	for _, t := range tags {
		if m := cweRe.FindStringSubmatch(t); m != nil {
			return "CWE-" + strings.TrimLeft(m[1], "0")
		}
	}
	return ""
}

func firstNonEmpty(ss ...string) string {
	for _, s := range ss {
		if s = strings.TrimSpace(s); s != "" {
			return s
		}
	}
	return ""
}
