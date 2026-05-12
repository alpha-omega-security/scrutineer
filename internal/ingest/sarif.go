package ingest

import (
	"encoding/json"
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

// SARIF 2.1.0 subset. Only the fields scrutineer maps onto a Finding are
// declared; everything else is dropped by encoding/json. The spec is
// large and tools populate it inconsistently, so each accessor below
// tolerates absence rather than assuming a field is set.
type sarifFile struct {
	Version string     `json:"version"`
	Runs    []sarifRun `json:"runs"`
}

type sarifRun struct {
	Tool                     sarifTool     `json:"tool"`
	VersionControlProvenance []sarifVCS    `json:"versionControlProvenance"`
	Results                  []sarifResult `json:"results"`
}

type sarifTool struct {
	Driver sarifDriver `json:"driver"`
}

type sarifDriver struct {
	Name  string      `json:"name"`
	Rules []sarifRule `json:"rules"`
}

type sarifVCS struct {
	RepositoryURI string `json:"repositoryUri"`
	RevisionID    string `json:"revisionId"`
}

type sarifRule struct {
	ID               string     `json:"id"`
	Name             string     `json:"name"`
	ShortDescription sarifText  `json:"shortDescription"`
	FullDescription  sarifText  `json:"fullDescription"`
	Properties       sarifProps `json:"properties"`
}

type sarifProps struct {
	Tags             []string `json:"tags"`
	SecuritySeverity string   `json:"security-severity"`
	Precision        string   `json:"precision"`
}

type sarifResult struct {
	RuleID    string          `json:"ruleId"`
	RuleIndex *int            `json:"ruleIndex"`
	Level     string          `json:"level"`
	Message   sarifText       `json:"message"`
	Locations []sarifLocation `json:"locations"`
	Fixes     []sarifFix      `json:"fixes"`
}

type sarifText struct {
	Text string `json:"text"`
}

type sarifLocation struct {
	PhysicalLocation struct {
		ArtifactLocation struct {
			URI string `json:"uri"`
		} `json:"artifactLocation"`
		Region struct {
			StartLine   int `json:"startLine"`
			StartColumn int `json:"startColumn"`
		} `json:"region"`
	} `json:"physicalLocation"`
}

// sarifFix is the SARIF "fix" object. Real-world emitters rarely
// populate it, but when present the description is the closest thing to
// a suggested patch the format carries.
type sarifFix struct {
	Description sarifText `json:"description"`
}

func parseSARIF(data []byte) ([]Result, error) {
	var f sarifFile
	if err := json.Unmarshal(data, &f); err != nil {
		return nil, wrapErr(FormatSARIF, err)
	}
	if len(f.Runs) == 0 {
		return nil, wrapErr(FormatSARIF, fmt.Errorf("no runs"))
	}
	out := make([]Result, 0, len(f.Runs))
	for _, run := range f.Runs {
		out = append(out, run.result())
	}
	return out, nil
}

func (r sarifRun) result() Result {
	res := Result{Tool: r.Tool.Driver.Name}
	if res.Tool == "" {
		res.Tool = "sarif"
	}
	if len(r.VersionControlProvenance) > 0 {
		res.RepoURL = r.VersionControlProvenance[0].RepositoryURI
		res.Commit = r.VersionControlProvenance[0].RevisionID
	}
	byID := r.ruleIndex()
	for _, sr := range r.Results {
		res.Findings = append(res.Findings, sr.finding(byID, r.Tool.Driver.Rules))
	}
	return res
}

// ruleIndex builds the id→rule map for the ruleId reference path.
func (r sarifRun) ruleIndex() map[string]sarifRule {
	m := make(map[string]sarifRule, len(r.Tool.Driver.Rules))
	for _, rule := range r.Tool.Driver.Rules {
		m[rule.ID] = rule
	}
	return m
}

// SARIF lets a result reference its rule by ruleId, by ruleIndex into
// tool.driver.rules, or both. Some emitters set only ruleIndex, so
// fall back to it when ruleId yields nothing.
func (sr sarifResult) finding(byID map[string]sarifRule, rules []sarifRule) Finding {
	rule, ok := byID[sr.RuleID]
	if !ok && sr.RuleIndex != nil && *sr.RuleIndex >= 0 && *sr.RuleIndex < len(rules) {
		rule = rules[*sr.RuleIndex]
	}
	f := Finding{
		RuleID:      sr.RuleID,
		Title:       firstNonEmpty(rule.ShortDescription.Text, rule.Name, sr.Message.Text, sr.RuleID),
		Description: firstNonEmpty(sr.Message.Text, rule.FullDescription.Text),
		Severity:    sarifSeverity(sr.Level, rule.Properties.SecuritySeverity),
		Confidence:  sarifConfidence(rule.Properties.Precision),
		CWE:         cweFromTags(rule.Properties.Tags),
		Location:    sr.location(),
	}
	if len(sr.Fixes) > 0 {
		f.SuggestedFix = sr.Fixes[0].Description.Text
	}
	return f
}

func (sr sarifResult) location() string {
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
