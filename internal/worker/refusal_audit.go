package worker

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"

	"scrutineer/internal/db"
)

// refusalAudit is a short, post-report account of code the deep-dive agent
// declined to analyse or could analyse only partially. It deliberately lives
// outside report.json so an audit cannot change the scan's primary artifact.
type refusalAudit struct {
	Refused bool                  `json:"refused"`
	Reason  *string               `json:"reason"`
	Skipped []refusalAuditSkipped `json:"skipped"`
}

type refusalAuditSkipped struct {
	Path   string `json:"path"`
	Reason string `json:"reason"`
}

func (a refusalAudit) warning() bool {
	return a.Refused || len(a.Skipped) > 0
}

func (w *Worker) auditSkillRefusals(ctx context.Context, skill *db.Skill, scan *db.Scan, sj SkillJob, emit func(Event)) {
	if skill.Name != refusalAuditSkillName || scan.SessionID == "" {
		return
	}

	emit(Event{Kind: KindText, Text: "refusal audit: asking the agent to account for skipped analysis"})
	auditJob := sj
	auditJob.ResumeSessionID = scan.SessionID
	auditJob.ResumePrompt = buildRefusalAuditPrompt()
	auditJob.OutputFile = refusalAuditOutputFile
	auditJob.MaxTurns = refusalAuditMaxTurns
	res, err := w.Runner.RunSkill(ctx, auditJob, emit)
	w.applySkillResult(scan, res)
	if err != nil {
		emit(Event{Kind: KindError, Text: fmt.Sprintf("refusal audit failed: %v; primary report retained", err)})
		return
	}
	audit, err := parseRefusalAudit(res.Report)
	if err != nil {
		emit(Event{Kind: KindError, Text: fmt.Sprintf("refusal audit ignored: %v", err)})
		return
	}

	scan.RefusalAudit = res.Report
	scan.RefusalAuditWarning = audit.warning()
	if scan.RefusalAuditWarning {
		emit(Event{Kind: KindText, Text: "refusal audit: analysis was refused or skipped; see scan details"})
	}
}

func buildRefusalAuditPrompt() string {
	return `The primary security-deep-dive report is complete. Do not restart analysis and do not modify report.json.

Audit only whether you declined, skipped, or could only partially analyse any security-relevant repository content. Write ./refusal_audit.json as exactly one JSON object:
{"refused": false, "reason": null, "skipped": []}

Set refused to true only when you declined analysis. Give its reason when true. For each skipped or partial area, add a repository-relative path and a concise reason. Use an empty skipped array when nothing was skipped. Do not write prose outside the JSON file.`
}

func parseRefusalAudit(raw string) (refusalAudit, error) {
	var audit refusalAudit
	raw = strings.TrimSpace(raw)
	if !strings.HasPrefix(raw, "{") {
		return refusalAudit{}, fmt.Errorf("%s must contain one JSON object", refusalAuditOutputFile)
	}
	dec := json.NewDecoder(strings.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&audit); err != nil {
		return refusalAudit{}, fmt.Errorf("%s is not valid JSON: %w", refusalAuditOutputFile, err)
	}
	if err := dec.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return refusalAudit{}, fmt.Errorf("%s must contain one JSON object", refusalAuditOutputFile)
	}
	if audit.Refused && (audit.Reason == nil || strings.TrimSpace(*audit.Reason) == "") {
		return refusalAudit{}, fmt.Errorf("%s must include a reason when refused is true", refusalAuditOutputFile)
	}
	for i, skipped := range audit.Skipped {
		if !isRepositoryRelativePath(skipped.Path) {
			return refusalAudit{}, fmt.Errorf("%s skipped[%d] path must be repository-relative", refusalAuditOutputFile, i)
		}
		if strings.TrimSpace(skipped.Reason) == "" {
			return refusalAudit{}, fmt.Errorf("%s skipped[%d] must include a reason", refusalAuditOutputFile, i)
		}
	}
	return audit, nil
}

// isRepositoryRelativePath accepts slash-separated repository paths without
// normalising them, so malformed agent output cannot escape or ambiguously
// describe the repository root.
func isRepositoryRelativePath(path string) bool {
	if path == "" || strings.ContainsRune(path, '\\') || strings.ContainsRune(path, 0) || strings.HasPrefix(path, "/") {
		return false
	}
	segments := strings.Split(path, "/")
	if isWindowsDrivePrefix(segments[0]) {
		return false
	}
	for _, segment := range segments {
		if segment == "" || segment == "." || segment == ".." {
			return false
		}
	}
	return true
}

func isWindowsDrivePrefix(segment string) bool {
	if len(segment) < 2 || segment[1] != ':' {
		return false
	}
	return (segment[0] >= 'a' && segment[0] <= 'z') || (segment[0] >= 'A' && segment[0] <= 'Z')
}
