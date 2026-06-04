package web

import (
	"encoding/json"
	"fmt"
	"net/http"
	"sort"
	"strings"

	"gorm.io/gorm"

	"scrutineer/internal/db"
)

// The threat-model workbench (#249) lets an operator iterate on a
// repository's threat model: edit the JSON, run security-deep-dive
// against the edited copy, and see which sinks moved between findings
// and ruled-out compared to the previous run. Repository.ThreatModel
// holds the working copy; the worker stages it as ./threat_model.json
// so deep-dive loads it instead of fetching the latest threat-model
// scan from the API.

const workbenchTab = "#rt12"

// Workbench is the template payload for the workbench tab.
type Workbench struct {
	// Model is the editor's seed: the operator's saved override if one
	// exists, otherwise the latest threat-model scan's report so the
	// first edit starts from the auto-generated model.
	Model string
	// HasOverride is true when Repository.ThreatModel is non-empty,
	// i.e. deep-dive will currently load the override instead of
	// fetching from the API.
	HasOverride bool
	// Runs are the most recent completed deep-dive scans, newest first.
	// The diff compares Runs[0] against Runs[1].
	Runs []db.Scan
	Diff WorkbenchDiff
}

// WorkbenchDiff buckets sinks by how their outcome changed between two
// deep-dive runs. A sink is keyed by its inventory location (file:line)
// since the per-run S<n> ids are not stable across runs.
type WorkbenchDiff struct {
	NowReported   []DiffRow
	NowSuppressed []DiffRow
	ReasonChanged []DiffRow
	Unchanged     int
	// OnlyInCurr / OnlyInPrev are sinks one run inventoried that the
	// other did not. Non-determinism in the inventory pass shows up
	// here rather than as a model effect.
	OnlyInCurr int
	OnlyInPrev int
}

type DiffRow struct {
	Location string
	Class    string
	Before   string
	After    string
}

func (d WorkbenchDiff) Empty() bool {
	return len(d.NowReported)+len(d.NowSuppressed)+len(d.ReasonChanged) == 0
}

// loadWorkbench assembles the workbench tab's data. seedReport is the
// latest threat-model scan's report.json, used to seed the editor when
// the operator has not saved an override yet.
func loadWorkbench(gdb *gorm.DB, repo *db.Repository, seedReport string) Workbench {
	wb := Workbench{
		Model:       repo.ThreatModel,
		HasOverride: repo.ThreatModel != "",
	}
	if wb.Model == "" {
		wb.Model = seedReport
	}
	// Workbench is repository-root scoped: the override lives on Repository
	// and repoThreatModelRun enqueues with empty SubPath. Restrict the
	// history (and the diff that feeds off it) to root deep-dives so a
	// recent subproject run doesn't show its inventory drift as a
	// model effect.
	gdb.Where("repository_id = ? AND skill_name = ? AND status = ? AND sub_path = '' AND report <> ''",
		repo.ID, deepDiveSkillName, db.ScanDone).
		Order("id DESC").Limit(workbenchRunHistory).Find(&wb.Runs)
	if len(wb.Runs) > 1 {
		wb.Diff = diffDeepDive(wb.Runs[1].Report, wb.Runs[0].Report)
	}
	return wb
}

const workbenchRunHistory = 5

// repoThreatModelSave persists the editor contents to
// Repository.ThreatModel without enqueueing a scan. Rejects input that
// is not valid JSON so a typo surfaces immediately rather than as a
// failed deep-dive ten minutes later.
func (s *Server) repoThreatModelSave(w http.ResponseWriter, r *http.Request) {
	repo, ok := loadByID[db.Repository](s, w, r)
	if !ok {
		return
	}
	model, err := normaliseThreatModel(r.FormValue("threat_model"))
	if err != nil {
		http.Error(w, "threat model is not valid JSON: "+err.Error(), http.StatusBadRequest)
		return
	}
	if err := s.DB.Model(&db.Repository{}).Where("id = ?", repo.ID).
		Update("threat_model", model).Error; err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	setFlash(w, Flash{Category: "success", Title: "Threat model saved"})
	s.redirect(w, r, fmt.Sprintf("/repositories/%d%s", repo.ID, workbenchTab))
}

// repoThreatModelRun saves the editor contents and enqueues a
// security-deep-dive scan in one step.
func (s *Server) repoThreatModelRun(w http.ResponseWriter, r *http.Request) {
	repo, ok := loadByID[db.Repository](s, w, r)
	if !ok {
		return
	}
	model, err := normaliseThreatModel(r.FormValue("threat_model"))
	if err != nil {
		http.Error(w, "threat model is not valid JSON: "+err.Error(), http.StatusBadRequest)
		return
	}
	if err := s.DB.Model(&db.Repository{}).Where("id = ?", repo.ID).
		Update("threat_model", model).Error; err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	var skill db.Skill
	if err := s.DB.Where("name = ? AND active = ?", deepDiveSkillName, true).First(&skill).Error; err != nil {
		http.Error(w, deepDiveSkillName+" skill is not installed", http.StatusPreconditionFailed)
		return
	}
	scanID, err := s.enqueueSkillWith(r.Context(), repo.ID, skill.ID, ScanOpts{})
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	s.redirect(w, r, fmt.Sprintf("/scans/%d", scanID))
}

// repoThreatModelClear drops the override so deep-dive goes back to
// fetching the latest threat-model scan from the API.
func (s *Server) repoThreatModelClear(w http.ResponseWriter, r *http.Request) {
	repo, ok := loadByID[db.Repository](s, w, r)
	if !ok {
		return
	}
	if err := s.DB.Model(&db.Repository{}).Where("id = ?", repo.ID).
		Update("threat_model", "").Error; err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	setFlash(w, Flash{Category: "success", Title: "Threat model override cleared"})
	s.redirect(w, r, fmt.Sprintf("/repositories/%d%s", repo.ID, workbenchTab))
}

// normaliseThreatModel checks the input parses as JSON and re-emits it
// indented so the editor round-trips cleanly. Empty input is allowed
// (it clears the override).
func normaliseThreatModel(in string) (string, error) {
	in = strings.TrimSpace(in)
	if in == "" {
		return "", nil
	}
	var v any
	if err := json.Unmarshal([]byte(in), &v); err != nil {
		return "", err
	}
	out, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return "", err
	}
	return string(out), nil
}

// sinkOutcome records what happened to one inventory sink in a
// deep-dive report: it either became a finding or was ruled out with a
// reason.
type sinkOutcome struct {
	Class    string
	Finding  bool
	Title    string
	Severity string
	Reason   string
}

func (o sinkOutcome) label() string {
	if o.Finding {
		return o.Severity + ": " + o.Title
	}
	return o.Reason
}

// ddReport is the subset of the security-deep-dive report.json the
// workbench diff reads. Field shapes match
// skills/security-deep-dive/schema.json.
type ddReport struct {
	Inventory []struct {
		ID       string `json:"id"`
		Location string `json:"location"`
		Class    string `json:"class"`
	} `json:"inventory"`
	Findings []struct {
		Sinks    []string `json:"sinks"`
		Title    string   `json:"title"`
		Severity string   `json:"severity"`
	} `json:"findings"`
	RuledOut []struct {
		Sinks  []string `json:"sinks"`
		Reason string   `json:"reason"`
	} `json:"ruled_out"`
}

// sinkOutcomes resolves a deep-dive report into a location-keyed map of
// what happened to each inventory sink. Per-run S<n> ids are unstable
// across runs so the inventory's file:line location is the join key.
func sinkOutcomes(report string) map[string]sinkOutcome {
	var r ddReport
	if err := json.Unmarshal([]byte(report), &r); err != nil {
		return nil
	}
	loc := map[string]string{}
	class := map[string]string{}
	for _, s := range r.Inventory {
		loc[s.ID] = s.Location
		class[s.ID] = s.Class
	}
	out := map[string]sinkOutcome{}
	for _, f := range r.Findings {
		for _, sid := range f.Sinks {
			l := loc[sid]
			if l == "" {
				continue
			}
			out[l] = sinkOutcome{Class: class[sid], Finding: true, Title: f.Title, Severity: f.Severity}
		}
	}
	for _, ro := range r.RuledOut {
		reason := headLine(ro.Reason)
		for _, sid := range ro.Sinks {
			l := loc[sid]
			if l == "" {
				continue
			}
			if _, seen := out[l]; seen {
				continue
			}
			out[l] = sinkOutcome{Class: class[sid], Reason: reason}
		}
	}
	return out
}

// diffDeepDive compares two deep-dive reports and buckets sinks by how
// their outcome changed. prev is the older run, curr the newer.
func diffDeepDive(prev, curr string) WorkbenchDiff {
	a := sinkOutcomes(prev)
	b := sinkOutcomes(curr)
	var d WorkbenchDiff
	for loc, after := range b {
		before, ok := a[loc]
		if !ok {
			d.OnlyInCurr++
			continue
		}
		row := DiffRow{Location: loc, Class: after.Class, Before: before.label(), After: after.label()}
		switch {
		case !before.Finding && after.Finding:
			d.NowReported = append(d.NowReported, row)
		case before.Finding && !after.Finding:
			d.NowSuppressed = append(d.NowSuppressed, row)
		case !before.Finding && !after.Finding && before.Reason != after.Reason:
			d.ReasonChanged = append(d.ReasonChanged, row)
		default:
			d.Unchanged++
		}
	}
	for loc := range a {
		if _, ok := b[loc]; !ok {
			d.OnlyInPrev++
		}
	}
	sortRows(d.NowReported)
	sortRows(d.NowSuppressed)
	sortRows(d.ReasonChanged)
	return d
}

func sortRows(rows []DiffRow) {
	sort.Slice(rows, func(i, j int) bool { return rows[i].Location < rows[j].Location })
}

func headLine(s string) string {
	head, _, _ := strings.Cut(s, "\n")
	return strings.TrimSpace(head)
}
