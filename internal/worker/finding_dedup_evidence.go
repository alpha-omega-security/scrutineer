package worker

import (
	"fmt"
	"time"

	"gorm.io/gorm"

	"scrutineer/internal/db"
)

// dedupEvidenceFields are the report prose a better duplicate can replace on
// the canonical finding. Location stays with the canonical because its
// snippet, VID and source links are derived from it at the canonical's
// commit. Assessments (severity, cwe, rating, reachability) and lifecycle
// data stay too.
var dedupEvidenceFields = []struct {
	name string
	get  func(*db.Finding) string
}{
	{"title", func(f *db.Finding) string { return f.Title }},
	{"sinks", func(f *db.Finding) string { return f.Sinks }},
	{"trace", func(f *db.Finding) string { return f.Trace }},
	{"boundary", func(f *db.Finding) string { return f.Boundary }},
	{"validation", func(f *db.Finding) string { return f.Validation }},
	{"reach", func(f *db.Finding) string { return f.Reach }},
	{"prior_art", func(f *db.Finding) string { return f.PriorArt }},
}

// promoteDedupEvidence copies the report body of member onto head, keeping
// head's id, status and history. Fields the analyst has edited are left
// alone. Reports whether anything changed.
func (w *Worker) promoteDedupEvidence(head, member db.Finding, reason string) (bool, error) {
	changed := false
	err := db.FindingWriteTransaction(w.DB, head.ID, func(tx *gorm.DB) error {
		changed = false
		var cur db.Finding
		if err := tx.First(&cur, head.ID).Error; err != nil {
			return fmt.Errorf("load finding %d: %w", head.ID, err)
		}
		// From ready onward a disclosure may already be drafted or sent from
		// the current body, so rewriting it underneath would desynchronise the two.
		switch cur.Status {
		case db.FindingNew, db.FindingEnriched, db.FindingTriaged:
		default:
			return nil
		}
		// Verify replays a captured PoC in preference to validation text, so
		// keep the text that describes the capture.
		capture, err := db.LoadFindingPoC(tx, cur.ID)
		if err != nil {
			return fmt.Errorf("load captured PoC for finding %d: %w", cur.ID, err)
		}
		var owned []string
		if err := tx.Model(&db.FindingHistory{}).
			Where("finding_id = ? AND source = ?", head.ID, db.SourceAnalyst).
			Distinct().Pluck("field", &owned).Error; err != nil {
			return fmt.Errorf("load analyst edits for finding %d: %w", head.ID, err)
		}
		analyst := map[string]bool{}
		for _, f := range owned {
			analyst[f] = true
		}

		updates := map[string]any{}
		for _, f := range dedupEvidenceFields {
			old, nv := f.get(&cur), f.get(&member)
			if nv == "" || nv == old || analyst[f.name] || (f.name == "validation" && capture != nil) {
				continue
			}
			updates[f.name] = nv
			if err := tx.Create(&db.FindingHistory{
				FindingID: cur.ID,
				Field:     f.name,
				OldValue:  old,
				NewValue:  nv,
				Source:    db.SourceModel,
				By:        findingDedupSkill,
				CreatedAt: time.Now(),
			}).Error; err != nil {
				return err
			}
		}
		if len(updates) == 0 {
			return nil
		}
		changed = true
		return tx.Model(&db.Finding{}).Where("id = ?", cur.ID).Updates(updates).Error
	})
	if err != nil {
		return false, fmt.Errorf("take evidence from finding %d: %w", member.ID, err)
	}
	if !changed {
		return false, nil
	}
	return true, w.addRelationNote(head.ID, dedupHeaderEvidence, []uint{member.ID}, reason)
}
