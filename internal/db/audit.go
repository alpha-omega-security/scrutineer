package db

import (
	"fmt"
	"strings"
	"time"

	"gorm.io/gorm"
)

// ValidReviewVerdicts is the closed set the audit form and API accept.
// Matches the revalidate skill's enum so reviewer agreement with the
// model is a direct string comparison.
var ValidReviewVerdicts = map[string]bool{
	"true_positive":  true,
	"false_positive": true,
	"already_fixed":  true,
	"uncertain":      true,
}

// AddFindingReview records one structured human verdict on a finding.
// verdict must be one of the values in ValidReviewVerdicts; the helper
// rejects free-text verdicts at the API boundary so the agreement-rate
// query stays a single GROUP BY rather than a string-matching mess.
// automatedOutcome is whatever the automation said about this finding
// at the time of review (typically the latest revalidate verdict);
// empty when no automation has weighed in yet.
func AddFindingReview(gdb *gorm.DB, findingID uint, verdict, reason, automatedOutcome, reviewer string) (*FindingReview, error) {
	verdict = strings.TrimSpace(verdict)
	if !ValidReviewVerdicts[verdict] {
		return nil, fmt.Errorf("verdict %q is not one of true_positive|false_positive|already_fixed|uncertain", verdict)
	}
	r := &FindingReview{
		FindingID:        findingID,
		Verdict:          verdict,
		Reason:           strings.TrimSpace(reason),
		AutomatedOutcome: strings.TrimSpace(automatedOutcome),
		Reviewer:         strings.TrimSpace(reviewer),
		CreatedAt:        time.Now(),
	}
	if err := gdb.Create(r).Error; err != nil {
		return nil, err
	}
	return r, nil
}

// ListFindingReviews returns reviews for one finding, newest first.
// Used by the finding page and the audit queue's reviewed-marker check.
func ListFindingReviews(gdb *gorm.DB, findingID uint) ([]FindingReview, error) {
	var out []FindingReview
	err := gdb.Where("finding_id = ?", findingID).Order("created_at desc").Find(&out).Error
	return out, err
}

// AuditQueueOptions filters the audit queue. Limit caps result count
// (the queue is for spot-checking, not exhaustive review). Since is a
// freshness cutoff; the zero value means "no cutoff".
type AuditQueueOptions struct {
	Limit int
	Since time.Time
}

// AuditQueue returns findings the automation has bucketed as not worth
// pursuing, which a TOC or VCT auditor should spot-check periodically to
// keep the heuristics honest. The set is the union of:
//
//   - Findings with severity Low (the automation's lowest bucket)
//   - Findings in status rejected (whoever rejected them, human or
//     automated)
//   - Findings whose cached last_revalidate_verdict is one of the
//     non-true_positive verdicts (false_positive, already_fixed,
//     uncertain). When the revalidate skill is absent or has not run
//     yet on this install, the column is empty and the queue degrades
//     to low-severity and rejected findings only.
//
// Findings already carrying a FindingReview row are excluded.
func AuditQueue(gdb *gorm.DB, opts AuditQueueOptions) ([]Finding, error) {
	limit := opts.Limit
	if limit <= 0 {
		limit = 50
	}
	q := gdb.Model(&Finding{}).
		Where(
			gdb.Where("severity = ?", "Low").
				Or("status = ?", FindingRejected).
				Or("last_revalidate_verdict IN ?", []string{"false_positive", "already_fixed", "uncertain"}),
		).
		Where("id NOT IN (SELECT finding_id FROM finding_reviews)")
	if !opts.Since.IsZero() {
		// SQLite stores timestamps as text with whatever TZ offset the
		// driver serialised, so a bare >= compares strings, not instants.
		// datetime() normalises both sides to UTC YYYY-MM-DD HH:MM:SS.
		q = q.Where("datetime(created_at) >= datetime(?)", opts.Since)
	}
	var out []Finding
	err := q.Order("updated_at desc").Limit(limit).Find(&out).Error
	return out, err
}

// AuditMetrics is the aggregate breakdown the audit page surfaces.
// AgreementRate is the share of reviews where the human verdict matches
// the automation's, restricted to reviews where both are known. By
// convention rates are fractions in [0, 1]; the caller formats them.
type AuditMetrics struct {
	TotalReviews         int64
	WithAutomatedOutcome int64
	Agreements           int64
	AgreementRate        float64
	ByVerdict            map[string]int64
}

// ComputeAuditMetrics scans the FindingReview table and returns
// aggregate stats for the audit page. A review counts toward agreement
// only when both the human verdict and the automated outcome are
// known: empty automated outcomes (no revalidate run) say nothing
// about calibration. The three count-style metrics fold into one
// query with conditional aggregation so the /audit page hits the
// table once for them; the per-verdict histogram is a separate GROUP BY.
func ComputeAuditMetrics(gdb *gorm.DB) (AuditMetrics, error) {
	var m AuditMetrics
	m.ByVerdict = map[string]int64{}
	var counts struct {
		TotalReviews         int64
		WithAutomatedOutcome int64
		Agreements           int64
	}
	if err := gdb.Model(&FindingReview{}).
		Select(`
			COUNT(*) AS total_reviews,
			COUNT(CASE WHEN automated_outcome != '' THEN 1 END) AS with_automated_outcome,
			COUNT(CASE WHEN automated_outcome != '' AND verdict = automated_outcome THEN 1 END) AS agreements`).
		Scan(&counts).Error; err != nil {
		return m, err
	}
	m.TotalReviews = counts.TotalReviews
	m.WithAutomatedOutcome = counts.WithAutomatedOutcome
	m.Agreements = counts.Agreements
	if m.WithAutomatedOutcome > 0 {
		m.AgreementRate = float64(m.Agreements) / float64(m.WithAutomatedOutcome)
	}
	rows, err := gdb.Model(&FindingReview{}).Select("verdict, count(*) as n").Group("verdict").Rows()
	if err != nil {
		return m, err
	}
	defer func() { _ = rows.Close() }()
	for rows.Next() {
		var v string
		var n int64
		if err := rows.Scan(&v, &n); err != nil {
			return m, err
		}
		m.ByVerdict[v] = n
	}
	return m, rows.Err()
}

// LatestRevalidateVerdict returns the verdict from the most recent
// revalidate FindingNote on the finding, or empty when revalidate has
// not run. The audit queue captures this into the FindingReview's
// AutomatedOutcome field so the agreement metric stays computable even
// after later revalidate runs change the model's mind.
func LatestRevalidateVerdict(gdb *gorm.DB, findingID uint) string {
	var note FindingNote
	if err := gdb.Where("finding_id = ? AND `by` = ?", findingID, "revalidate").
		Order("created_at desc").First(&note).Error; err != nil {
		return ""
	}
	body := strings.TrimSpace(note.Body)
	// Parser writes "revalidate: <verdict>\n..." (skill_parsers.go);
	// extract the verdict token from that header.
	const prefix = "revalidate: "
	if !strings.HasPrefix(body, prefix) {
		return ""
	}
	rest := body[len(prefix):]
	if i := strings.IndexAny(rest, "\n "); i >= 0 {
		rest = rest[:i]
	}
	if ValidReviewVerdicts[rest] {
		return rest
	}
	return ""
}
