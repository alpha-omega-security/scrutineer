package web

import (
	"strings"

	"scrutineer/internal/ingest"
)

// An externally-produced scanner report is unbounded. One over-eager CodeQL or
// Semgrep rule can carry thousands of hits against a single repository, so the
// import path would turn each one into a Finding row plus a revalidate job
// that chains into verify. The caps below bound that.
//
// The caps are per parsed result, which is one repository's findings from one
// tool: a multi-run SARIF file is bounded per run while a multi-repo CSV is
// bounded per repository, so one upload's ceiling is importResultCap times the
// number of results it parses to. The budget is not shared across the upload
// on purpose: one repository's noise would otherwise starve another
// repository's findings out of the same file, which is worse than importing
// both bounded.
//
// They apply to the formats carrying raw scanner output: SARIF, the
// code-scanning CSV export and the hosted-scanner markdown export. Curated
// input imports whole because it is somebody's considered list rather than a
// rule dump: scrutineer's own sharing bundle, a hand-written minimal-JSON
// report plus the ingest skill's fallback for unrecognised payloads.
const (
	// importPerRuleCap is the most findings one rule may contribute to a
	// single imported result. Five hits are enough to show what a rule is
	// flagging; the rest are noise until somebody has triaged those five.
	importPerRuleCap = 5
	// importResultCap is the most findings one imported result may contribute
	// in total, whatever the spread of rules. It backstops the per-rule cap
	// for reports that spray a thousand distinct rules.
	importResultCap = 50
)

// capsApplyTo reports whether a parsed format carries raw scanner output and
// therefore gets bounded. The rationale above says which formats are excluded
// and why.
func capsApplyTo(format ingest.Format) bool {
	switch format {
	case ingest.FormatSARIF, ingest.FormatCSV, ingest.FormatMarkdown:
		return true
	default:
		return false
	}
}

// importCapStats records what the caps did to one result so the import
// response and the server log can tell a clean scan from a bounded one.
//
// Received counts findings as the parser produced them. Accepted counts those
// that passed both caps. The created/observed counts reported alongside are
// taken further downstream, after fingerprint dedup, so accepted is an upper
// bound on them rather than their sum.
type importCapStats struct {
	Received       int
	Accepted       int
	DroppedPerRule int
	DroppedTotal   int
}

// truncated reports whether either cap rejected anything.
func (c importCapStats) truncated() bool {
	return c.DroppedPerRule > 0 || c.DroppedTotal > 0
}

// uncappedImportStats describes a result imported whole, so a format the caps
// do not apply to still reports the same counters.
func uncappedImportStats(res ingest.Result) importCapStats {
	return importCapStats{Received: len(res.Findings), Accepted: len(res.Findings)}
}

// capScannerResult returns res with its findings bounded by the two caps, plus
// the counts describing what was dropped.
//
// Input order decides who survives: the first importPerRuleCap hits of a rule
// and the first importResultCap findings overall are the ones kept. Truncation
// is therefore deterministic for a given report, which is what lets an operator
// re-run the same file and reason about what is missing.
//
// A finding both caps would reject is counted against the per-rule cap alone,
// the more specific reason, so the two dropped counts sum to Received minus
// Accepted rather than double-counting.
func capScannerResult(res ingest.Result) (ingest.Result, importCapStats) {
	stats := importCapStats{Received: len(res.Findings)}
	accepted := make([]ingest.Finding, 0, min(len(res.Findings), importResultCap))
	perRule := make(map[string]int, len(res.Findings))
	for _, f := range res.Findings {
		key := capKey(f)
		switch {
		case perRule[key] >= importPerRuleCap:
			stats.DroppedPerRule++
		case len(accepted) >= importResultCap:
			stats.DroppedTotal++
		default:
			perRule[key]++
			accepted = append(accepted, f)
		}
	}
	stats.Accepted = len(accepted)
	res.Findings = accepted
	return res, stats
}

// capKey picks the most rule-like identifier a finding offers, since the
// per-rule cap is only worth anything when its key repeats across a rule's
// hits.
//
// Two producers fail to supply one. SARIF does not require a result to name
// its ruleId, while the CSV parser fills RuleID with the per-alert Finding URL
// (see internal/ingest/csv.go), which is unique per row, so keying on it
// straight would put every CSV hit in its own bucket and leave the per-rule
// cap inert for that whole format. Both fall back to the title: in SARIF it is
// the rule's short description whenever the parser resolved a rule, in a
// code-scanning CSV it is the alert's Name or Category column, so in each case
// it is the nearest thing to a rule name the input carries. Where it is not,
// grouping by it still beats lumping every anonymous hit into one bucket that
// the fifth finding would close.
//
// A finding with no title at all falls back to the URL rule id rather than to
// the empty string. Both leave the per-rule cap doing nothing for that row,
// since a per-alert URL is unique, but an inert key is much better than a
// shared one: `csv.go` fills Title from the Name column falling back to
// Category, so a code-scanning export with both columns blank would otherwise
// collapse unrelated alerts into a single bucket the fifth finding closes. The
// per-result cap still bounds them. The key is empty only when the finding
// carries neither identifier, where there is nothing left to group on.
func capKey(f ingest.Finding) string {
	if f.RuleID != "" && !strings.Contains(f.RuleID, "://") {
		return f.RuleID
	}
	if f.Title != "" {
		return f.Title
	}
	return f.RuleID
}
