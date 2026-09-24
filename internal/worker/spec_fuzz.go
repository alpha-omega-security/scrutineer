package worker

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strings"

	"scrutineer/internal/db"
	"scrutineer/internal/specfuzz"
)

// specFuzzReport is the skill's report.json: one clause id, the
// adapter's verdict for every corpus input plus every control (keyed
// by input id), and where in the target the adapter entered.
type specFuzzReport struct {
	ClauseID   string                             `json:"clause_id"`
	Entrypoint string                             `json:"entrypoint"`
	Verdicts   map[string]specfuzz.AdapterVerdict `json:"verdicts"`
	Notes      string                             `json:"notes,omitempty"`
	Error      string                             `json:"error,omitempty"`
}

// parseSpecFuzzOutput classifies the skill's adapter verdicts against
// the vendored oracle and reference matrix, then creates one Finding
// per corpus label that produced a Deviates result.
func (w *Worker) parseSpecFuzzOutput(ctx context.Context, skill *db.Skill, scan *db.Scan, report string, emit func(Event)) error {
	var r specFuzzReport
	if err := json.Unmarshal([]byte(report), &r); err != nil {
		return fmt.Errorf("spec_fuzz report: %w", err)
	}
	if r.Error != "" {
		emit(Event{Kind: KindText, Text: "spec-fuzz skill error: " + r.Error})
		return nil
	}
	if r.ClauseID == "" {
		return fmt.Errorf("spec_fuzz report: clause_id missing")
	}
	clause, err := specfuzz.LoadClause(r.ClauseID)
	if err != nil {
		return err
	}
	adapter := &specfuzz.Adapter{Run: verdictLookup(clause, r.Verdicts)}
	run, err := specfuzz.Run(ctx, clause, adapter)
	if err != nil {
		return err
	}
	if !run.ControlPass {
		var failed []string
		for _, c := range run.Controls {
			if !c.Pass && c.Expect {
				failed = append(failed, c.Control.ID)
			}
		}
		emit(Event{Kind: KindText, Text: fmt.Sprintf(
			"spec-fuzz: adapter failed must_accept controls %v; clause %s skipped",
			failed, r.ClauseID)})
		return nil
	}
	emit(Event{Kind: KindText, Text: fmt.Sprintf(
		"spec-fuzz %s: %d inputs, conformant=%d deviates=%d over-strict=%d",
		r.ClauseID, len(run.Results),
		run.ByClass[specfuzz.Conformant],
		run.ByClass[specfuzz.Deviates],
		run.ByClass[specfuzz.OverStrict])})

	findings := specFuzzFindings(run, r.Entrypoint, scan)
	findings = groupByFingerprint(findings, scan.SkillName)
	scan.FindingsCount = len(findings)
	created := 0
	for i := range findings {
		wasCreated, perr := w.persistFinding(scan, &findings[i])
		if perr != nil {
			return perr
		}
		if wasCreated {
			created++
		}
	}
	emit(Event{Kind: KindText, Text: fmt.Sprintf(
		"spec-fuzz: %d finding(s), %d new", len(findings), created)})
	_ = skill
	return nil
}

// verdictLookup answers each hex input from the skill's precomputed
// verdict map. The map is keyed by input id (stable across corpus
// regenerations); this rebuilds hex → verdict from the loaded clause.
func verdictLookup(c *specfuzz.Clause, verdicts map[string]specfuzz.AdapterVerdict) func(context.Context, io.Reader) ([]byte, error) {
	byHex := map[string]specfuzz.AdapterVerdict{}
	for _, in := range c.Corpus {
		if v, ok := verdicts[in.ID]; ok {
			byHex[in.Hex] = v
		}
	}
	all := append(append([]specfuzz.Control{}, c.Controls.MustAccept...), c.Controls.MustReject...)
	for _, ctrl := range all {
		if v, ok := verdicts[ctrl.ID]; ok {
			byHex[ctrl.Hex] = v
		}
	}
	return func(_ context.Context, stdin io.Reader) ([]byte, error) {
		var out bytes.Buffer
		b, err := io.ReadAll(stdin)
		if err != nil {
			return nil, err
		}
		for line := range strings.SplitSeq(strings.TrimRight(string(b), "\n"), "\n") {
			v, ok := byHex[line]
			if !ok {
				v = specfuzz.AdapterVerdict{Accept: false, Error: "verdict-missing"}
			}
			enc, _ := json.Marshal(v)
			out.Write(enc)
			out.WriteByte('\n')
		}
		return out.Bytes(), nil
	}
}

// specFuzzFindings groups Deviates results by corpus label (one label
// = one grammar-mutation family) and produces one Finding per family.
func specFuzzFindings(run *specfuzz.RunReport, entrypoint string, scan *db.Scan) []db.Finding {
	byLabel := map[string][]specfuzz.Result{}
	for _, res := range run.Deviations() {
		byLabel[res.Input.Label] = append(byLabel[res.Input.Label], res)
	}
	labels := make([]string, 0, len(byLabel))
	for l := range byLabel {
		labels = append(labels, l)
	}
	sort.Strings(labels)

	loc := entrypoint
	if !strings.Contains(loc, ":") {
		loc = "(adapter):1"
	}
	var out []db.Finding
	for _, label := range labels {
		group := byLabel[label]
		hasBoundary := false
		for _, r := range group {
			if specfuzz.AnyBoundary(r.Differentials) {
				hasBoundary = true
			}
		}
		sev := "Low"
		if hasBoundary {
			sev = "High"
		}
		out = append(out, db.Finding{
			ScanID:       scan.ID,
			RepositoryID: scan.RepositoryID,
			Commit:       scan.Commit,
			SubPath:      scan.SubPath,
			Model:        scan.Model,
			Title: fmt.Sprintf("Accepts %s-mutated input that %s rejects",
				label, run.Clause.Citation),
			Severity:     sev,
			Confidence:   "high",
			CWE:          specFuzzCWE(run.Clause.Protocol),
			Location:     loc,
			Reachability: "reachable",
			QualityTier:  "high",
			Trace:        specFuzzTrace(run, group),
			Boundary:     specFuzzBoundary(run),
			Validation:   specFuzzValidation(group),
			Rating:       specFuzzRating(sev, hasBoundary, group),
		})
	}
	return out
}

func specFuzzCWE(protocol string) string {
	if protocol == "http1" {
		return "CWE-444"
	}
	return "CWE-1286"
}

func specFuzzTrace(run *specfuzz.RunReport, group []specfuzz.Result) string {
	ex := group[0]
	var b strings.Builder
	fmt.Fprintf(&b, "%d input(s) in this mutation family; example `%s`:\n\n",
		len(group), ex.Input.ID)
	fmt.Fprintf(&b, "    hex:    %s\n", ex.Input.Hex)
	fmt.Fprintf(&b, "    oracle: reject (%s)\n", run.Clause.Citation)
	fmt.Fprintf(&b, "    target: accept, body_hex=%s", ex.Target.BodyHex)
	if ex.Target.Consumed != nil {
		fmt.Fprintf(&b, ", consumed=%d", *ex.Target.Consumed)
	}
	fmt.Fprintf(&b, "\n\nlean-rfcs %s\n", strings.TrimSpace(run.Source))
	return b.String()
}

func specFuzzBoundary(run *specfuzz.RunReport) string {
	return fmt.Sprintf(
		"An untrusted client sends the byte sequence to the target's %s parser. "+
			"The %s grammar rejects it; the target accepts.",
		run.Clause.Protocol, run.Clause.Citation)
}

func specFuzzValidation(group []specfuzz.Result) string {
	ex := group[0]
	sort.Slice(ex.Differentials, func(i, j int) bool {
		return ex.Differentials[i].Peer < ex.Differentials[j].Peer
	})
	var b strings.Builder
	b.WriteString("Reference implementations on the same input:\n\n")
	for _, d := range ex.Differentials {
		ver := d.Version
		if ver != "" {
			ver = "@" + ver
		}
		fmt.Fprintf(&b, "    %s%s: %s\n", d.Peer, ver, d.Class)
	}
	return b.String()
}

func specFuzzRating(sev string, hasBoundary bool, group []specfuzz.Result) string {
	if hasBoundary {
		return fmt.Sprintf(
			"%s: at least one reference implementation accepts the same input at a "+
				"different byte offset, so this parser paired with that peer disagrees "+
				"on where the message ends.", sev)
	}
	return fmt.Sprintf(
		"%s: every reference implementation either agrees with the target or rejects "+
			"the input, so no message-boundary disagreement is known among the tested "+
			"peers. The target accepting an input the spec forbids is a leniency that "+
			"could pair with an untested peer. %d input(s) in this family.",
		sev, len(group))
}
