package specfuzz

import (
	"context"
	"fmt"
)

// ControlOutcome is the adapter's result on one control input.
type ControlOutcome struct {
	Control Control        `json:"control"`
	Expect  bool           `json:"expect"`
	Got     AdapterVerdict `json:"got"`
	Pass    bool           `json:"pass"`
}

// RunReport is the output of Run: control results, per-input classified
// results, and a summary count by class.
type RunReport struct {
	Clause      ClauseMeta       `json:"clause"`
	Source      string           `json:"lean_rfcs"`
	Controls    []ControlOutcome `json:"controls"`
	ControlPass bool             `json:"control_pass"`
	Results     []Result         `json:"results"`
	ByClass     map[Class]int    `json:"by_class"`
}

// Run executes the full clause run: controls first (adapter must pass
// every must_accept and must_reject), then the corpus. If controls
// fail, Results is empty and ControlPass is false; the caller decides
// whether that's a skill error (bad adapter) or a finding (repo
// mishandles baseline inputs).
func Run(ctx context.Context, c *Clause, adapter *Adapter) (*RunReport, error) {
	oracle, err := NewOracle(ctx, c.OracleWASM)
	if err != nil {
		return nil, err
	}
	defer func() { _ = oracle.Close(ctx) }()

	rep := &RunReport{
		Clause:  c.Meta,
		Source:  Source,
		ByClass: make(map[Class]int),
	}

	// Controls.
	var ctrlHex []string
	var ctrlExpect []bool
	for _, cc := range c.Controls.MustAccept {
		ctrlHex = append(ctrlHex, cc.Hex)
		ctrlExpect = append(ctrlExpect, true)
		rep.Controls = append(rep.Controls, ControlOutcome{Control: cc, Expect: true})
	}
	for _, cc := range c.Controls.MustReject {
		ctrlHex = append(ctrlHex, cc.Hex)
		ctrlExpect = append(ctrlExpect, false)
		rep.Controls = append(rep.Controls, ControlOutcome{Control: cc, Expect: false})
	}
	ctrlOut, err := adapter.FeedAll(ctx, ctrlHex)
	if err != nil {
		return nil, fmt.Errorf("adapter (controls): %w", err)
	}
	// must_accept failures mean the adapter cannot parse baseline
	// valid inputs, so it is broken (wrong entrypoint, wrong repo,
	// build failed) and the clause is skipped. must_reject failures
	// mean the target accepts something the oracle forbids; that is a
	// finding, not an adapter failure, so the run continues.
	rep.ControlPass = true
	for i := range rep.Controls {
		rep.Controls[i].Got = ctrlOut[i]
		rep.Controls[i].Pass = ctrlOut[i].Accept == ctrlExpect[i]
		if !rep.Controls[i].Pass && rep.Controls[i].Expect {
			rep.ControlPass = false
		}
	}
	if !rep.ControlPass {
		return rep, nil
	}

	// Corpus.
	hexes := make([]string, len(c.Corpus))
	for i, in := range c.Corpus {
		hexes[i] = in.Hex
	}
	ov, err := oracle.CheckAll(ctx, hexes)
	if err != nil {
		return nil, err
	}
	av, err := adapter.FeedAll(ctx, hexes)
	if err != nil {
		return nil, fmt.Errorf("adapter (corpus): %w", err)
	}
	for i, in := range c.Corpus {
		cls, diffs := Classify(ov[i], av[i], c.MatrixFor(in.ID), c.Matrix.AdapterVersions)
		rep.Results = append(rep.Results, Result{
			Input: in, Oracle: ov[i], Target: av[i],
			Class: cls, Differentials: diffs,
		})
		rep.ByClass[cls]++
	}
	return rep, nil
}

// Deviations returns only the results where the target deviates from
// the oracle, which are the candidate findings.
func (r *RunReport) Deviations() []Result {
	var out []Result
	for _, res := range r.Results {
		if res.Class == Deviates {
			out = append(out, res)
		}
	}
	return out
}
