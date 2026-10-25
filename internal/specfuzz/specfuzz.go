// Package specfuzz runs a target adapter against a vendored lean-rfcs
// oracle and reference matrix, and classifies each corpus input.
//
// The oracle is a WASI module compiled from the Lean model; it reads
// hex-encoded inputs on stdin and writes {"valid":bool,"body":"hex"}
// per line. An adapter is any executable satisfying the same stdin
// contract that writes {"accept":bool,"body_hex":"...","consumed":N}.
package specfuzz

import (
	"bufio"
	"embed"
	"encoding/json"
	"fmt"
	"io/fs"
	"path"
)

const scanBuf = 1 << 20

//go:embed vendor
var vendored embed.FS

// Source is the lean-rfcs commit the vendored artefacts came from.
//
//go:embed vendor/SOURCE
var Source string

// ClauseMeta is the per-clause metadata from clause.json.
type ClauseMeta struct {
	ID       string `json:"id"`
	Citation string `json:"citation"`
	Protocol string `json:"protocol"`
}

// CorpusInput is one line of a clause's corpus/seed0.jsonl.
type CorpusInput struct {
	ID    string `json:"id"`
	Label string `json:"label"`
	Hex   string `json:"hex"`
}

// OracleVerdict is one oracle decision. The vendored matrix encodes it
// as {accept, body_hex}; the WASM oracle currently emits {valid, body}.
// UnmarshalJSON accepts either.
type OracleVerdict struct {
	Valid   bool
	BodyHex *string
}

// UnmarshalJSON accepts both {accept,body_hex} and {valid,body}.
func (v *OracleVerdict) UnmarshalJSON(b []byte) error {
	var raw struct {
		Accept  *bool   `json:"accept"`
		BodyHex *string `json:"body_hex"`
		Valid   *bool   `json:"valid"`
		Body    *string `json:"body"`
	}
	if err := json.Unmarshal(b, &raw); err != nil {
		return err
	}
	switch {
	case raw.Accept != nil:
		v.Valid = *raw.Accept
	case raw.Valid != nil:
		v.Valid = *raw.Valid
	}
	if raw.BodyHex != nil {
		v.BodyHex = raw.BodyHex
	} else {
		v.BodyHex = raw.Body
	}
	return nil
}

// MarshalJSON emits the design-doc form.
func (v OracleVerdict) MarshalJSON() ([]byte, error) {
	return json.Marshal(struct {
		Accept  bool    `json:"accept"`
		BodyHex *string `json:"body_hex"`
	}{v.Valid, v.BodyHex})
}

// AdapterVerdict is one line of adapter output.
type AdapterVerdict struct {
	Accept   bool   `json:"accept"`
	BodyHex  string `json:"body_hex"`
	Consumed *int   `json:"consumed,omitempty"`
	Error    string `json:"error,omitempty"`
}

// MatrixRow is one input's oracle verdict plus every reference
// adapter's verdict, from matrix/<clause>.json.
type MatrixRow struct {
	ID       string                    `json:"id"`
	Oracle   OracleVerdict             `json:"oracle"`
	Adapters map[string]AdapterVerdict `json:"-"`
}

// Matrix is the reference-adapter behaviour table for one clause.
type Matrix struct {
	Clause          string            `json:"clause"`
	Adapters        []string          `json:"adapters"`
	AdapterVersions map[string]string `json:"adapter_versions"`
	Rows            []MatrixRow       `json:"rows"`
}

// Clauses returns the ids of every vendored clause.
func Clauses() ([]string, error) {
	var ids []string
	err := fs.WalkDir(vendored, "vendor/clauses", func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() || d.Name() != "clause.json" {
			return err
		}
		var m ClauseMeta
		if err := readJSON(p, &m); err != nil {
			return err
		}
		ids = append(ids, m.ID)
		return nil
	})
	return ids, err
}

// LoadClause returns the metadata, corpus, oracle wasm, and reference
// matrix for one clause id.
func LoadClause(id string) (*Clause, error) {
	dir, err := findClauseDir(id)
	if err != nil {
		return nil, err
	}
	var c Clause
	if err := readJSON(path.Join(dir, "clause.json"), &c.Meta); err != nil {
		return nil, err
	}
	c.Corpus, err = readCorpus(path.Join(dir, "corpus", "seed0.jsonl"))
	if err != nil {
		return nil, err
	}
	if err := readJSON(path.Join(dir, "controls.json"), &c.Controls); err != nil {
		return nil, err
	}
	c.OracleWASM, err = vendored.ReadFile(path.Join("vendor", "dist", id+"-oracle.wasm"))
	if err != nil {
		return nil, err
	}
	if err := readMatrix(path.Join("vendor", "matrix", id+".json"), &c.Matrix); err != nil {
		return nil, err
	}
	c.matrixByID = make(map[string]*MatrixRow, len(c.Matrix.Rows))
	for i := range c.Matrix.Rows {
		c.matrixByID[c.Matrix.Rows[i].ID] = &c.Matrix.Rows[i]
	}
	return &c, nil
}

// Clause bundles everything needed to run one clause against a target.
type Clause struct {
	Meta       ClauseMeta
	Corpus     []CorpusInput
	Controls   Controls
	OracleWASM []byte
	Matrix     Matrix
	matrixByID map[string]*MatrixRow
}

// Controls is a clause's must_accept / must_reject list.
type Controls struct {
	MustAccept []Control `json:"must_accept"`
	MustReject []Control `json:"must_reject"`
}

// Control is one entry in controls.json.
type Control struct {
	ID  string `json:"id"`
	Hex string `json:"hex"`
	Why string `json:"why"`
}

// MatrixFor returns the reference-adapter row for one corpus input, or
// nil if the input is not in the matrix (e.g. a control).
func (c *Clause) MatrixFor(inputID string) *MatrixRow {
	return c.matrixByID[inputID]
}

func findClauseDir(id string) (string, error) {
	var found string
	err := fs.WalkDir(vendored, "vendor/clauses", func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() || d.Name() != "clause.json" {
			return err
		}
		var m ClauseMeta
		if err := readJSON(p, &m); err != nil {
			return err
		}
		if m.ID == id {
			found = path.Dir(p)
			return fs.SkipAll
		}
		return nil
	})
	if err != nil {
		return "", err
	}
	if found == "" {
		return "", fmt.Errorf("clause %q not vendored", id)
	}
	return found, nil
}

func readJSON(p string, v any) error {
	b, err := vendored.ReadFile(p)
	if err != nil {
		return err
	}
	return json.Unmarshal(b, v)
}

func readCorpus(p string) ([]CorpusInput, error) {
	f, err := vendored.Open(p)
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	var out []CorpusInput
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, scanBuf), scanBuf)
	for sc.Scan() {
		var c CorpusInput
		if err := json.Unmarshal(sc.Bytes(), &c); err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, sc.Err()
}

func readMatrix(p string, m *Matrix) error {
	// Rows carry adapter columns as sibling keys of "id" and "oracle";
	// decode into a raw map first, then split.
	var raw struct {
		Clause          string            `json:"clause"`
		Adapters        []string          `json:"adapters"`
		AdapterVersions map[string]string `json:"adapter_versions"`
		Rows            []json.RawMessage `json:"rows"`
	}
	if err := readJSON(p, &raw); err != nil {
		return err
	}
	m.Clause = raw.Clause
	m.Adapters = raw.Adapters
	m.AdapterVersions = raw.AdapterVersions
	m.Rows = make([]MatrixRow, 0, len(raw.Rows))
	for _, rr := range raw.Rows {
		var head struct {
			ID     string        `json:"id"`
			Oracle OracleVerdict `json:"oracle"`
		}
		if err := json.Unmarshal(rr, &head); err != nil {
			return err
		}
		var full map[string]json.RawMessage
		if err := json.Unmarshal(rr, &full); err != nil {
			return err
		}
		row := MatrixRow{ID: head.ID, Oracle: head.Oracle,
			Adapters: make(map[string]AdapterVerdict, len(raw.Adapters))}
		for _, a := range raw.Adapters {
			var av AdapterVerdict
			if err := json.Unmarshal(full[a], &av); err != nil {
				return fmt.Errorf("row %s adapter %s: %w", head.ID, a, err)
			}
			row.Adapters[a] = av
		}
		m.Rows = append(m.Rows, row)
	}
	return nil
}
