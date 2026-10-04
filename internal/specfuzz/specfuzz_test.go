package specfuzz

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"io"
	"strings"
	"testing"
)

func TestClauses(t *testing.T) {
	ids, err := Clauses()
	if err != nil {
		t.Fatal(err)
	}
	if len(ids) == 0 {
		t.Fatal("no clauses vendored")
	}
	found := false
	for _, id := range ids {
		if id == "rfc9112-7.1" {
			found = true
		}
	}
	if !found {
		t.Fatalf("rfc9112-7.1 not in %v", ids)
	}
}

func TestLoadClause(t *testing.T) {
	c, err := LoadClause("rfc9112-7.1")
	if err != nil {
		t.Fatal(err)
	}
	if c.Meta.ID != "rfc9112-7.1" {
		t.Errorf("Meta.ID = %q", c.Meta.ID)
	}
	if c.Meta.Citation == "" {
		t.Error("Meta.Citation empty")
	}
	if len(c.Corpus) == 0 {
		t.Error("Corpus empty")
	}
	if len(c.Controls.MustAccept) == 0 || len(c.Controls.MustReject) == 0 {
		t.Error("Controls incomplete")
	}
	if len(c.OracleWASM) == 0 {
		t.Error("OracleWASM empty")
	}
	if len(c.Matrix.Rows) != len(c.Corpus) {
		t.Errorf("matrix has %d rows, corpus has %d", len(c.Matrix.Rows), len(c.Corpus))
	}
	if c.MatrixFor(c.Corpus[0].ID) == nil {
		t.Error("MatrixFor first corpus input is nil")
	}
}

func TestLoadClauseUnknown(t *testing.T) {
	if _, err := LoadClause("rfc0000-0.0"); err == nil {
		t.Fatal("expected error for unknown clause")
	}
}

func TestOracleControls(t *testing.T) {
	c, err := LoadClause("rfc9112-7.1")
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	o, err := NewOracle(ctx, c.OracleWASM)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = o.Close(ctx) }()
	var hexes []string
	var expect []bool
	for _, cc := range c.Controls.MustAccept {
		hexes = append(hexes, cc.Hex)
		expect = append(expect, true)
	}
	for _, cc := range c.Controls.MustReject {
		hexes = append(hexes, cc.Hex)
		expect = append(expect, false)
	}
	got, err := o.CheckAll(ctx, hexes)
	if err != nil {
		t.Fatal(err)
	}
	for i := range hexes {
		if got[i].Valid != expect[i] {
			t.Errorf("control %d hex=%s: oracle valid=%v, want %v",
				i, hexes[i], got[i].Valid, expect[i])
		}
	}
}

func TestOracleMatchesVendoredMatrix(t *testing.T) {
	c, err := LoadClause("rfc9112-7.1")
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	o, err := NewOracle(ctx, c.OracleWASM)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = o.Close(ctx) }()
	hexes := make([]string, len(c.Corpus))
	for i, in := range c.Corpus {
		hexes[i] = in.Hex
	}
	got, err := o.CheckAll(ctx, hexes)
	if err != nil {
		t.Fatal(err)
	}
	for i, in := range c.Corpus {
		row := c.MatrixFor(in.ID)
		if row == nil {
			t.Fatalf("no matrix row for %s", in.ID)
		}
		if got[i].Valid != row.Oracle.Valid {
			t.Errorf("%s: wasm oracle valid=%v, matrix says %v",
				in.ID, got[i].Valid, row.Oracle.Valid)
		}
	}
}

// h11015Adapter mimics h11 0.15.0's behaviour: accepts any two bytes
// after chunk-data (CVE-2025-43859). Enough to test that Run flags it.
func h11015Adapter(ctx context.Context, stdin io.Reader) ([]byte, error) {
	var out bytes.Buffer
	sc := newLineScanner(stdin)
	for sc.Scan() {
		buf, err := hex.DecodeString(sc.Text())
		if err != nil {
			out.WriteString(`{"accept":false,"error":"bad-hex"}` + "\n")
			continue
		}
		body, ok := parseChunkedLenient(buf)
		v := AdapterVerdict{Accept: ok}
		if ok {
			v.BodyHex = hex.EncodeToString(body)
		} else {
			v.Error = "reject"
		}
		b, _ := json.Marshal(v)
		out.Write(b)
		out.WriteByte('\n')
	}
	return out.Bytes(), sc.Err()
}

// strictAdapter delegates to the vendored oracle's own verdict via
// the matrix (i.e. behaves exactly as the oracle expects). Used to
// prove Run reports Conformant when the adapter is correct.
func strictAdapter(c *Clause) func(context.Context, io.Reader) ([]byte, error) {
	byHex := map[string]OracleVerdict{}
	for _, r := range c.Matrix.Rows {
		byHex[r.ID] = r.Oracle
	}
	idFor := map[string]string{}
	for _, in := range c.Corpus {
		idFor[in.Hex] = in.ID
	}
	return func(ctx context.Context, stdin io.Reader) ([]byte, error) {
		var out bytes.Buffer
		sc := newLineScanner(stdin)
		for sc.Scan() {
			h := sc.Text()
			ov, ok := byHex[idFor[h]]
			var v AdapterVerdict
			if !ok {
				// Controls: fall back to the strict parser.
				buf, _ := hex.DecodeString(h)
				body, acc := parseChunkedStrict(buf)
				v = AdapterVerdict{Accept: acc, BodyHex: hex.EncodeToString(body)}
			} else {
				v = AdapterVerdict{Accept: ov.Valid}
				if ov.BodyHex != nil {
					v.BodyHex = *ov.BodyHex
				}
			}
			b, _ := json.Marshal(v)
			out.Write(b)
			out.WriteByte('\n')
		}
		return out.Bytes(), sc.Err()
	}
}

func TestRunConformant(t *testing.T) {
	c, err := LoadClause("rfc9112-7.1")
	if err != nil {
		t.Fatal(err)
	}
	rep, err := Run(context.Background(), c, &Adapter{Run: strictAdapter(c)})
	if err != nil {
		t.Fatal(err)
	}
	if !rep.ControlPass {
		t.Fatalf("controls failed: %+v", rep.Controls)
	}
	if rep.ByClass[Deviates] != 0 {
		t.Errorf("strict adapter has %d Deviates", rep.ByClass[Deviates])
	}
	if rep.ByClass[Conformant] != len(c.Corpus) {
		t.Errorf("Conformant = %d, want %d", rep.ByClass[Conformant], len(c.Corpus))
	}
}

func TestRunDeviates(t *testing.T) {
	c, err := LoadClause("rfc9112-7.1")
	if err != nil {
		t.Fatal(err)
	}
	rep, err := Run(context.Background(), c, &Adapter{Run: h11015Adapter})
	if err != nil {
		t.Fatal(err)
	}
	if !rep.ControlPass {
		t.Fatalf("controls failed: %+v", rep.Controls)
	}
	devs := rep.Deviations()
	if len(devs) == 0 {
		t.Fatal("h11-0.15.0-shaped adapter produced no Deviates")
	}
	// Every deviation should include a data_crlf:v4-labelled input,
	// and each should have differentials against the reference set.
	sawCVE := false
	for _, d := range devs {
		if strings.Contains(d.Input.Label, "data_crlf:v4") {
			sawCVE = true
		}
		if len(d.Differentials) == 0 {
			t.Errorf("%s: Deviates with no differentials", d.Input.ID)
		}
		if AnyBoundary(d.Differentials) {
			t.Errorf("%s: unexpected boundary-class differential against reference set (all references are strict)", d.Input.ID)
		}
	}
	if !sawCVE {
		t.Error("no data_crlf:v4 deviation (the CVE-2025-43859 shape)")
	}
}

func TestRunControlFail(t *testing.T) {
	c, err := LoadClause("rfc9112-7.1")
	if err != nil {
		t.Fatal(err)
	}
	// Adapter that rejects everything: fails must_accept controls,
	// which is the gate that indicates a broken adapter.
	never := func(ctx context.Context, stdin io.Reader) ([]byte, error) {
		var out bytes.Buffer
		sc := newLineScanner(stdin)
		for sc.Scan() {
			out.WriteString(`{"accept":false,"error":"nope"}` + "\n")
		}
		return out.Bytes(), sc.Err()
	}
	rep, err := Run(context.Background(), c, &Adapter{Run: never})
	if err != nil {
		t.Fatal(err)
	}
	if rep.ControlPass {
		t.Fatal("reject-everything adapter passed controls")
	}
	if len(rep.Results) != 0 {
		t.Errorf("Results should be empty when controls fail, got %d", len(rep.Results))
	}
}

func TestClassify(t *testing.T) {
	i5, i18 := 5, 18
	cases := []struct {
		name   string
		oracle OracleVerdict
		target AdapterVerdict
		row    *MatrixRow
		wantC  Class
		wantP  map[string]PeerClass
	}{
		{
			name:   "conformant reject",
			oracle: OracleVerdict{Valid: false},
			target: AdapterVerdict{Accept: false},
			wantC:  Conformant,
		},
		{
			name:   "deviates",
			oracle: OracleVerdict{Valid: false},
			target: AdapterVerdict{Accept: true, BodyHex: "aa"},
			row: &MatrixRow{Adapters: map[string]AdapterVerdict{
				"ref": {Accept: false},
			}},
			wantC: Deviates,
			wantP: map[string]PeerClass{"ref": PeerAcceptError},
		},
		{
			name:   "over-strict",
			oracle: OracleVerdict{Valid: true},
			target: AdapterVerdict{Accept: false},
			wantC:  OverStrict,
		},
		{
			name:   "peer boundary via consumed",
			oracle: OracleVerdict{Valid: false},
			target: AdapterVerdict{Accept: true, BodyHex: "aa", Consumed: &i5},
			row: &MatrixRow{Adapters: map[string]AdapterVerdict{
				"ref": {Accept: true, BodyHex: "aa", Consumed: &i18},
			}},
			wantC: Deviates,
			wantP: map[string]PeerClass{"ref": PeerBoundary},
		},
		{
			name:   "peer value via body",
			oracle: OracleVerdict{Valid: false},
			target: AdapterVerdict{Accept: true, BodyHex: "aa"},
			row: &MatrixRow{Adapters: map[string]AdapterVerdict{
				"ref": {Accept: true, BodyHex: "bb"},
			}},
			wantC: Deviates,
			wantP: map[string]PeerClass{"ref": PeerValue},
		},
		{
			name:   "peer agree",
			oracle: OracleVerdict{Valid: false},
			target: AdapterVerdict{Accept: true, BodyHex: "aa"},
			row: &MatrixRow{Adapters: map[string]AdapterVerdict{
				"ref": {Accept: true, BodyHex: "aa"},
			}},
			wantC: Deviates,
			wantP: map[string]PeerClass{"ref": PeerAgree},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cls, diffs := Classify(tc.oracle, tc.target, tc.row, nil)
			if cls != tc.wantC {
				t.Errorf("class = %s, want %s", cls, tc.wantC)
			}
			for _, d := range diffs {
				if want, ok := tc.wantP[d.Peer]; ok && d.Class != want {
					t.Errorf("peer %s class = %s, want %s", d.Peer, d.Class, want)
				}
			}
		})
	}
}

func TestSource(t *testing.T) {
	if !strings.Contains(Source, "lean-rfcs") {
		t.Errorf("Source = %q, want lean-rfcs reference", Source)
	}
}
