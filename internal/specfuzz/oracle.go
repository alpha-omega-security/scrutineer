package specfuzz

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"

	"github.com/tetratelabs/wazero"
	"github.com/tetratelabs/wazero/imports/wasi_snapshot_preview1"
)

// Oracle wraps a compiled WASI oracle module. One per clause.
type Oracle struct {
	rt   wazero.Runtime
	mod  wazero.CompiledModule
	wasm []byte
}

// NewOracle compiles the clause's WASM oracle. The returned Oracle can
// be reused across many CheckAll calls; call Close when done.
func NewOracle(ctx context.Context, wasm []byte) (*Oracle, error) {
	rt := wazero.NewRuntime(ctx)
	wasi_snapshot_preview1.MustInstantiate(ctx, rt)
	mod, err := rt.CompileModule(ctx, wasm)
	if err != nil {
		_ = rt.Close(ctx)
		return nil, fmt.Errorf("compile oracle: %w", err)
	}
	return &Oracle{rt: rt, mod: mod, wasm: wasm}, nil
}

// Close releases the runtime.
func (o *Oracle) Close(ctx context.Context) error {
	return o.rt.Close(ctx)
}

// CheckAll runs the oracle over a batch of hex-encoded inputs and
// returns one verdict per input, in order. The WASI module reads
// newline-delimited hex on stdin and writes newline-delimited JSON
// verdicts on stdout, so the whole batch is one module instantiation.
func (o *Oracle) CheckAll(ctx context.Context, hexes []string) ([]OracleVerdict, error) {
	var stdin bytes.Buffer
	for _, h := range hexes {
		stdin.WriteString(h)
		stdin.WriteByte('\n')
	}
	var stdout, stderr bytes.Buffer
	cfg := wazero.NewModuleConfig().
		WithStdin(&stdin).
		WithStdout(&stdout).
		WithStderr(&stderr).
		WithName("")
	m, err := o.rt.InstantiateModule(ctx, o.mod, cfg)
	if err != nil {
		return nil, fmt.Errorf("oracle: %w (stderr: %s)", err, stderr.String())
	}
	_ = m.Close(ctx)
	out := make([]OracleVerdict, 0, len(hexes))
	sc := bufio.NewScanner(&stdout)
	sc.Buffer(make([]byte, 0, scanBuf), scanBuf)
	for sc.Scan() {
		var v OracleVerdict
		if err := json.Unmarshal(sc.Bytes(), &v); err != nil {
			return nil, fmt.Errorf("oracle output %q: %w", sc.Text(), err)
		}
		out = append(out, v)
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	if len(out) != len(hexes) {
		return nil, fmt.Errorf("oracle: %d inputs, %d verdicts (stderr: %s)",
			len(hexes), len(out), stderr.String())
	}
	return out, nil
}

// Adapter runs an external adapter process. The process reads
// newline-delimited hex on stdin and writes newline-delimited JSON
// AdapterVerdict on stdout.
type Adapter struct {
	// Run executes the adapter with the given stdin and returns stdout.
	// Callers supply this so the adapter can run in whatever sandbox
	// scrutineer already uses for repository code.
	Run func(ctx context.Context, stdin io.Reader) (stdout []byte, err error)
}

// FeedAll runs the adapter over a batch of hex inputs.
func (a *Adapter) FeedAll(ctx context.Context, hexes []string) ([]AdapterVerdict, error) {
	var stdin bytes.Buffer
	for _, h := range hexes {
		stdin.WriteString(h)
		stdin.WriteByte('\n')
	}
	stdout, err := a.Run(ctx, &stdin)
	if err != nil {
		return nil, err
	}
	out := make([]AdapterVerdict, 0, len(hexes))
	sc := bufio.NewScanner(bytes.NewReader(stdout))
	sc.Buffer(make([]byte, 0, scanBuf), scanBuf)
	for sc.Scan() {
		var v AdapterVerdict
		if err := json.Unmarshal(sc.Bytes(), &v); err != nil {
			return nil, fmt.Errorf("adapter output %q: %w", sc.Text(), err)
		}
		out = append(out, v)
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	if len(out) != len(hexes) {
		return nil, fmt.Errorf("adapter: %d inputs, %d verdicts", len(hexes), len(out))
	}
	return out, nil
}
