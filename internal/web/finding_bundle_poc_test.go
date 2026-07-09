package web

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
)

func pocEntries(t *testing.T, entries []bundleEntry) map[string]bundleEntry {
	t.Helper()
	out := map[string]bundleEntry{}
	for _, e := range entries {
		out[e.Name] = e
	}
	return out
}

func TestBundlePoC_shellBlockBecomesRunSh(t *testing.T) {
	validation := "Run the following against a local server:\n\n" +
		"```sh\ncurl -s http://127.0.0.1:8080/v1 -d @input.json\n```\n\n" +
		"Expected: HTTP 500 with the stack trace in the body."
	got := pocEntries(t, bundlePoC(validation))

	run, ok := got["poc/run.sh"]
	if !ok {
		t.Fatalf("missing poc/run.sh; have %v", keys(got))
	}
	if string(run.Data) != "curl -s http://127.0.0.1:8080/v1 -d @input.json\n" {
		t.Errorf("run.sh body = %q", run.Data)
	}
	if run.Mode != runShMode {
		t.Errorf("run.sh mode = %#o, want %#o", run.Mode, runShMode)
	}
	readme, ok := got["poc/README.md"]
	if !ok {
		t.Fatal("missing poc/README.md")
	}
	if !strings.Contains(string(readme.Data), "Expected: HTTP 500") {
		t.Errorf("README.md must carry the surrounding prose so the fingerprint survives: %q", readme.Data)
	}
	if len(got) != 2 {
		t.Errorf("want exactly run.sh + README.md, got %v", keys(got))
	}
}

func TestBundlePoC_languageProbeGetsGeneratedRunSh(t *testing.T) {
	validation := "```python\nimport requests\nrequests.post('http://127.0.0.1:8000/x', json={'a': 1})\n```"
	got := pocEntries(t, bundlePoC(validation))

	if _, ok := got["poc/probe.py"]; !ok {
		t.Fatalf("missing poc/probe.py; have %v", keys(got))
	}
	run, ok := got["poc/run.sh"]
	if !ok {
		t.Fatalf("missing generated poc/run.sh; have %v", keys(got))
	}
	body := string(run.Data)
	if !strings.HasPrefix(body, "#!/bin/sh\n") {
		t.Errorf("generated run.sh missing shebang: %q", body)
	}
	if !strings.Contains(body, "python3 probe.py") {
		t.Errorf("generated run.sh should invoke the probe: %q", body)
	}
	if run.Mode != runShMode {
		t.Errorf("generated run.sh mode = %#o, want %#o", run.Mode, runShMode)
	}
}

func TestBundlePoC_compiledProbeGetsReadmeFallbackRunSh(t *testing.T) {
	// Go, Rust, C, Java have no one-line runner; the generated run.sh must
	// exit non-zero pointing at README rather than pretend to know how to
	// build the probe.
	validation := "```go\npackage main\nfunc main() { panic(1) }\n```"
	got := pocEntries(t, bundlePoC(validation))
	run := string(got["poc/run.sh"].Data)
	if !strings.Contains(run, "README.md") || !strings.Contains(run, "exit 2") {
		t.Errorf("compiled-language fallback run.sh should point at README and exit 2: %q", run)
	}
	if _, ok := got["poc/probe.go"]; !ok {
		t.Errorf("missing poc/probe.go; have %v", keys(got))
	}
}

func TestBundlePoC_multipleBlocksSameLangAreNumbered(t *testing.T) {
	validation := "```ruby\nputs 1\n```\nthen\n```ruby\nputs 2\n```\nand a payload:\n```json\n{\"x\":1}\n```"
	got := pocEntries(t, bundlePoC(validation))
	for _, want := range []string{"poc/probe.rb", "poc/probe-2.rb", "poc/input.json", "poc/run.sh", "poc/README.md"} {
		if _, ok := got[want]; !ok {
			t.Errorf("missing %s; have %v", want, keys(got))
		}
	}
	if string(got["poc/probe.rb"].Data) != "puts 1\n" {
		t.Errorf("probe.rb body = %q, want first block", got["poc/probe.rb"].Data)
	}
	if string(got["poc/probe-2.rb"].Data) != "puts 2\n" {
		t.Errorf("probe-2.rb body = %q, want second block", got["poc/probe-2.rb"].Data)
	}
	// The generated run.sh drives the first probe, not the numbered one.
	if !strings.Contains(string(got["poc/run.sh"].Data), "ruby probe.rb") {
		t.Errorf("run.sh should invoke the first probe: %q", got["poc/run.sh"].Data)
	}
}

func TestBundlePoC_shellBlockWinsOverGeneratedRunSh(t *testing.T) {
	// When the validation supplies both a language probe and a shell driver,
	// the shell block IS run.sh; do not overwrite it with a generated stub.
	validation := "```python\nprint('x')\n```\n\n```bash\npython3 probe.py --flag\n```"
	got := pocEntries(t, bundlePoC(validation))
	if body := string(got["poc/run.sh"].Data); body != "python3 probe.py --flag\n" {
		t.Errorf("run.sh should be the authored shell block verbatim, got %q", body)
	}
}

func TestBundlePoC_unknownLangUsesInfoStringAsExtension(t *testing.T) {
	validation := "```lua\nprint('x')\n```"
	got := pocEntries(t, bundlePoC(validation))
	if _, ok := got["poc/probe.lua"]; !ok {
		t.Errorf("unknown fence lang should become probe.<lang>; have %v", keys(got))
	}
}

func TestBundlePoC_noFencedBlocksReturnsNil(t *testing.T) {
	if got := bundlePoC(""); got != nil {
		t.Errorf("empty validation: got %d entries, want nil", len(got))
	}
	if got := bundlePoC("prose only, no code"); got != nil {
		t.Errorf("prose-only validation: got %d entries, want nil", len(got))
	}
	// A fence whose body is whitespace-only is dropped; if that was the only
	// block, the whole poc/ is dropped.
	if got := bundlePoC("```\n   \n```"); got != nil {
		t.Errorf("whitespace-only block: got %d entries, want nil", len(got))
	}
}

func TestBundlePoC_trailingNewlineNormalised(t *testing.T) {
	// A block whose closing fence sits on the same line as the last content
	// byte still gets a trailing newline so the file is a well-formed text
	// file the recipient can cat/diff cleanly.
	got := pocEntries(t, bundlePoC("```sh\necho hi```"))
	if body := string(got["poc/run.sh"].Data); body != "echo hi\n" {
		t.Errorf("run.sh = %q, want trailing newline added", body)
	}
}

func TestSuffixBeforeExt(t *testing.T) {
	cases := []struct {
		name string
		n    int
		want string
	}{
		{"probe.py", 2, "probe-2.py"},
		{"run.sh", 3, "run-3.sh"},
		{"Probe.java", 2, "Probe-2.java"},
		{"noext", 4, "noext-4"},
		{".rc", 2, ".rc-2"},
	}
	for _, tc := range cases {
		if got := suffixBeforeExt(tc.name, tc.n); got != tc.want {
			t.Errorf("suffixBeforeExt(%q, %d) = %q, want %q", tc.name, tc.n, got, tc.want)
		}
	}
}

func TestBuildTarGz_honoursEntryMode(t *testing.T) {
	entries := []bundleEntry{
		{Name: "a.txt", Data: []byte("x")},
		{Name: "run.sh", Data: []byte("#!/bin/sh\n"), Mode: runShMode},
	}
	body, err := buildTarGz(entries)
	if err != nil {
		t.Fatal(err)
	}
	gz, _ := gzip.NewReader(bytes.NewReader(body))
	tr := tar.NewReader(gz)
	modes := map[string]int64{}
	for {
		h, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		modes[h.Name] = h.Mode
		_, _ = io.Copy(io.Discard, tr)
	}
	if modes["a.txt"] != 0o644 {
		t.Errorf("a.txt mode = %#o, want 0644 default", modes["a.txt"])
	}
	if modes["run.sh"] != runShMode {
		t.Errorf("run.sh mode = %#o, want %#o", modes["run.sh"], runShMode)
	}
}

func TestFindingBundle_includesPoCWhenValidationHasFence(t *testing.T) {
	s, done := newTestServer(t)
	defer done()
	f := setUpBundleFinding(t, s, false)
	s.DB.Model(f).Update("validation",
		"Trigger:\n\n```sh\necho boom | ./src/bin/widget --stdin\n```\n\nObserved: SIGSEGV.")

	r := httptest.NewRequest(http.MethodGet,
		"/findings/"+strconv.Itoa(int(f.ID))+"/bundle.tar.gz", nil)
	r.Host = "127.0.0.1:8080"
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, r)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", w.Code, w.Body.String())
	}
	files := readArchive(t, w.Body.Bytes())
	if _, ok := files["poc/run.sh"]; !ok {
		t.Errorf("archive missing poc/run.sh; have %v", keys(files))
	}
	if _, ok := files["poc/README.md"]; !ok {
		t.Errorf("archive missing poc/README.md; have %v", keys(files))
	}
	var m bundleManifest
	if err := json.Unmarshal(files["manifest.json"], &m); err != nil {
		t.Fatalf("decode manifest: %v", err)
	}
	if _, ok := m.Contents["poc/"]; !ok {
		t.Errorf("manifest.contents missing poc/: %+v", m.Contents)
	}
}

func TestFindingBundle_omitsPoCWhenValidationHasNoFence(t *testing.T) {
	s, done := newTestServer(t)
	defer done()
	f := setUpBundleFinding(t, s, false)
	s.DB.Model(f).Update("validation", "prose description only, no runnable block")

	r := httptest.NewRequest(http.MethodGet,
		"/findings/"+strconv.Itoa(int(f.ID))+"/bundle.tar.gz", nil)
	r.Host = "127.0.0.1:8080"
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, r)
	files := readArchive(t, w.Body.Bytes())
	for name := range files {
		if strings.HasPrefix(name, "poc/") {
			t.Errorf("archive should omit poc/ when validation has no fenced block; have %v", keys(files))
			break
		}
	}
	var m bundleManifest
	_ = json.Unmarshal(files["manifest.json"], &m)
	if _, ok := m.Contents["poc/"]; ok {
		t.Errorf("manifest.contents should omit poc/ without a fenced block")
	}
}
