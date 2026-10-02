package web

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
)

func mustBundlePoC(t *testing.T, validation string) []bundleEntry {
	t.Helper()
	entries, err := bundlePoC(validation)
	if err != nil {
		t.Fatal(err)
	}
	return entries
}

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
	got := pocEntries(t, mustBundlePoC(t, validation))

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
	got := pocEntries(t, mustBundlePoC(t, validation))

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

func TestBundlePoC_languageFenceAllowsLeadingWhitespace(t *testing.T) {
	validation := "``` python\nprint('x')\n```"
	got := pocEntries(t, mustBundlePoC(t, validation))
	if _, ok := got["poc/probe.py"]; !ok {
		t.Fatalf("missing poc/probe.py for spaced info string; have %v", keys(got))
	}
	if _, ok := got["poc/transcript.txt"]; ok {
		t.Fatalf("spaced python fence was treated as transcript; have %v", keys(got))
	}
}

func TestBundlePoC_compiledProbeGetsReadmeFallbackRunSh(t *testing.T) {
	// Go, Rust, C, Java have no one-line runner; the generated run.sh must
	// exit non-zero pointing at README rather than pretend to know how to
	// build the probe.
	validation := "```go\npackage main\nfunc main() { panic(1) }\n```"
	got := pocEntries(t, mustBundlePoC(t, validation))
	runEntry, ok := got["poc/run.sh"]
	if !ok {
		t.Fatalf("missing generated poc/run.sh; have %v", keys(got))
	}
	run := string(runEntry.Data)
	if !strings.Contains(run, "README.md") || !strings.Contains(run, "exit 2") {
		t.Errorf("compiled-language fallback run.sh should point at README and exit 2: %q", run)
	}
	if _, ok := got["poc/probe.go"]; !ok {
		t.Errorf("missing poc/probe.go; have %v", keys(got))
	}
}

func TestBundlePoC_multipleBlocksSameLangAreNumbered(t *testing.T) {
	validation := "```ruby\nputs 1\n```\nthen\n```ruby\nputs 2\n```\nand a payload:\n```json\n{\"x\":1}\n```"
	got := pocEntries(t, mustBundlePoC(t, validation))
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
	got := pocEntries(t, mustBundlePoC(t, validation))
	run, ok := got["poc/run.sh"]
	if !ok {
		t.Fatalf("missing authored poc/run.sh; have %v", keys(got))
	}
	if body := string(run.Data); body != "python3 probe.py --flag\n" {
		t.Errorf("run.sh should be the authored shell block verbatim, got %q", body)
	}
}

func TestBundlePoC_duplicateShellBlocksStayExecutable(t *testing.T) {
	validation := "```sh\necho one\n```\n\n```bash\necho two\n```"
	got := pocEntries(t, mustBundlePoC(t, validation))
	for _, name := range []string{"poc/run.sh", "poc/run-2.sh"} {
		entry, ok := got[name]
		if !ok {
			t.Fatalf("missing %s; have %v", name, keys(got))
		}
		if entry.Mode != runShMode {
			t.Errorf("%s mode = %#o, want %#o", name, entry.Mode, runShMode)
		}
	}
}

func TestBundlePoC_consoleBlockBecomesTranscript(t *testing.T) {
	validation := "```console\n$ curl -i http://127.0.0.1:8080/poc\nHTTP/1.1 500 Internal Server Error\nboom\n```"
	got := pocEntries(t, mustBundlePoC(t, validation))
	if _, ok := got["poc/session.txt"]; !ok {
		t.Fatalf("missing poc/session.txt; have %v", keys(got))
	}
	if string(got["poc/session.txt"].Data) != "$ curl -i http://127.0.0.1:8080/poc\nHTTP/1.1 500 Internal Server Error\nboom\n" {
		t.Errorf("session transcript body = %q", got["poc/session.txt"].Data)
	}
	run := string(got["poc/run.sh"].Data)
	if !strings.Contains(run, "README.md") || !strings.Contains(run, "exit 2") {
		t.Errorf("console transcript should get README fallback run.sh, got %q", run)
	}
}

func TestBundlePoC_unmarkedBlockBecomesTranscript(t *testing.T) {
	validation := "```\n$ ./poc\nexpected output\n```"
	got := pocEntries(t, mustBundlePoC(t, validation))
	if _, ok := got["poc/transcript.txt"]; !ok {
		t.Fatalf("missing poc/transcript.txt; have %v", keys(got))
	}
	if body := string(got["poc/run.sh"].Data); !strings.Contains(body, "exit 2") {
		t.Errorf("unmarked transcript should not be executable run.sh, got %q", body)
	}
}

func TestBundlePoC_unknownLangUsesInfoStringAsExtension(t *testing.T) {
	validation := "```lua\nprint('x')\n```"
	got := pocEntries(t, mustBundlePoC(t, validation))
	if _, ok := got["poc/probe.lua"]; !ok {
		t.Errorf("unknown fence lang should become probe.<lang>; have %v", keys(got))
	}
}

func TestBundlePoC_noFencedBlocksReturnsNil(t *testing.T) {
	if got := mustBundlePoC(t, ""); got != nil {
		t.Errorf("empty validation: got %d entries, want nil", len(got))
	}
	if got := mustBundlePoC(t, "prose only, no code"); got != nil {
		t.Errorf("prose-only validation: got %d entries, want nil", len(got))
	}
	// A fence whose body is whitespace-only is dropped; if that was the only
	// block, the whole poc/ is dropped.
	if got := mustBundlePoC(t, "```\n   \n```"); got != nil {
		t.Errorf("whitespace-only block: got %d entries, want nil", len(got))
	}
}

func TestBundlePoC_embeddedBackticksPreserved(t *testing.T) {
	for _, fence := range []string{"````sh", "~~~sh", "```sh filename=run.sh"} {
		t.Run(fence, func(t *testing.T) {
			closing, _, _ := strings.Cut(fence, "sh")
			want := "printf '%s\\n' '```'\n# literal ```\necho done\n"
			got := pocEntries(t, mustBundlePoC(t, fence+"\n"+want+closing+"\n"))
			if body := string(got["poc/run.sh"].Data); body != want {
				t.Errorf("run.sh = %q, want %q", body, want)
			}
		})
	}
}

func TestFindingBundle_legacyGluedFences(t *testing.T) {
	s, done := newTestServer(t)
	defer done()
	f := setUpBundleFinding(t, s, false)
	validation := "```sh\nprintf 'hi\\n'```\n\nExpected output:\n```text\nhi```\n\n" +
		"```text filename=inputs/value.txt\nnamed file\n```\n"
	if err := s.DB.Model(f).Update("validation", validation).Error; err != nil {
		t.Fatal(err)
	}
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, localReq(http.MethodGet, "/findings/"+strconv.Itoa(int(f.ID))+"/bundle.tar.gz"))
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d: %s", w.Code, w.Body)
	}
	files := readArchive(t, w.Body.Bytes())
	for name, want := range map[string]string{
		"poc/run.sh":           "printf 'hi\\n'\n",
		"poc/transcript.txt":   "hi\n",
		"poc/inputs/value.txt": "named file\n",
	} {
		if string(files[name]) != want {
			t.Errorf("%s = %q, want %q", name, files[name], want)
		}
	}
	script := filepath.Join(t.TempDir(), "run.sh")
	if err := os.WriteFile(script, files["poc/run.sh"], 0o600); err != nil {
		t.Fatal(err)
	}
	output, err := exec.CommandContext(t.Context(), "sh", script).CombinedOutput()
	if err != nil || string(output) != "hi\n" {
		t.Fatalf("downloaded script: %v, output %q", err, output)
	}
}

func TestFindingBundle_namedRunShIsExecutable(t *testing.T) {
	s, done := newTestServer(t)
	defer done()
	f := setUpBundleFinding(t, s, false)
	validation := "```text filename=run.sh\n#!/bin/sh\nprintf 'named driver\\n'\n```\n"
	if err := s.DB.Model(f).Update("validation", validation).Error; err != nil {
		t.Fatal(err)
	}
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, localReq(http.MethodGet, "/findings/"+strconv.Itoa(int(f.ID))+"/bundle.tar.gz"))
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d: %s", w.Code, w.Body)
	}
	gz, err := gzip.NewReader(bytes.NewReader(w.Body.Bytes()))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = gz.Close() }()
	archive := tar.NewReader(gz)
	for {
		header, err := archive.Next()
		if err != nil {
			t.Fatalf("missing run.sh: %v", err)
		}
		if header.Name != "poc/run.sh" {
			continue
		}
		if header.Mode != runShMode {
			t.Fatalf("run.sh mode = %#o, want %#o", header.Mode, runShMode)
		}
		if runtime.GOOS == "windows" {
			return
		}
		body, err := io.ReadAll(archive)
		if err != nil {
			t.Fatal(err)
		}
		path := filepath.Join(t.TempDir(), "run.sh")
		if err := os.WriteFile(path, body, os.FileMode(header.Mode)); err != nil {
			t.Fatal(err)
		}
		output, err := exec.CommandContext(t.Context(), path).CombinedOutput()
		if err != nil || string(output) != "named driver\n" {
			t.Fatalf("downloaded driver = %q, %v", output, err)
		}
		return
	}
}

func TestFindingBundle_omitsUnterminatedNamedPoC(t *testing.T) {
	s, done := newTestServer(t)
	defer done()
	f := setUpBundleFinding(t, s, true)
	seedBundleDependent(t, s, f.RepositoryID)
	for _, validation := range []string{
		"```sh filename=run.sh\necho hi\n\nExpected output: hi\n",
		"```text filename=empty.txt",
		"```sh filename=run.sh\necho hi\n~~~\n",
		"````sh filename=run.sh\necho hi\n```\n",
		"> ```text filename=quoted.txt\n> content\n\noutside quote\n",
	} {
		t.Run(validation, func(t *testing.T) {
			if err := s.DB.Model(f).Update("validation", validation).Error; err != nil {
				t.Fatal(err)
			}
			w := httptest.NewRecorder()
			s.Handler().ServeHTTP(w, localReq(http.MethodGet, "/findings/"+strconv.Itoa(int(f.ID))+"/bundle.tar.gz"))
			if w.Code != http.StatusOK {
				t.Fatalf("status = %d: %s", w.Code, w.Body)
			}
			assertBundlePoCOmitted(t, readArchive(t, w.Body.Bytes()), validation)
		})
	}
}

func TestBundlePoC_trailingNewlineNormalised(t *testing.T) {
	for _, validation := range []string{
		"```sh\necho hi```",
		"```sh\necho hi``` \t\r\n",
		"  ```sh\n  echo hi```\n",
		"> ```sh\n> echo hi```\n",
	} {
		t.Run(validation, func(t *testing.T) {
			got := pocEntries(t, mustBundlePoC(t, validation))
			if body := string(got["poc/run.sh"].Data); body != "echo hi\n" {
				t.Errorf("run.sh = %q", body)
			}
		})
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
	gz, err := gzip.NewReader(bytes.NewReader(body))
	if err != nil {
		t.Fatalf("open gzip: %v", err)
	}
	defer func() { _ = gz.Close() }()
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

func TestFindingBundle_namedFilesReproduceAndRender(t *testing.T) {
	s, done := newTestServer(t)
	defer done()
	f := setUpBundleFinding(t, s, false)
	validation, err := os.ReadFile("testdata/poc_validation.txt")
	if err != nil {
		t.Fatal(err)
	}
	if err := s.DB.Model(f).Update("validation", string(validation)).Error; err != nil {
		t.Fatal(err)
	}
	url := "/findings/" + strconv.Itoa(int(f.ID))
	r := httptest.NewRequest(http.MethodGet, url+"/bundle.tar.gz", nil)
	r.Host = "127.0.0.1:8080"
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, r)
	if w.Code != http.StatusOK {
		t.Fatalf("bundle status = %d: %s", w.Code, w.Body.String())
	}
	files := readArchive(t, w.Body.Bytes())
	want := map[string]string{
		"poc/lib/value.sh":   "message='<poc>'\n",
		"poc/lib/print.sh":   "print_message() {\n  printf '%s\\n' \"$message\"\n}\n",
		"poc/run.sh":         "#!/bin/sh\nset -eu\ncd \"$(dirname \"$0\")\"\n. ./lib/value.sh\n. ./lib/print.sh\nprint_message\n",
		"poc/transcript.txt": "<poc>\n",
	}
	dir := t.TempDir()
	for name, body := range want {
		if string(files[name]) != body {
			t.Fatalf("%s = %q, want %q", name, files[name], body)
		}
		path := filepath.Join(dir, name)
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, files[name], 0o600); err != nil {
			t.Fatal(err)
		}
	}
	t.Run("execute", func(t *testing.T) {
		shell, err := exec.LookPath("sh")
		if err != nil {
			t.Skip("sh unavailable")
		}
		cmd := exec.CommandContext(t.Context(), shell, "run.sh")
		cmd.Dir = filepath.Join(dir, "poc")
		output, err := cmd.CombinedOutput()
		if err != nil || string(output) != "<poc>\n" {
			t.Fatalf("downloaded reproduction: %v, output %q", err, output)
		}
	})
	r = httptest.NewRequest(http.MethodGet, url, nil)
	r.Host = "127.0.0.1:8080"
	w = httptest.NewRecorder()
	s.Handler().ServeHTTP(w, r)
	if w.Code != http.StatusOK {
		t.Fatalf("finding status = %d: %s", w.Code, w.Body.String())
	}
	for _, fragment := range []string{
		"<pre><code class=\"language-sh\">message='&lt;poc&gt;'\n</code></pre>",
		"print_message() {\n  printf",
		"<pre><code class=\"language-text\">&lt;poc&gt;\n</code></pre>",
	} {
		if !strings.Contains(w.Body.String(), fragment) {
			t.Errorf("rendered finding missing %q", fragment)
		}
	}
}

func TestFindingBundle_omitsUnsafeOrConflictingPoC(t *testing.T) {
	s, done := newTestServer(t)
	defer done()
	f := setUpBundleFinding(t, s, true)
	seedBundleDependent(t, s, f.RepositoryID)
	cases := []string{
		"../escape.sh", "/tmp/escape.sh", "dir/../../escape.sh", "dir\\escape.sh",
		"C:/escape.sh", ".", "", "dir//file.sh", "dir/./file.sh", "../x\x00",
		"README.md", "README.md/file", "run.sh/file", "RUN.SH", "dir./file", "file name.sh",
	}
	validations := make(map[string]string)
	for _, name := range cases {
		validations[name] = "```sh filename=" + name + "\necho harmless\n```\n"
	}
	validations["duplicate"] = "```sh filename=run.sh\necho one\n```\n\n```sh filename=run.sh\necho two\n```\n"
	validations["misplaced"] = "```filename=run.sh sh\necho harmless\n```\n"
	for name, validation := range validations {
		t.Run(name, func(t *testing.T) {
			if err := s.DB.Model(f).Update("validation", validation).Error; err != nil {
				t.Fatal(err)
			}
			r := httptest.NewRequest(http.MethodGet, "/findings/"+strconv.Itoa(int(f.ID))+"/bundle.tar.gz", nil)
			r.Host = "127.0.0.1:8080"
			w := httptest.NewRecorder()
			s.Handler().ServeHTTP(w, r)
			if w.Code != http.StatusOK {
				t.Fatalf("status = %d: %s", w.Code, w.Body.String())
			}
			assertBundlePoCOmitted(t, readArchive(t, w.Body.Bytes()), validation)
		})
	}
}

func assertBundlePoCOmitted(t *testing.T, files map[string][]byte, validation string) {
	t.Helper()
	for _, name := range []string{"manifest.json", "report.md", "osv.json", "csaf.json", "patch.diff"} {
		if len(files[name]) == 0 {
			t.Errorf("bundle missing %s", name)
		}
	}
	for name := range files {
		if strings.HasPrefix(name, "poc/") {
			t.Errorf("bundle contains rejected PoC file %s", name)
		}
	}
	if !strings.Contains(string(files["report.md"]), validation) {
		t.Error("report missing original validation")
	}
	var manifest bundleManifest
	if err := json.Unmarshal(files["manifest.json"], &manifest); err != nil {
		t.Fatal(err)
	}
	if _, ok := manifest.Contents["poc/"]; ok {
		t.Error("manifest lists omitted poc/")
	}
	if len(manifest.Warnings) != 1 || !strings.Contains(manifest.Warnings[0], "poc/ omitted:") {
		t.Errorf("manifest warnings = %q", manifest.Warnings)
	}
}

func TestBundlePoC_filenameConflicts(t *testing.T) {
	for _, names := range [][2]string{{"x.sh", "x.sh"}, {"x.sh", "X.sh"}, {"dir", "dir/x.sh"}, {"dir/x.sh", "dir"}} {
		t.Run(strings.Join(names[:], "+"), func(t *testing.T) {
			validation := "```sh filename=" + names[0] + "\necho one\n```\n\n```sh filename=" + names[1] + "\necho two\n```\n"
			if _, err := bundlePoC(validation); err == nil {
				t.Fatal("expected conflicting filenames to be rejected")
			}
		})
	}
}

func TestBundlePoC_namedFilesReserveLegacyNames(t *testing.T) {
	validation := "```python\nprint('legacy')\n```\n\n```python filename=probe.py\nprint('named')\n```\n\n```sh filename=run.sh\npython3 probe.py\n```\n"
	files := pocEntries(t, mustBundlePoC(t, validation))
	if string(files["poc/probe.py"].Data) != "print('named')\n" || string(files["poc/probe-2.py"].Data) != "print('legacy')\n" {
		t.Fatalf("filename collision lost or renamed the declared file: %v", keys(files))
	}
}

func TestBundlePoC_namedFileBytes(t *testing.T) {
	validation := "~~~text filename=inputs/empty.txt\n~~~\n\n" +
		"```text filename=inputs/spaces.txt\n \t\n```\n\n" +
		"```python filename=custom.py\nprint('custom')\n```\n"
	files := pocEntries(t, mustBundlePoC(t, validation))
	for name, want := range map[string]string{
		"poc/inputs/empty.txt":  "",
		"poc/inputs/spaces.txt": " \t\n",
		"poc/custom.py":         "print('custom')\n",
	} {
		entry, ok := files[name]
		if !ok || string(entry.Data) != want {
			t.Errorf("%s = %q, present=%v, want %q", name, entry.Data, ok, want)
		}
	}
	if !strings.Contains(string(files["poc/run.sh"].Data), "exit 2") {
		t.Fatal("missing driver should direct the recipient to the instructions")
	}
}

func TestBundlePoC_ambiguousFileHeadersRemainProse(t *testing.T) {
	validation := "--- /work/src/poc/one.ml ---\nlet () = ()\n\n--- /work/src/poc/two.ml ---\nlet () = ()\n\nBuild and run after compiling both files."
	if got := mustBundlePoC(t, validation); len(got) != 0 {
		t.Fatalf("extracted ambiguous prose into %v", got)
	}
}
