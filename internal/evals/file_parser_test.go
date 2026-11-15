//go:build evals

package evals

import (
	"encoding/json"
	"os/exec"
	"strings"
	"testing"
)

func TestFileParserFixtureBehavior(t *testing.T) {
	python, err := exec.LookPath("python3")
	if err != nil {
		t.Skip("python3 is needed to exercise the fixture")
	}
	const script = `import contextlib, io, os, runpy, shutil, struct, sys, tempfile, zlib
from pathlib import Path
fixtures = Path('../../evals/fixtures').resolve()
sys.path.insert(0, str(fixtures / 'file-parser-format'))
from tlvdoc import reader, bundle

def element(kind, payload):
    return struct.pack('>BI', kind, len(payload)) + payload

# A normal document parses.
doc = element(2, element(1, b'title') + element(1, b'body'))
assert reader.parse(doc) == ['title', 'body']

# A small compressed element expands far beyond its input size.
big = element(1, b'a' * 10_000_000)
packed = element(3, zlib.compress(big, 9))
assert len(packed) < 20_000
value = reader.parse(packed)
assert len(value) == 10_000_000
assert len(value) / len(packed) > 100
del value

# Container nesting has no depth limit.
nested = element(1, b'x')
for _ in range(5000):
    nested = element(2, nested)
try:
    reader.parse(nested)
except RecursionError:
    pass
else:
    raise AssertionError('deep nesting did not recurse')

# The bundle extractor writes normal entries and refuses escapes.
with tempfile.TemporaryDirectory() as tmp:
    dest = Path(tmp) / 'out'
    dest.mkdir()
    written = bundle.extract_bundle([('docs/a.txt', b'one')], dest)
    assert [p.read_bytes() for p in written] == [b'one']
    for name in ('../escape', 'docs/../../escape', '/abs-name', '\\evil'):
        try:
            bundle.extract_bundle([(name, b'x')], dest)
        except ValueError:
            pass
        else:
            raise AssertionError('accepted ' + name)
    try:
        bundle.extract_bundle([('docs/a.txt', b'two')], dest)
    except FileExistsError:
        pass
    else:
        raise AssertionError('overwrote an entry')
    assert (dest / 'docs' / 'a.txt').read_bytes() == b'one'
    assert sorted(p.name for p in Path(tmp).iterdir()) == ['out']

# The consumer loads its config and bundled resource.
with tempfile.TemporaryDirectory() as tmp:
    shutil.copytree(fixtures / 'file-parser-consumer', Path(tmp) / 'app')
    app = runpy.run_path(str(Path(tmp) / 'app' / 'app.py'))
    assert app['load_config']()['page_size'] == 20
    assert app['help_text']().startswith('Press')

# The example app runs on its generated sample.
with tempfile.TemporaryDirectory() as tmp:
    shutil.copytree(fixtures / 'file-parser-format', Path(tmp) / 'lib', ignore=shutil.ignore_patterns('__pycache__'))
    example = runpy.run_path(str(Path(tmp) / 'lib' / 'examples' / 'report.py'))
    out = io.StringIO()
    with contextlib.redirect_stdout(out):
        example['main']()
    assert out.getvalue().splitlines()[0] == 'Quarterly report'

# The protocol library decodes a DNS query and refuses pointer loops.
sys.path.insert(0, str(fixtures / 'file-parser-protocol'))
from dnswire import parse_message
query = struct.pack('>HHHHHH', 0x1234, 0x0100, 1, 0, 0, 0) + b'\x03www\x07example\x03com\x00' + struct.pack('>HH', 1, 1)
msg = parse_message(query)
assert msg.questions[0].name == 'www.example.com'
assert msg.questions[0].qtype == 1
loop = struct.pack('>HHHHHH', 1, 0, 1, 0, 0, 0) + b'\xc0\x0c' + struct.pack('>HH', 1, 1)
try:
    parse_message(loop)
except ValueError:
    pass
else:
    raise AssertionError('pointer loop accepted')

# The upload service parses a record file and answers health checks.
sys.path.insert(0, str(fixtures / 'file-parser-upload'))
upload = runpy.run_path(str(fixtures / 'file-parser-upload' / 'server.py'))
status, result = upload['dispatch']('POST', '/import', {}, b'\x00\x03abc\x00\x02de')
assert status == 200 and result['records'] == 2, (status, result)
assert upload['dispatch']('GET', '/health', {}, b'')[0] == 200

# The native decoder is shipped as source for the overlap case.
assert (fixtures / 'file-parser-native' / 'src' / 'decode.c').exists()
`
	if output, err := exec.CommandContext(t.Context(), python, "-B", "-c", script).CombinedOutput(); err != nil {
		t.Fatalf("fixture: %v\n%s", err, output)
	}
}

func TestFileParserAuditLive(t *testing.T) {
	skipUnlessLiveEvals(t)
	for _, fixture := range []string{"file-parser-format", "file-parser-consumer"} {
		t.Run(fixture, func(t *testing.T) {
			scenario := Scenario{Skill: "audit-file-parser", Fixture: "fixtures/" + fixture}
			if fixture == "file-parser-format" {
				scenario = loadLiveScenario(t, "../../evals/file-parser-decompress.yaml")
			}
			status, findings := runAuditScenario(t, scenario)
			if fixture == "file-parser-consumer" && (status != "not-applicable" || findings != 0) {
				t.Fatalf("consumer status=%s findings=%d", status, findings)
			}
		})
	}
}

type fileParserModeCase struct {
	name, fixture, subPath string
	parser, memory, skip   bool
	web                    bool
}

func TestFileParserTriageLive(t *testing.T) {
	skipUnlessLiveEvals(t)
	for _, tc := range []fileParserModeCase{
		{name: "format library", fixture: "file-parser-format", parser: true},
		{name: "consumer", fixture: "file-parser-consumer"},
		{name: "scoped format library", fixture: "file-parser-format", subPath: "tlvdoc", parser: true},
		{name: "scoped consumer of the format library", fixture: "file-parser-format", subPath: "examples"},
		{name: "native decoder", fixture: "file-parser-native", parser: true, memory: true},
		{name: "protocol message parser", fixture: "file-parser-protocol", parser: true},
		{name: "web upload service", fixture: "file-parser-upload", parser: true, web: true},
		{name: "active audit", fixture: "file-parser-format", parser: true, skip: true},
	} {
		t.Run(tc.name, func(t *testing.T) { runFileParserModeCase(t, tc) })
	}
}

func runFileParserModeCase(t *testing.T, tc fileParserModeCase) {
	t.Helper()
	counts, report := runTriageModeCase(t, triageScan{fixture: tc.fixture, subPath: tc.subPath, activeSkill: "audit-file-parser", activeHere: tc.skip})
	// Extracting archive entries stays with audit-file-parser. None of the
	// fixtures resolve external references or deserialize into arbitrary types.
	wants := map[string]bool{"audit-file-parser": tc.parser && !tc.skip, "audit-memory": tc.memory, "audit-exfil": false, "audit-injection": false, "audit-web": tc.web, "audit-embedded": false, "audit-build-tooling": false, "audit-mobile": false, "threat-model": true}
	for skill, want := range wants {
		if got := counts["/api/repositories/1/skills/"+skill+"/run"] > 0; got != want {
			t.Errorf("%s enqueued=%t want=%t; report=%s", skill, got, want, report)
		}
	}
	// Shared audits are enqueued once.
	for path, n := range counts {
		if strings.HasPrefix(path, "/api/repositories/1/skills/") && strings.HasSuffix(path, "/run") && n > 1 {
			t.Errorf("%s requested %d times", path, n)
		}
	}
	modes := triageReportModes(t, report)
	if modes["file-parser"] != tc.parser || modes["web-api"] != tc.web {
		t.Fatalf("modes=%v want file-parser=%t web-api=%t", modes, tc.parser, tc.web)
	}
}

// The default judge must count a false positive on the guarded bundle
// extractor as unexpected however the model titles it, while a correct
// finding on the unbounded decompression passes under either CWE the threat
// model lists for it.
func TestFileParserScenarioRejectsGuardedPathFalsePositive(t *testing.T) {
	scenario, err := LoadScenario("../../evals/file-parser-decompress.yaml")
	if err != nil {
		t.Fatal(err)
	}
	truePositive := Finding{
		Title:      "Compressed elements are inflated without an output bound",
		CWE:        "CWE-409",
		Location:   "tlvdoc/reader.py:42",
		Trace:      "read_element passes a type 3 payload to read_compressed, which calls zlib.decompress on attacker-supplied bytes.",
		Validation: "Unlike extract_bundle, which resolves each path and refuses escapes, read_compressed has no output size limit.",
	}
	falsePositive := Finding{
		Title:    "Bundle extraction may write outside the destination",
		CWE:      "CWE-22",
		Location: "tlvdoc/bundle.py:19",
		Trace:    "extract_bundle joins an entry name onto the destination directory.",
	}
	asResourceConsumption := truePositive
	asResourceConsumption.CWE = "CWE-400"
	for _, tc := range []struct {
		name                     string
		findings                 []Finding
		failedRequired, unexpect int
	}{
		{"true positive only", []Finding{truePositive}, 0, 0},
		{"true positive filed as CWE-400", []Finding{asResourceConsumption}, 0, 0},
		{"false positive on guarded path", []Finding{truePositive, falsePositive}, 0, 1},
		{"false positive alone", []Finding{falsePositive}, 1, 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			raw, err := json.Marshal(map[string]any{"findings": tc.findings})
			if err != nil {
				t.Fatal(err)
			}
			matches, err := HeuristicJudge{}.Judge(scenario, string(raw))
			if err != nil {
				t.Fatal(err)
			}
			failedRequired, unexpected := 0, 0
			for _, m := range matches {
				switch {
				case !m.Matched && m.Kind == assertionShouldFind && m.Required:
					failedRequired++
				case !m.Matched && m.Kind == assertionShouldNotFind:
					unexpected++
				}
			}
			if failedRequired != tc.failedRequired || unexpected != tc.unexpect {
				t.Fatalf("failed required=%d unexpected=%d, want %d and %d; matches=%+v", failedRequired, unexpected, tc.failedRequired, tc.unexpect, matches)
			}
		})
	}
}
