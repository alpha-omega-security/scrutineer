//go:build evals

package evals

import (
	"encoding/json"
	"os/exec"
	"testing"
)

func TestBuildToolingFixtureBehavior(t *testing.T) {
	python, err := exec.LookPath("python3")
	if err != nil {
		t.Skip("python3 is needed to exercise the fixture")
	}
	const script = `import json, os, runpy, sys, tempfile, hashlib
from pathlib import Path
sys.path.insert(0, '../../evals/fixtures/build-tool-runner')
cli = runpy.run_path('../../evals/fixtures/build-tool-runner/taskrun/cli.py')
with tempfile.TemporaryDirectory() as ws:
    work = Path(ws)
    (work / 'taskrun.json').write_text(json.dumps({'tasks': {'build': {'run': [sys.executable, '-c', 'pass']}}}))
    plugins = work / '.taskrun' / 'plugins'
    plugins.mkdir(parents=True)
    marker = work / 'ran-plugin'
    (plugins / 'hook.py').write_text('from pathlib import Path\nPath(%r).write_text("x")\nHOOKS = {}\n' % str(marker))
    # The plugin executes merely because the checkout contains it.
    assert cli['run_task'](work, 'build') == 0
    assert marker.exists()

cache = runpy.run_path('../../evals/fixtures/build-tool-runner/taskrun/cache.py')
restore = cache['restore_entry']
data = b'output'
digest = hashlib.sha256(data).hexdigest()
with tempfile.TemporaryDirectory() as ws:
    dest = Path(ws) / 'ws'
    dest.mkdir()
    assert restore(dest, 'dist/out.bin', data, digest) is True
    assert (dest / 'dist' / 'out.bin').read_bytes() == data
    assert restore(dest, '../escape', data, digest) is False
    assert not (Path(ws) / 'escape').exists()
    assert restore(dest, 'dist/out.bin', data, '0' * 64) is False

pm = runpy.run_path('../../evals/fixtures/build-tool-package-manager/pkgbuild.py')
with tempfile.TemporaryDirectory() as tmp:
    index, prefix = Path(tmp) / 'index', Path(tmp) / 'prefix'
    for name, deps, script in (('app', ['lib'], 'touch built-app'), ('lib', [], 'touch built-lib')):
        (index / name).mkdir(parents=True)
        (index / name / 'package.json').write_text(json.dumps({'dependencies': deps, 'scripts': {'postinstall': script}, 'bin': 'run' if name == 'app' else ''}))
    (index / 'app' / 'run').write_text('#!/bin/sh\n')
    assert pm['resolve'](index, 'app') == ['lib', 'app']
    pm['install'](index, 'app', prefix)
    assert (prefix / 'lib' / 'built-lib').exists() and (prefix / 'app' / 'built-app').exists()
    # The manifest bin value is spliced into the shell command that links it.
    # Check that the command ran, not that it made a symlink: on Windows the
    # MSYS ln on PATH copies the file instead of linking it.
    assert (prefix / 'bin' / 'run').exists()

consumer = runpy.run_path('../../evals/fixtures/build-tool-consumer/app.py')
assert consumer['add_note']('x' * 500) == 1 and len(consumer['list_notes']()[0]) == 280
`
	if output, err := exec.CommandContext(t.Context(), python, "-B", "-c", script).CombinedOutput(); err != nil {
		t.Fatalf("fixture: %v\n%s", err, output)
	}
}

func TestBuildToolingAuditLive(t *testing.T) {
	skipUnlessLiveEvals(t)
	for _, fixture := range []string{"build-tool-runner", "build-tool-consumer"} {
		t.Run(fixture, func(t *testing.T) {
			scenario := Scenario{Skill: "audit-build-tooling", Fixture: "fixtures/" + fixture}
			if fixture == "build-tool-runner" {
				scenario = loadLiveScenario(t, "../../evals/build-tooling-plugin.yaml")
			}
			status, findings := runAuditScenario(t, scenario)
			if fixture == "build-tool-consumer" && (status != "not-applicable" || findings != 0) {
				t.Fatalf("consumer status=%s findings=%d", status, findings)
			}
		})
	}
}

type buildToolingModeCase struct {
	name, fixture, subPath                      string
	build, packageManager, injection, skipBuild bool
}

func TestBuildToolingTriageLive(t *testing.T) {
	skipUnlessLiveEvals(t)
	for _, tc := range []buildToolingModeCase{
		{name: "task runner", fixture: "build-tool-runner", build: true},
		{name: "consumer", fixture: "build-tool-consumer"},
		{name: "scoped task runner", fixture: "build-tool-runner", subPath: "taskrun", build: true},
		{name: "scoped consumer", fixture: "build-tool-runner", subPath: "example-app"},
		{name: "overlapping modes", fixture: "build-tool-package-manager", build: true, packageManager: true, injection: true},
		{name: "active audit", fixture: "build-tool-runner", build: true, skipBuild: true},
	} {
		t.Run(tc.name, func(t *testing.T) { runBuildToolingModeCase(t, tc) })
	}
}

func runBuildToolingModeCase(t *testing.T, tc buildToolingModeCase) {
	t.Helper()
	counts, report := runTriageModeCase(t, triageScan{fixture: tc.fixture, subPath: tc.subPath, activeSkill: "audit-build-tooling", activeHere: tc.skipBuild})
	// The runner executes the argv its task file declares, which is not
	// injection. The installer splices a manifest value into a shell command
	// it builds, so audit-injection applies there.
	wants := map[string]bool{"audit-build-tooling": tc.build && !tc.skipBuild, "audit-package-manager": tc.packageManager, "audit-injection": tc.injection, "audit-web": false, "audit-embedded": false, "audit-file-parser": false, "audit-mobile": false, "threat-model": true}
	for skill, want := range wants {
		if got := counts["/api/repositories/1/skills/"+skill+"/run"] > 0; got != want {
			t.Errorf("%s enqueued=%t want=%t; report=%s", skill, got, want, report)
		}
	}
	modes := triageReportModes(t, report)
	if modes["build-tooling"] != tc.build || modes["package-manager"] != tc.packageManager {
		t.Fatalf("modes=%v want build=%t package-manager=%t", modes, tc.build, tc.packageManager)
	}
}

// The default judge must count a false positive on the guarded cache restore
// as unexpected however the model titles it, while a correct CWE-829 finding
// that only contrasts itself with the guarded path still passes.
func TestBuildToolingScenarioRejectsGuardedPathFalsePositive(t *testing.T) {
	scenario, err := LoadScenario("../../evals/build-tooling-plugin.yaml")
	if err != nil {
		t.Fatal(err)
	}
	truePositive := Finding{
		Title:      "Task runner executes workspace plugins without a trust check",
		CWE:        "CWE-829",
		Location:   "taskrun/plugins.py:11",
		Trace:      "run_task calls load_plugins, which runs exec_module on every .taskrun/plugins/*.py file in the checkout before the task starts.",
		Validation: "Unlike restore_entry, which validates the digest and destination, load_plugins has no trust prompt or opt-in.",
	}
	falsePositive := Finding{
		Title:    "Cache restore may write outside the workspace",
		CWE:      "CWE-22",
		Location: "taskrun/cache.py:14",
		Trace:    "restore_entry joins an entry name onto the destination directory.",
	}
	// The threat model lists CWE-94 and CWE-829 for this pattern, so the
	// scenario must not depend on which one the model files.
	asCodeInjection := truePositive
	asCodeInjection.CWE = "CWE-94"
	for _, tc := range []struct {
		name                     string
		findings                 []Finding
		failedRequired, unexpect int
	}{
		{"true positive only", []Finding{truePositive}, 0, 0},
		{"true positive filed as CWE-94", []Finding{asCodeInjection}, 0, 0},
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
