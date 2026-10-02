//go:build evals

package evals

import (
	"encoding/json"
	"os/exec"
	"testing"
)

func TestEmbeddedFixtureBehavior(t *testing.T) {
	python, err := exec.LookPath("python3")
	if err != nil {
		t.Skip("python3 is needed to exercise the fixture")
	}
	const script = `import hashlib, hmac, json, runpy
ota = runpy.run_path('../../evals/fixtures/embedded-device/firmware/ota.py')
written = []
def flash_write(slot, image):
    written.append((slot, image))

# The digest comes from the same manifest as the image, so any pair is accepted.
evil = b'attacker firmware'
state = {'boot_slot': 'a', 'config_version': 3}
manifest = {'sha256': hashlib.sha256(evil).hexdigest()}
assert ota['apply_update'](evil, manifest, state, flash_write) is True
assert written == [('b', evil)]
assert state['boot_slot'] == 'b' and state['pending'] is True
assert ota['apply_update'](evil, {'sha256': '0' * 64}, dict(state), flash_write) is False
assert len(written) == 1

key = b'device-provisioned-key'
def bundle(version):
    raw = json.dumps({'version': version, 'values': {'interval': version}}).encode()
    return raw, hmac.new(key, raw, hashlib.sha256).digest()

state = {'config_version': 3}
apply = runpy.run_path('../../evals/fixtures/embedded-device/firmware/config_bundle.py')['apply_config_bundle']
raw, sig = bundle(4)
assert apply(raw, b'\0' * 32, state, key) is False
assert apply(raw, sig, state, b'wrong-key') is False
assert state['config_version'] == 3
assert apply(raw, sig, state, key) is True
assert state['config_version'] == 4 and state['config'] == {'interval': 4}
assert apply(raw, sig, state, key) is False
old_raw, old_sig = bundle(2)
assert apply(old_raw, old_sig, state, key) is False
assert state['config_version'] == 4

web = runpy.run_path('../../evals/fixtures/embedded-web-device/firmware/web.py')
dispatch = web['dispatch']
body = '{"name": "changed"}'
assert dispatch('GET', '/status', {})[0] == 200
assert dispatch('POST', '/admin/settings', {}, body)[0] == 401
assert dispatch('POST', '/admin/settings', {'X-Admin-Password': 'wrong'}, body)[0] == 401
status, settings = dispatch('POST', '/admin/settings', {'X-Admin-Password': web['ADMIN_PASSWORD']}, body)
assert status == 200 and settings['name'] == 'changed'
`
	if output, err := exec.CommandContext(t.Context(), python, "-B", "-c", script).CombinedOutput(); err != nil {
		t.Fatalf("fixture: %v\n%s", err, output)
	}
}

func TestEmbeddedAuditLive(t *testing.T) {
	skipUnlessLiveEvals(t)
	for _, fixture := range []string{"embedded-device", "embedded-host-tool"} {
		t.Run(fixture, func(t *testing.T) {
			scenario := Scenario{Skill: "audit-embedded", Fixture: "fixtures/" + fixture}
			if fixture == "embedded-device" {
				scenario = loadLiveScenario(t, "../../evals/embedded-ota.yaml")
			}
			status, findings := runAuditScenario(t, scenario)
			if fixture == "embedded-host-tool" && (status != "not-applicable" || findings != 0) {
				t.Fatalf("host tool status=%s findings=%d", status, findings)
			}
		})
	}
}

type embeddedModeCase struct {
	name, fixture, subPath string
	embedded, web, skipEmb bool
}

func TestEmbeddedTriageLive(t *testing.T) {
	skipUnlessLiveEvals(t)
	for _, tc := range []embeddedModeCase{
		{name: "device", fixture: "embedded-device", embedded: true},
		{name: "host tool", fixture: "embedded-host-tool"},
		{name: "scoped firmware", fixture: "embedded-device", subPath: "firmware", embedded: true},
		{name: "scoped flasher", fixture: "embedded-device", subPath: "tools/flasher"},
		{name: "overlapping modes", fixture: "embedded-web-device", embedded: true, web: true},
		{name: "active audit", fixture: "embedded-device", embedded: true, skipEmb: true},
	} {
		t.Run(tc.name, func(t *testing.T) { runEmbeddedModeCase(t, tc) })
	}
}

func runEmbeddedModeCase(t *testing.T, tc embeddedModeCase) {
	t.Helper()
	counts, report := runTriageModeCase(t, triageScan{fixture: tc.fixture, subPath: tc.subPath, activeSkill: "audit-embedded", activeHere: tc.skipEmb})
	// The fixtures are Python, so audit-memory never applies.
	for skill, want := range map[string]bool{"audit-embedded": tc.embedded && !tc.skipEmb, "audit-web": tc.web, "audit-memory": false, "threat-model": true} {
		if got := counts["/api/repositories/1/skills/"+skill+"/run"] > 0; got != want {
			t.Errorf("%s enqueued=%t want=%t; report=%s", skill, got, want, report)
		}
	}
	var parsed struct {
		Modes []struct {
			Name     string   `json:"name"`
			Evidence []string `json:"evidence"`
		} `json:"modes"`
	}
	if err := json.Unmarshal([]byte(report), &parsed); err != nil {
		t.Fatal(err)
	}
	modes := make(map[string]bool)
	for _, mode := range parsed.Modes {
		if modes[mode.Name] || len(mode.Evidence) == 0 {
			t.Errorf("duplicate or unevidenced mode=%+v", mode)
		}
		modes[mode.Name] = true
	}
	if modes["embedded-iot"] != tc.embedded || modes["web-api"] != tc.web {
		t.Fatalf("modes=%v want embedded=%t web=%t", modes, tc.embedded, tc.web)
	}
}

// The default judge must count a false positive on the guarded configuration
// path as unexpected however the model titles it, while a correct CWE-494
// finding that only contrasts itself with the guarded path still passes.
func TestEmbeddedOTAScenarioRejectsGuardedPathFalsePositive(t *testing.T) {
	scenario, err := LoadScenario("../../evals/embedded-ota.yaml")
	if err != nil {
		t.Fatal(err)
	}
	truePositive := Finding{
		Title:      "Firmware update accepts images verified only by a server-supplied digest",
		CWE:        "CWE-494",
		Location:   "firmware/ota.py:8",
		Trace:      "apply_update compares the image sha256 with manifest['sha256'] from the same unauthenticated update server response.",
		Validation: "Unlike apply_config_bundle, which checks an HMAC under the device key, apply_update trusts the manifest digest.",
	}
	falsePositive := Finding{
		Title:    "Configuration rollback permits replay of old signed settings",
		CWE:      "CWE-294",
		Location: "firmware/config_bundle.py:6",
		Trace:    "apply_config_bundle applies a signed bundle received from the update server.",
	}
	for _, tc := range []struct {
		name                     string
		findings                 []Finding
		failedRequired, unexpect int
	}{
		{"true positive only", []Finding{truePositive}, 0, 0},
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
