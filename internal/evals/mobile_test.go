//go:build evals

package evals

import (
	"encoding/json"
	"os/exec"
	"strings"
	"testing"
)

func TestMobileFixtureBehavior(t *testing.T) {
	python, err := exec.LookPath("python3")
	if err != nil {
		t.Skip("python3 is needed to exercise the fixture")
	}
	const script = `import plistlib, runpy, sys
import xml.etree.ElementTree as ET
from pathlib import Path
fixtures = Path('../../evals/fixtures').resolve()

# Both deep link activities are exported and accept the notes scheme.
android = fixtures / 'mobile-android-app'
ns = '{http://schemas.android.com/apk/res/android}'
app = ET.parse(android / 'app' / 'src' / 'main' / 'AndroidManifest.xml').getroot().find('application')
components = {
    node.get(ns + 'name'): (node.get(ns + 'exported') == 'true', sorted({d.get(ns + 'scheme') for d in node.iter('data')}))
    for node in app
}
for name in ('.DeepLinkActivity', '.HelpActivity'):
    assert components[name] == (True, ['notes']), (name, components.get(name))

# The planted bridge is in the deep link activity and the guarded one has none.
src = android / 'app' / 'src' / 'main' / 'java' / 'com' / 'example' / 'notes'
deep = (src / 'DeepLinkActivity.kt').read_text()
assert 'addJavascriptInterface' in deep and 'loadUrl' in deep
help_source = (src / 'HelpActivity.kt').read_text()
assert 'HELP_HOST' in help_source and 'addJavascriptInterface' not in help_source
assert 'EncryptedSharedPreferences' in (src / 'TokenStore.kt').read_text()

# The iOS and hybrid property lists register the expected settings.
with open(fixtures / 'mobile-ios-app' / 'NotesApp' / 'Info.plist', 'rb') as f:
    ios = plistlib.load(f)
assert ios['CFBundleURLTypes'][0]['CFBundleURLSchemes'] == ['notes']
assert ios['NSAppTransportSecurity']['NSAllowsArbitraryLoads'] is False
with open(fixtures / 'mobile-hybrid-monorepo' / 'app' / 'ios' / 'Hybrid' / 'Info.plist', 'rb') as f:
    assert plistlib.load(f)['CFBundleIdentifier'] == 'com.example.hybrid'

# The hybrid server issues sessions and keeps notes private to their owner.
import json
server = runpy.run_path(str(fixtures / 'mobile-hybrid-monorepo' / 'server' / 'server.py'))
dispatch = server['dispatch']
def login(user):
    status, result = dispatch('POST', '/login', {}, json.dumps({'username': user, 'password': user + '-password'}).encode())
    assert status == 200, (status, result)
    return {'Authorization': 'Bearer ' + result['token']}
alice, bob = login('alice'), login('bob')
status, notes = dispatch('GET', '/notes', alice)
assert status == 200 and [n['title'] for n in notes] == ['Alice groceries'], (status, notes)
assert dispatch('GET', '/notes/1', alice)[0] == 200
assert dispatch('GET', '/notes/1', bob)[0] in (403, 404)
assert dispatch('GET', '/notes', {})[0] == 401
assert dispatch('POST', '/login', {}, b'{"username": "alice", "password": "wrong"}')[0] == 403

# The push client only builds request dicts.
sys.path.insert(0, str(fixtures / 'mobile-api-client'))
from pushclient.client import PushClient
request = PushClient('key').register('ios', 'abc')
assert request['method'] == 'POST' and request['json'] == {'platform': 'ios', 'token': 'abc'}
`
	if output, err := exec.CommandContext(t.Context(), python, "-B", "-c", script).CombinedOutput(); err != nil {
		t.Fatalf("fixture: %v\n%s", err, output)
	}
}

func TestMobileAuditLive(t *testing.T) {
	skipUnlessLiveEvals(t)
	for _, fixture := range []string{"mobile-android-app", "mobile-api-client"} {
		t.Run(fixture, func(t *testing.T) {
			scenario := Scenario{Skill: "audit-mobile", Fixture: "fixtures/" + fixture}
			if fixture == "mobile-android-app" {
				scenario = loadLiveScenario(t, "../../evals/mobile-webview-bridge.yaml")
			}
			status, findings := runAuditScenario(t, scenario)
			if fixture == "mobile-api-client" && (status != "not-applicable" || findings != 0) {
				t.Fatalf("api client status=%s findings=%d", status, findings)
			}
		})
	}
}

type mobileModeCase struct {
	name, fixture, subPath string
	mobile, web, authz     bool
	skip                   bool
}

func TestMobileTriageLive(t *testing.T) {
	skipUnlessLiveEvals(t)
	for _, tc := range []mobileModeCase{
		{name: "android app", fixture: "mobile-android-app", mobile: true},
		{name: "ios app", fixture: "mobile-ios-app", mobile: true},
		{name: "api client", fixture: "mobile-api-client"},
		{name: "hybrid monorepo", fixture: "mobile-hybrid-monorepo", mobile: true, web: true, authz: true},
		{name: "scoped app", fixture: "mobile-hybrid-monorepo", subPath: "app", mobile: true},
		{name: "scoped server", fixture: "mobile-hybrid-monorepo", subPath: "server", web: true, authz: true},
		{name: "active audit", fixture: "mobile-android-app", mobile: true, skip: true},
	} {
		t.Run(tc.name, func(t *testing.T) { runMobileModeCase(t, tc) })
	}
}

func runMobileModeCase(t *testing.T, tc mobileModeCase) {
	t.Helper()
	counts, report := runTriageModeCase(t, triageScan{fixture: tc.fixture, subPath: tc.subPath, activeSkill: "audit-mobile", activeHere: tc.skip})
	// None of the fixtures has native code. A WebView alone never adds
	// audit-web, which the hybrid server earns through its own API.
	wants := map[string]bool{"audit-mobile": tc.mobile && !tc.skip, "audit-memory": false, "audit-web": tc.web, "audit-authz": tc.authz, "audit-embedded": false, "audit-build-tooling": false, "audit-file-parser": false, "threat-model": true}
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
	if modes["mobile"] != tc.mobile || modes["web-api"] != tc.web {
		t.Fatalf("modes=%v want mobile=%t web-api=%t", modes, tc.mobile, tc.web)
	}
}

// The default judge must count a false positive on the guarded help activity
// as unexpected however the model titles it, while a correct finding on the
// deep link WebView bridge passes.
func TestMobileScenarioRejectsGuardedPathFalsePositive(t *testing.T) {
	scenario, err := LoadScenario("../../evals/mobile-webview-bridge.yaml")
	if err != nil {
		t.Fatal(err)
	}
	truePositive := Finding{
		Title:      "Deep link loads an attacker URL into a WebView that exposes the session token",
		CWE:        "CWE-749",
		Location:   "app/src/main/java/com/example/notes/DeepLinkActivity.kt:23",
		Trace:      "The exported activity passes the url query parameter to loadUrl on a WebView with addJavascriptInterface exposing SessionBridge.token.",
		Validation: "Unlike HelpActivity, which checks the https scheme and HELP_HOST, nothing restricts the URL loaded by DeepLinkActivity.",
	}
	falsePositive := Finding{
		Title:    "Help deep link loads a URL from a query parameter",
		CWE:      "CWE-601",
		Location: "app/src/main/java/com/example/notes/HelpActivity.kt:16",
		Trace:    "HelpActivity reads the page query parameter and calls loadUrl on a WebView when the host equals HELP_HOST.",
	}
	for _, tc := range []struct {
		name                     string
		findings                 []Finding
		failedRequired, unexpect int
	}{
		{"true positive only", []Finding{truePositive}, 0, 0},
		{"false positive on guarded path", []Finding{truePositive, falsePositive}, 0, 1},
		{"false positive alone", []Finding{falsePositive}, 1, 1},
		{"no findings", nil, 1, 0},
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
