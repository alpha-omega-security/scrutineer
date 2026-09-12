package worker

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"scrutineer/internal/coverage"
	"scrutineer/internal/db"
)

func TestContainerCapabilityPreflight(t *testing.T) {
	bin := t.TempDir()
	runtimePath := filepath.Join(bin, "runtime")
	script := `#!/bin/sh
while [ "$#" -gt 0 ] && [ "$1" != "--" ]; do shift; done
[ "$#" -gt 1 ] || exit 2
shift
shift
PATH=/usr/bin:/bin
export PATH
exec "$@"
`
	if err := os.WriteFile(runtimePath, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(bin, "host-only-preflight-command"), []byte("#!/bin/sh\nexit 0\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", bin+string(os.PathListSeparator)+os.Getenv("PATH"))
	exerciseContainerCapabilityPreflight(t, ContainerRunner{
		Runtime: ContainerRuntime{Bin: runtimePath}, Image: "selected-profile-image", Harness: dockerNoopHarness{},
	})
}

func TestIntegrationContainerCapabilityPreflight(t *testing.T) {
	image := os.Getenv("SCRUTINEER_PREFLIGHT_TEST_IMAGE")
	if image == "" {
		t.Skip("set SCRUTINEER_PREFLIGHT_TEST_IMAGE to test a local container image with /bin/sh and /usr/bin/true")
	}
	exerciseContainerCapabilityPreflight(t, ContainerRunner{Image: image, Harness: dockerNoopHarness{}})
}

func exerciseContainerCapabilityPreflight(t *testing.T, runner ContainerRunner) {
	t.Helper()
	for _, tc := range []struct {
		name, command, status string
		degraded              bool
		features              []string
	}{
		{"ready", "true", coverage.PreflightReady, false, nil},
		{"blocked", "host-only-preflight-command", coverage.PreflightBlocked, false, nil},
		{"degraded", "host-only-preflight-command", coverage.PreflightDegraded, true, nil},
		{"network-policy", "sh", coverage.PreflightBlocked, false, []string{"network-egress"}},
		{"unsupported-features", "sh", coverage.PreflightDegraded, true, []string{"docker-in-docker", "fuse"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			work := t.TempDir()
			if err := os.Mkdir(filepath.Join(work, "src"), 0o755); err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
			defer cancel()
			recorded, launched := false, false
			sj := SkillJob{WorkRoot: work, SrcReady: true, Profile: "default", RequiresCommands: []string{tc.command}, RequiresFeatures: tc.features, DegradedMode: tc.degraded,
				RecordPreflight: func(p coverage.Preflight) error {
					recorded = true
					if p.Status != tc.status {
						t.Errorf("status=%s want=%s error=%s", p.Status, tc.status, p.Error)
					}
					return nil
				},
			}
			_, err := runner.RunSkill(ctx, sj, func(e Event) {
				if strings.HasPrefix(e.Text, "$ ") {
					launched = true
					if !recorded {
						t.Error("agent launched before preflight was recorded")
					}
				}
			})
			blocked := tc.status == coverage.PreflightBlocked
			if !recorded || (err != nil) != blocked || launched == blocked {
				t.Fatalf("recorded=%v launched=%v err=%v", recorded, launched, err)
			}
		})
	}
}

func TestCapabilityProbe(t *testing.T) {
	bin := t.TempDir()
	marker := filepath.Join(bin, "executed")
	if err := os.WriteFile(filepath.Join(bin, "available"), []byte("#!/bin/sh\ntouch "+marker+"\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(bin, "nonexec"), []byte("data"), 0o644); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", bin)
	sj := SkillJob{WorkRoot: t.TempDir(), RequiresCommands: []string{"available", "missing", "nonexec"}, RequiresFeatures: []string{"fuse", "docker-in-docker", "network-egress"}}
	for _, egress := range []bool{false, true} {
		missing, err := sj.probeCapabilities(context.Background(), nil, nil, egress)
		if err != nil {
			t.Fatal(err)
		}
		want := []string{"command:missing", "command:nonexec", "feature:docker-in-docker", "feature:fuse"}
		if !egress {
			want = append(want, "feature:network-egress")
		}
		if !slices.Equal(missing, want) {
			t.Fatalf("missing=%v want=%v", missing, want)
		}
	}
	if _, err := os.Stat(marker); !os.IsNotExist(err) {
		t.Fatal("probe executed the required command")
	}
}

func TestCapabilityPreflightStates(t *testing.T) {
	for _, degraded := range []bool{false, true} {
		sj := SkillJob{WorkRoot: t.TempDir(), RequiresCommands: []string{"scrutineer-missing-capability"}, DegradedMode: degraded}
		var got coverage.Preflight
		sj.RecordPreflight = func(p coverage.Preflight) error { got = p; return nil }
		err := sj.checkCapabilities(context.Background(), nil, nil, false, func(Event) {})
		if degraded {
			if err != nil || got.Status != coverage.PreflightDegraded || !got.Degraded {
				t.Fatalf("degraded=%+v err=%v", got, err)
			}
		} else if err == nil || got.Status != coverage.PreflightBlocked {
			t.Fatalf("blocked=%+v err=%v", got, err)
		}
		sj.RequiresCommands = []string{"sh"}
		if err := sj.checkCapabilities(context.Background(), nil, nil, false, func(Event) {}); err != nil || got.Status != coverage.PreflightReady {
			t.Fatalf("ready=%+v err=%v", got, err)
		}
		sj.RecordPreflight = func(coverage.Preflight) error { return errors.New("database unavailable") }
		if err := sj.checkCapabilities(context.Background(), nil, nil, false, func(Event) {}); err == nil {
			t.Fatal("ignored persistence failure")
		}
	}
}

func TestCapabilityPreflightProbeErrorsNeverDegrade(t *testing.T) {
	for _, commands := range [][]string{{"sh"}, {"bad;command"}} {
		sj := SkillJob{WorkRoot: t.TempDir(), RequiresCommands: commands, DegradedMode: true}
		var got coverage.Preflight
		sj.RecordPreflight = func(p coverage.Preflight) error { got = p; return nil }
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		if err := sj.checkCapabilities(ctx, nil, nil, false, func(Event) {}); err == nil || got.Status != coverage.PreflightBlocked || got.Degraded || got.Error == "" {
			t.Fatalf("probe failure not blocked: %+v", got)
		}
	}
	for _, output := range []string{"", "command:sh\n", "feature:bogus\npreflight-ok\n", "command:sh\ncommand:sh\npreflight-ok\n"} {
		if _, err := parseCapabilityProbe(output, []string{"command:sh"}); err == nil {
			t.Fatalf("accepted %q", output)
		}
	}
	// No declared requirements means no command, callback, or behavior change.
	sj := SkillJob{RecordPreflight: func(coverage.Preflight) error { t.Fatal("unexpected preflight"); return nil }}
	if err := sj.checkCapabilities(context.Background(), []string{"/nonexistent"}, nil, false, func(Event) {}); err != nil {
		t.Fatal(err)
	}
}

func TestLocalRunnerBlocksBeforeModel(t *testing.T) {
	work := t.TempDir()
	if err := os.Mkdir(filepath.Join(work, "src"), 0o755); err != nil {
		t.Fatal(err)
	}
	sj := SkillJob{WorkRoot: work, SrcReady: true, RequiresCommands: []string{"scrutineer-missing-capability"}}
	_, err := (LocalClaude{}).RunSkill(context.Background(), sj, func(e Event) {
		if strings.Contains(e.Text, "$ claude") {
			t.Fatal("model started despite blocked preflight")
		}
	})
	if err == nil || !strings.Contains(err.Error(), "capability preflight blocked") {
		t.Fatalf("error=%v", err)
	}
}

func TestCapabilityPreflightPersistenceAndContext(t *testing.T) {
	w, repo := newStreamWorker(t)
	scan := db.Scan{RepositoryID: repo.ID, Status: db.ScanRunning, Kind: JobSkill}
	if err := w.DB.Create(&scan).Error; err != nil {
		t.Fatal(err)
	}
	work := t.TempDir()
	skillDir := filepath.Join(work, "skill")
	if err := os.Mkdir(skillDir, 0o755); err != nil {
		t.Fatal(err)
	}
	for _, dir := range []string{work, skillDir} {
		if err := os.WriteFile(filepath.Join(dir, "context.json"), []byte(`{"scrutineer":{"scan_id":1},"repo":{"name":"keep"}}`), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	skill := db.Skill{RequiresCommands: "scrutineer-missing-capability", DegradedMode: true}
	sj := SkillJob{WorkRoot: work, SkillDir: skillDir}
	w.configureCapabilityPreflight(context.Background(), &scan, &skill, &sj)
	if err := sj.checkCapabilities(context.Background(), nil, nil, false, func(Event) {}); err != nil {
		t.Fatal(err)
	}
	var stored db.Scan
	if err := w.DB.First(&stored, scan.ID).Error; err != nil {
		t.Fatal(err)
	}
	rec, ok := coverage.Parse(stored.Coverage)
	if !ok || rec.Preflight.Status != coverage.PreflightDegraded || stored.Completeness != coverage.CompletenessPartial {
		t.Fatalf("stored=%+v", stored)
	}
	for _, dir := range []string{work, skillDir} {
		data, err := os.ReadFile(filepath.Join(dir, "context.json"))
		if err != nil {
			t.Fatal(err)
		}
		var doc struct {
			Scrutineer struct{ Preflight coverage.Preflight }
			Repo       struct{ Name string }
		}
		if err := json.Unmarshal(data, &doc); err != nil {
			t.Fatal(err)
		}
		if doc.Scrutineer.Preflight.Status != coverage.PreflightDegraded || doc.Repo.Name != "keep" {
			t.Fatalf("context=%s", data)
		}
	}
	if err := applySkillCoverageClaim(&scan, coverage.Claim{Receipts: []coverage.Receipt{}}); err != nil {
		t.Fatal(err)
	}
	if scan.Completeness != coverage.CompletenessPartial {
		t.Fatal("model erased preflight cap")
	}
	if err := sj.RecordPreflight(coverage.Preflight{Status: coverage.PreflightReady, Missing: []string{}}); err != nil {
		t.Fatal(err)
	}
	if scan.Completeness != coverage.CompletenessPartial {
		t.Fatal("repair erased earlier degraded attempt")
	}
	if err := w.DB.Delete(&stored).Error; err != nil {
		t.Fatal(err)
	}
	if err := sj.RecordPreflight(coverage.Preflight{Status: coverage.PreflightReady}); err == nil {
		t.Fatal("silently ignored missing scan")
	}
}
