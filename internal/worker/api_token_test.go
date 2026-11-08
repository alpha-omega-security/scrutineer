package worker

import (
	"context"
	"errors"
	"testing"
	"time"

	"scrutineer/internal/db"
)

const testAPIToken = "per-run-token"

func TestTerminalScanClearsAPIToken(t *testing.T) {
	finalize := func(ctx context.Context, err error) func(*Worker, *db.Scan) {
		return func(w *Worker, scan *db.Scan) {
			if startErr := w.startScan(scan); startErr != nil {
				t.Fatal(startErr)
			}
			if finErr := w.finalizeScan(ctx, scan, "", err, time.Minute, func(Event) {}, func() {}); finErr != nil {
				t.Fatal(finErr)
			}
		}
	}
	cases := []struct {
		name      string
		run       func(*Worker, *db.Scan)
		want      db.ScanStatus
		wantToken string
	}{
		{"done", finalize(context.Background(), nil), db.ScanDone, ""},
		{"failed", finalize(context.Background(), errors.New("runner failed")), db.ScanFailed, ""},
		{"cancelled", finalize(cancelledContext(), nil), db.ScanCancelled, ""},
		{"opted out", func(w *Worker, scan *db.Scan) { w.cancelOptedOut(scan) }, db.ScanCancelled, ""},
		{"failed prerequisites", func(w *Worker, scan *db.Scan) {
			w.failScanPrereqs(scan, scan.SkillName, "prereqs failed", []string{"threat-model"})
		}, db.ScanFailed, ""},
		{"server restarted", func(w *Worker, scan *db.Scan) {
			if err := w.startScan(scan); err != nil {
				t.Fatal(err)
			}
			if err := db.SweepRunning(w.DB); err != nil {
				t.Fatal(err)
			}
		}, db.ScanFailed, ""},
		// Resume reuses the row's token, so a pause must keep it.
		{"paused", finalize(context.Background(), &AccountError{Detail: "limit"}), db.ScanPaused, testAPIToken},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			w, skill, repoID := newResumeTestWorker(t, &recordingRunner{})
			scan := db.Scan{RepositoryID: repoID, Kind: JobSkill, Status: db.ScanQueued,
				SkillID: &skill.ID, SkillName: skill.Name, APIToken: testAPIToken}
			if err := w.DB.Create(&scan).Error; err != nil {
				t.Fatal(err)
			}
			tc.run(w, &scan)

			var got db.Scan
			if err := w.DB.First(&got, scan.ID).Error; err != nil {
				t.Fatal(err)
			}
			if got.Status != tc.want {
				t.Fatalf("status = %q, want %q", got.Status, tc.want)
			}
			if got.APIToken != tc.wantToken {
				t.Errorf("api_token = %q, want %q", got.APIToken, tc.wantToken)
			}
		})
	}
}
