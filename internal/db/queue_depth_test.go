package db

import (
	"errors"
	"testing"
	"time"
)

// TestQueueDepth pins when a claim, a cancellation, a resume, an import and
// history ending before the window leave the queue, from timestamps alone.
func TestQueueDepth(t *testing.T) {
	gdb, err := Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	repo := Repository{URL: "https://example.com/queue-depth", Name: "queue-depth"}
	if err := gdb.Create(&repo).Error; err != nil {
		t.Fatal(err)
	}
	t0 := time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC)
	at := func(d time.Duration) *time.Time { return new(t0.Add(d)) }
	for _, sc := range []Scan{
		{Status: ScanDone, CreatedAt: t0, StartedAt: at(2 * time.Hour), FinishedAt: at(3 * time.Hour)},
		{Status: ScanCancelled, CreatedAt: t0.Add(time.Hour), FinishedAt: at(4 * time.Hour)},
		{Status: ScanRunning, CreatedAt: t0.Add(30 * time.Minute), StartedAt: at(90 * time.Minute)},
		{Status: ScanQueued, CreatedAt: t0.Add(3 * time.Hour), StartedAt: at(210 * time.Minute)},
		{Kind: "import", Status: ScanDone, CreatedAt: t0.Add(time.Hour + time.Second), StartedAt: at(time.Hour), FinishedAt: at(time.Hour)},
		{Status: ScanDone, CreatedAt: t0.Add(-5 * time.Hour), StartedAt: at(-4 * time.Hour), FinishedAt: at(-3 * time.Hour)},
	} {
		sc.RepositoryID = repo.ID
		if err := gdb.Create(&sc).Error; err != nil {
			t.Fatal(err)
		}
	}

	points, err := QueueDepth(gdb, t0, t0.Add(5*time.Hour), time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	want := []int{1, 3, 1, 2, 1, 1}
	if len(points) != len(want) {
		t.Fatalf("points = %+v, want %d", points, len(want))
	}
	for i, p := range points {
		if !p.At.Equal(t0.Add(time.Duration(i) * time.Hour)) {
			t.Errorf("point %d at %s", i, p.At)
		}
		if p.Queued != want[i] {
			t.Errorf("queued at +%dh = %d, want %d", i, p.Queued, want[i])
		}
	}
}

// TestQueueDepthReplaysEvents pins that paused hours read as not queued once
// the resume has cleared them from the row, including a pause taken while
// running and a resume whose enqueue failed.
func TestQueueDepthReplaysEvents(t *testing.T) {
	gdb, err := Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	repo := Repository{URL: "https://example.com/queue-depth", Name: "queue-depth"}
	if err := gdb.Create(&repo).Error; err != nil {
		t.Fatal(err)
	}
	t0 := time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC)
	at := func(h int) *time.Time { return new(t0.Add(time.Duration(h) * time.Hour)) }
	type event struct {
		kind string
		hour int
	}
	for _, tc := range []struct {
		scan   Scan
		events []event
	}{
		// Paused at +1h and resumed at +3h, still queued.
		{Scan{Status: ScanQueued, CreatedAt: t0}, []event{{AuditEventScanPaused, 1}, {AuditEventScanResumeRequested, 3}}},
		// Ran from +1h, paused mid-run at +2h, resumed at +4h and claimed at +5h.
		{Scan{Status: ScanRunning, CreatedAt: t0, StartedAt: at(5)}, []event{{AuditEventScanStarted, 1}, {AuditEventScanPaused, 2}, {AuditEventScanResumeRequested, 4}, {AuditEventScanStarted, 5}}},
		// Paused at +1h, a resume at +2h failed to enqueue, resumed for good at +4h.
		{Scan{Status: ScanQueued, CreatedAt: t0}, []event{{AuditEventScanPaused, 1}, {AuditEventScanResumeRequested, 2}, {AuditEventScanResumeEnqueueFailed, 2}, {AuditEventScanResumeRequested, 4}}},
	} {
		sc := tc.scan
		sc.RepositoryID = repo.ID
		if err := gdb.Create(&sc).Error; err != nil {
			t.Fatal(err)
		}
		for _, ev := range tc.events {
			if err := gdb.Create(&AuditEvent{Kind: ev.kind, SubjectType: AuditSubjectScan, SubjectID: sc.ID, Source: SourceSystem, Payload: "{}", CreatedAt: *at(ev.hour)}).Error; err != nil {
				t.Fatal(err)
			}
		}
	}

	points, err := QueueDepth(gdb, t0, t0.Add(5*time.Hour), time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	want := []int{3, 0, 0, 1, 3, 2}
	if len(points) != len(want) {
		t.Fatalf("points = %+v, want %d", points, len(want))
	}
	for i, p := range points {
		if p.Queued != want[i] {
			t.Errorf("queued at +%dh = %d, want %d", i, p.Queued, want[i])
		}
	}
}

// TestQueueDepthAcrossOffsets pins that rows stored in another UTC offset than
// the window still count.
func TestQueueDepthAcrossOffsets(t *testing.T) {
	gdb, err := Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	repo := Repository{URL: "https://example.com/queue-depth", Name: "queue-depth"}
	if err := gdb.Create(&repo).Error; err != nil {
		t.Fatal(err)
	}
	t0 := time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC)
	east, west := time.FixedZone("UTC+9", 9*3600), time.FixedZone("UTC-5", -5*3600)
	for _, sc := range []Scan{
		{Status: ScanQueued, CreatedAt: t0.Add(-time.Minute).In(east)},
		{Status: ScanCancelled, CreatedAt: t0.Add(-time.Hour).In(west), FinishedAt: new(t0.Add(time.Minute).In(west))},
		{Status: ScanQueued, CreatedAt: t0.Add(time.Minute).In(west)},
	} {
		sc.RepositoryID = repo.ID
		if err := gdb.Create(&sc).Error; err != nil {
			t.Fatal(err)
		}
	}
	points, err := QueueDepth(gdb, t0, t0, time.Hour)
	if err != nil || len(points) != 1 || points[0].Queued != 2 {
		t.Fatalf("points = %+v, err %v, want 2 queued at t0", points, err)
	}
}

func TestQueueDepthRejectsInvalidWindows(t *testing.T) {
	gdb, err := Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	t0 := time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC)
	for name, tc := range map[string]struct {
		to   time.Time
		step time.Duration
	}{
		"zero step":       {t0.Add(time.Hour), 0},
		"negative step":   {t0.Add(time.Hour), -time.Minute},
		"to before from":  {t0.Add(-time.Hour), time.Minute},
		"too many points": {t0.Add(QueueDepthMaxPoints * time.Minute), time.Minute},
		"past Duration":   {t0.AddDate(300, 0, 0), 2563 * time.Hour},
	} {
		if _, err := QueueDepth(gdb, t0, tc.to, tc.step); !errors.Is(err, ErrInvalidQueueDepthWindow) {
			t.Errorf("%s: err = %v, want ErrInvalidQueueDepthWindow", name, err)
		}
	}
	points, err := QueueDepth(gdb, t0, t0.Add((QueueDepthMaxPoints-1)*time.Minute), time.Minute)
	if err != nil || len(points) != QueueDepthMaxPoints {
		t.Fatalf("largest window: %d points, err %v", len(points), err)
	}
}
