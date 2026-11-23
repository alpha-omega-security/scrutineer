package db

import (
	"errors"
	"testing"
	"time"
)

// TestQueueDepth pins when a claim, a cancellation, a resume, an overage pause,
// an import and history ending before the window leave the queue.
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
		{Status: ScanPaused, CreatedAt: t0},
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
