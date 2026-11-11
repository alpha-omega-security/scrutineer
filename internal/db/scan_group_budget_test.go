package db_test

import (
	"testing"

	"scrutineer/internal/db"
	"scrutineer/internal/db/dbtest"
)

func TestScanGroupBudget_setAndGet(t *testing.T) {
	gdb := dbtest.Open(t)
	if err := db.SetScanGroupBudget(gdb, "g1", 3, 5); err != nil {
		t.Fatal(err)
	}
	if got, err := db.ScanGroupBudgetFor(gdb, "g1"); err != nil || got != 5 {
		t.Fatalf("budget = %v, %v, want 5", got, err)
	}
	if err := db.SetScanGroupBudget(gdb, "g1", 3, 8.5); err != nil {
		t.Fatal(err)
	}
	if got, _ := db.ScanGroupBudgetFor(gdb, "g1"); got != 8.5 {
		t.Errorf("budget after upsert = %v, want 8.5", got)
	}
	var rows int64
	gdb.Model(&db.ScanGroupBudget{}).Count(&rows)
	if rows != 1 {
		t.Errorf("rows = %d, want 1", rows)
	}
	if got, err := db.ScanGroupBudgetFor(gdb, "other"); err != nil || got != 0 {
		t.Errorf("unknown group budget = %v, %v, want 0", got, err)
	}
}

func TestScanGroupBudget_noOps(t *testing.T) {
	gdb := dbtest.Open(t)
	for _, c := range []struct {
		group string
		limit float64
	}{{"", 5}, {"g", 0}, {"g", -1}} {
		if err := db.SetScanGroupBudget(gdb, c.group, 1, c.limit); err != nil {
			t.Fatal(err)
		}
	}
	var rows int64
	gdb.Model(&db.ScanGroupBudget{}).Count(&rows)
	if rows != 0 {
		t.Errorf("rows = %d, want 0", rows)
	}
	if got, err := db.ScanGroupBudgetFor(gdb, ""); err != nil || got != 0 {
		t.Errorf("empty group budget = %v, %v, want 0", got, err)
	}
}

func TestScanGroupSpend(t *testing.T) {
	gdb := dbtest.Open(t)
	repo := db.Repository{URL: "https://example.com/s", Name: "s"}
	gdb.Create(&repo)
	var ids []uint
	for _, sc := range []db.Scan{
		{RepositoryID: repo.ID, ScanGroup: "g", CostUSD: 1.5},
		{RepositoryID: repo.ID, ScanGroup: "g", CostUSD: 2},
		{RepositoryID: repo.ID, ScanGroup: "other", CostUSD: 9},
	} {
		gdb.Create(&sc)
		ids = append(ids, sc.ID)
	}
	if got, err := db.ScanGroupSpend(gdb, "g", 0); err != nil || got != 3.5 {
		t.Errorf("spend = %v, %v, want 3.5", got, err)
	}
	if got, _ := db.ScanGroupSpend(gdb, "g", ids[0]); got != 2 {
		t.Errorf("spend excluding first = %v, want 2", got)
	}
	if got, _ := db.ScanGroupSpend(gdb, "none", 0); got != 0 {
		t.Errorf("empty group spend = %v, want 0", got)
	}
}
