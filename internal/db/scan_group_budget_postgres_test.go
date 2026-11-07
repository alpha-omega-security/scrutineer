package db

import (
	"testing"

	"scrutineer/internal/testutil"
)

// TestPostgresScanGroupBudget runs the budget upsert on PostgreSQL.
func TestPostgresScanGroupBudget(t *testing.T) {
	gdb, err := OpenBackend(Options{Dialect: DialectPostgres, DSN: testutil.PostgresDSN(t)})
	if err != nil {
		t.Fatalf("OpenBackend postgres: %v", err)
	}
	closePostgres(t, gdb)

	const group = "pg-group-budget"
	gdb.Where("scan_group = ?", group).Delete(&ScanGroupBudget{})
	for _, limit := range []float64{4, 6.5} {
		if err := SetScanGroupBudget(gdb, group, 1, limit); err != nil {
			t.Fatalf("set budget: %v", err)
		}
	}
	if got, err := ScanGroupBudgetFor(gdb, group); err != nil || got != 6.5 {
		t.Errorf("budget = %v, %v, want 6.5", got, err)
	}
}
