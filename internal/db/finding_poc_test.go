package db_test

import (
	"testing"

	"scrutineer/internal/db/dbtest"
)

func TestFindingPoCTableName(t *testing.T) {
	gdb := dbtest.Open(t)
	if !gdb.Migrator().HasTable("finding_pocs") || gdb.Migrator().HasTable("finding_po_cs") {
		t.Fatal("PoC migration must create finding_pocs")
	}
}
