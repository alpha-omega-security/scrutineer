package dbtest

import (
	"testing"

	"scrutineer/internal/db"
)

func TestOpen_isolatedPerCall(t *testing.T) {
	a := Open(t)
	b := Open(t)

	if err := a.Create(&db.Repository{URL: "https://example.com/a", Name: "a"}).Error; err != nil {
		t.Fatalf("create in a: %v", err)
	}
	var n int64
	if err := b.Model(&db.Repository{}).Count(&n).Error; err != nil {
		t.Fatalf("count in b: %v", err)
	}
	if n != 0 {
		t.Errorf("second Open sees %d rows from first; want isolated", n)
	}
}

func TestOpen_schemaMatchesAutoMigrate(t *testing.T) {
	fast := Open(t)
	full, err := db.Open("file::memory:")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if sqldb, _ := full.DB(); sqldb != nil {
			_ = sqldb.Close()
		}
	})

	const q = "SELECT type || ' ' || name FROM sqlite_schema WHERE name NOT LIKE 'sqlite_%' ORDER BY 1"
	var fromFast, fromFull []string
	if err := fast.Raw(q).Scan(&fromFast).Error; err != nil {
		t.Fatal(err)
	}
	if err := full.Raw(q).Scan(&fromFull).Error; err != nil {
		t.Fatal(err)
	}
	if len(fromFast) != len(fromFull) {
		t.Fatalf("object count differs: fast=%d full=%d", len(fromFast), len(fromFull))
	}
	for i := range fromFull {
		if fromFast[i] != fromFull[i] {
			t.Errorf("schema mismatch at %d: fast=%q full=%q", i, fromFast[i], fromFull[i])
		}
	}
}
