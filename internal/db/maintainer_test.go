package db

import (
	"testing"

	"gorm.io/gorm"

	"scrutineer/internal/testutil"
)

func TestMaintainerActivityMigration(t *testing.T) {
	checkMaintainerActivityMigration(t, newTestDB(t))
}

func TestPostgresMaintainerActivityMigration(t *testing.T) {
	gdb, err := OpenBackend(Options{Dialect: DialectPostgres, DSN: testutil.PostgresDSN(t)})
	if err != nil {
		t.Fatal(err)
	}
	closePostgres(t, gdb)
	checkMaintainerActivityMigration(t, gdb)
}

func checkMaintainerActivityMigration(t *testing.T, gdb *gorm.DB) {
	t.Helper()
	if err := gdb.Migrator().DropTable(&MaintainerActivity{}); err != nil {
		t.Fatal(err)
	}
	repo := Repository{URL: "https://example.com/legacy", Name: "legacy"}
	maintainer := Maintainer{Login: "person", Name: "Original", Email: "original@example.org", Status: MaintainerActive, Notes: "analyst note", DoNotContact: true}
	if err := gdb.Create(&repo).Error; err != nil {
		t.Fatal(err)
	}
	if err := gdb.Create(&maintainer).Error; err != nil {
		t.Fatal(err)
	}
	if err := gdb.Model(&repo).Association("Maintainers").Append(&maintainer); err != nil {
		t.Fatal(err)
	}
	if err := migrate(gdb); err != nil {
		t.Fatal(err)
	}
	var activities int64
	if err := gdb.Model(&MaintainerActivity{}).Count(&activities).Error; err != nil {
		t.Fatal(err)
	}
	if activities != 0 {
		t.Fatalf("migration created %d activity records, want none", activities)
	}
	rows, err := RepositoryMaintainers(gdb, repo.ID)
	if err != nil || len(rows) != 1 {
		t.Fatalf("legacy maintainers = %+v, err=%v", rows, err)
	}
	if rows[0].Name != maintainer.Name || rows[0].Email != maintainer.Email || rows[0].Notes != maintainer.Notes || rows[0].Status != MaintainerActive || !rows[0].DoNotContact {
		t.Fatalf("migration changed the legacy profile: %+v", rows[0])
	}
	for _, status := range []MaintainerStatus{MaintainerActive, MaintainerInactive} {
		if err := RecordMaintainerActivity(gdb, repo.ID, maintainer.ID, string(status)); err != nil {
			t.Fatal(err)
		}
	}
	rows, err = RepositoryMaintainers(gdb, repo.ID)
	if err != nil || len(rows) != 1 || rows[0].Status != MaintainerInactive {
		t.Fatalf("refreshed activity = %+v, err=%v", rows, err)
	}
	var shared Maintainer
	if err := gdb.First(&shared, maintainer.ID).Error; err != nil {
		t.Fatal(err)
	}
	if shared.Status != MaintainerActive || shared.Name != maintainer.Name || shared.Email != maintainer.Email || shared.Notes != maintainer.Notes || !shared.DoNotContact {
		t.Fatalf("activity update changed shared profile: %+v", shared)
	}
}
