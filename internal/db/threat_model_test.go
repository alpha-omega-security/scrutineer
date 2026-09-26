package db_test

import (
	"errors"
	"testing"

	"scrutineer/internal/db"
	"scrutineer/internal/db/dbtest"
)

func TestUpdateThreatModelRetriesConcurrentEdit(t *testing.T) {
	gdb := dbtest.Open(t)
	repo := db.Repository{URL: "https://example.com/model", Name: "model", ThreatModel: "initial"}
	if err := gdb.Create(&repo).Error; err != nil {
		t.Fatal(err)
	}
	calls := 0
	err := db.UpdateThreatModel(gdb, repo.ID, func(previous string) (string, error) {
		calls++
		if calls == 1 {
			if err := gdb.Model(&repo).Update("threat_model", "operator edit").Error; err != nil {
				return "", err
			}
		}
		return previous + " merged", nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := gdb.First(&repo, repo.ID).Error; err != nil {
		t.Fatal(err)
	}
	if calls != 2 || repo.ThreatModel != "operator edit merged" {
		t.Fatalf("calls=%d model=%s", calls, repo.ThreatModel)
	}
	want := errors.New("invalid report")
	if err := db.UpdateThreatModel(gdb, repo.ID, func(string) (string, error) { return "", want }); !errors.Is(err, want) {
		t.Fatalf("error=%v", err)
	}
}
