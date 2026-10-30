package db_test

import (
	"bytes"
	"errors"
	"log/slog"
	"testing"

	"gorm.io/gorm"

	"scrutineer/internal/db"
	"scrutineer/internal/db/dbtest"
)

func TestTimedTransactionQuietAndAtomic(t *testing.T) {
	gdb := dbtest.Open(t)
	var logs bytes.Buffer
	log := slog.New(slog.NewJSONHandler(&logs, nil))
	repo := db.Repository{URL: "https://example.com/transaction"}
	if err := db.TimedTransaction(gdb, log, func(tx *gorm.DB) error { return tx.Create(&repo).Error }); err != nil {
		t.Fatal(err)
	}
	wantErr := errors.New("rollback")
	err := db.TimedTransaction(gdb, log, func(tx *gorm.DB) error {
		if err := tx.Model(&repo).Update("name", "rolled-back").Error; err != nil {
			return err
		}
		return wantErr
	})
	if err != wantErr {
		t.Fatalf("error = %v, want original error", err)
	}
	var saved db.Repository
	if err := gdb.First(&saved, repo.ID).Error; err != nil {
		t.Fatal(err)
	}
	if saved.Name != "" {
		t.Fatalf("rollback did not preserve repository: %+v", saved)
	}
	if logs.Len() != 0 {
		t.Fatalf("fast transactions logged: %s", &logs)
	}
}
