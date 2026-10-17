package web

import (
	"context"
	"testing"

	"scrutineer/internal/db"
)

func TestAddRepository_queuesTriageOnce(t *testing.T) {
	s, done := newTestServer(t)
	defer done()
	s.DB.Create(&db.Skill{Name: "triage", Description: "o", Body: "b", Active: true, Source: "ui", Version: 1})
	dir := t.TempDir()

	repo, isNew, err := s.AddRepository(context.Background(), dir)
	if err != nil {
		t.Fatalf("AddRepository: %v", err)
	}
	if !isNew || repo.ID == 0 {
		t.Fatalf("isNew=%v id=%d, want a new repository", isNew, repo.ID)
	}
	var scans []db.Scan
	s.DB.Where("repository_id = ?", repo.ID).Find(&scans)
	if len(scans) != 1 || scans[0].SkillName != "triage" || scans[0].Status != db.ScanQueued {
		t.Fatalf("scans = %+v, want one queued triage scan", scans)
	}

	again, isNew, err := s.AddRepository(context.Background(), dir)
	if err != nil {
		t.Fatalf("second AddRepository: %v", err)
	}
	if isNew || again.ID != repo.ID {
		t.Errorf("second add isNew=%v id=%d, want existing repo %d", isNew, again.ID, repo.ID)
	}
	var n int64
	s.DB.Model(&db.Scan{}).Where("repository_id = ?", repo.ID).Count(&n)
	if n != 1 {
		t.Errorf("scan count after re-add = %d, want 1", n)
	}
}
