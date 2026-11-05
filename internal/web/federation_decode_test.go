package web

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"scrutineer/internal/db"
	"scrutineer/internal/interchange"
)

func TestImportFeedSkipsInvalidDecodedStatements(t *testing.T) {
	s, cleanup := newTestServer(t)
	defer cleanup()
	s.Worker.DataDir = t.TempDir()
	badRepo := seedFeedRepo(t, s, "https://example.com/bad", "")
	goodRepo := seedFeedRepo(t, s, "https://example.com/good", "")
	bad := interchange.NewOptOut(interchange.OptOutPredicate{Repository: badRepo.URL, RequestedAt: feedTime(t)})
	good := interchange.NewOptOut(interchange.OptOutPredicate{Repository: goodRepo.URL, RequestedAt: feedTime(t), Reason: "valid peer request"})
	raw := make(map[string]string)
	for name, fields := range map[string]map[string]any{
		"0": {"Subject": []any{}},
		"1": {"Subject": []any{map[string]any{"name": badRepo.URL, "digest": map[string]string{"sha256": "../../not-hex"}}}},
		"2": {"Predicate": map[string]any{"repository": badRepo.URL, "requested_at": "2026-07-01T12:00:00Z", "finding_body": "fixture evidence"}},
	} {
		body, err := json.Marshal(bad)
		if err != nil {
			t.Fatal(err)
		}
		extension, err := json.Marshal(fields)
		if err != nil {
			t.Fatal(err)
		}
		body = append(append(body[:len(body)-1], ','), extension[1:]...)
		if err := interchange.Validate(body); err != nil {
			t.Fatalf("raw record precondition: %v", err)
		}
		raw["optout/"+strings.Repeat(name, 64)+".json"] = string(body)
	}
	remote := publishPeerFeedWithRaw(t, []interchange.Statement{good}, raw)
	if err := s.importFeed(context.Background(), remote, mustRepoIDs(t, s)); err != nil {
		t.Fatal(err)
	}
	var rows []db.InterchangeRecord
	if err := s.DB.Where("feed = ?", remote).Find(&rows).Error; err != nil {
		t.Fatal(err)
	}
	if len(rows) != 1 || rows[0].SubjectDigest != good.Subject[0].Digest["sha256"] || rows[0].AppliedAt == nil {
		t.Fatalf("archived records = %+v, want only the valid applied record", rows)
	}
	var gotBad, gotGood db.Repository
	if err := s.DB.First(&gotBad, badRepo.ID).Error; err != nil {
		t.Fatal(err)
	}
	if err := s.DB.First(&gotGood, goodRepo.ID).Error; err != nil {
		t.Fatal(err)
	}
	if gotBad.FederationOptOutAt != nil {
		t.Fatal("invalid decoded record changed its repository")
	}
	if gotGood.FederationOptOutAt == nil || gotGood.FederationOptOutReason != "valid peer request" {
		t.Fatal("valid record after the invalid records was not applied")
	}
}
