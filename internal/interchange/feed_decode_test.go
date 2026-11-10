package interchange

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"filippo.io/age"
)

func TestReadFeedValidatesDecodedStatements(t *testing.T) {
	base := optOut(t, "https://example.com/target")
	for _, encrypted := range []bool{false, true} {
		for _, tc := range []struct {
			name, field string
			value       any
			invalid     bool
		}{
			{name: "normal"},
			{name: "envelope extension", field: "metadata", value: map[string]string{"producer": "fixture"}},
			{name: "empty subject", field: "Subject", value: []ResourceDescriptor{}, invalid: true},
			{name: "missing digest", field: "Subject", value: []ResourceDescriptor{{Name: "target"}}, invalid: true},
			{name: "non-hex digest", field: "Subject", value: []ResourceDescriptor{{Name: "target", Digest: map[string]string{"sha256": "../../not-hex"}}}, invalid: true},
			{name: "invalid second subject", field: "Subject", value: []ResourceDescriptor{base.Subject[0], {Name: "other", Digest: map[string]string{"sha256": "not-hex"}}}, invalid: true},
			{name: "null predicate", field: "Predicate", value: nil, invalid: true},
			{name: "predicate extension", field: "Predicate", value: map[string]any{"repository": "https://example.com/target", "requested_at": "2026-07-01T12:00:00Z", "finding_body": "fixture evidence"}, invalid: true},
			{name: "statement type", field: "_Type", value: "unsupported", invalid: true},
			{name: "predicate type", field: "PredicateType", value: "unsupported", invalid: true},
		} {
			t.Run(tc.name+map[bool]string{false: "/plain", true: "/encrypted"}[encrypted], func(t *testing.T) {
				record, raw := readExtendedFeedRecord(t, base, tc.field, tc.value, encrypted)
				requireDecodedFeedRecord(t, record, raw, tc.invalid)
			})
		}
	}
}

func requireDecodedFeedRecord(t *testing.T, record FeedRecord, raw []byte, invalid bool) {
	t.Helper()
	if invalid {
		if record.Err == nil || !strings.Contains(record.Err.Error(), "invalid decoded record") {
			t.Fatalf("decoded record error = %v", record.Err)
		}
		if len(record.Statement.Subject) != 0 || record.Raw != nil {
			t.Fatal("rejected record exposed a partial statement or raw bytes")
		}
		return
	}
	if record.Err != nil {
		t.Fatal(record.Err)
	}
	if !bytes.Equal(record.Raw, raw) {
		t.Fatal("accepted record did not preserve the peer's exact bytes")
	}
	decoded, err := json.Marshal(record.Statement)
	if err != nil {
		t.Fatal(err)
	}
	if err := Validate(decoded); err != nil {
		t.Fatal(err)
	}
}

func readExtendedFeedRecord(t *testing.T, base Statement, field string, value any, encrypted bool) (FeedRecord, []byte) {
	t.Helper()
	raw, err := json.Marshal(base)
	if err != nil {
		t.Fatal(err)
	}
	if field != "" {
		extension, err := json.Marshal(map[string]any{field: value})
		if err != nil {
			t.Fatal(err)
		}
		raw = append(append(raw[:len(raw)-1], ','), extension[1:]...)
	}
	raw = append(raw, '\n')
	if err := Validate(raw); err != nil {
		t.Fatalf("raw record precondition: %v", err)
	}
	body := raw
	var identities []age.Identity
	if encrypted {
		id := testIdentity(t)
		identities = []age.Identity{id}
		body, err = encryptRecord(raw, []age.Recipient{id.Recipient()})
		if err != nil {
			t.Fatal(err)
		}
	}
	name, err := RecordFile(base, encrypted)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	path := filepath.Join(dir, name)
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, body, 0o644); err != nil {
		t.Fatal(err)
	}
	records, err := ReadFeed(dir, identities)
	if err != nil {
		t.Fatal(err)
	}
	if len(records) != 1 {
		t.Fatalf("ReadFeed returned %d records", len(records))
	}
	return records[0], raw
}
