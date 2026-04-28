package worker

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"scrutineer/internal/db"
)

const cnaFixture = `[
  {
    "shortName": "apache",
    "cnaID": "CNA-2016-0004",
    "organizationName": "Apache Software Foundation",
    "scope": "All Apache Software Foundation projects",
    "country": "USA",
    "contact": [{
      "email": [{"label": "Email", "emailAddr": "security@apache.org"}],
      "contact": [{"label": "Page", "url": "https://apache.org/security/"}]
    }],
    "disclosurePolicy": [{"label": "Policy", "url": "https://apache.org/security/committers.html"}],
    "securityAdvisories": {"advisories": [{"label": "Advisories", "url": "https://apache.org/security/projects.html"}]},
    "CNA": {"root": {"shortName": "mitre"}, "type": ["Open Source"]}
  },
  {
    "shortName": "curl",
    "cnaID": "CNA-2023-0002",
    "organizationName": "curl",
    "scope": "curl and libcurl",
    "contact": [{"email": [], "contact": []}],
    "disclosurePolicy": [],
    "securityAdvisories": {"advisories": []},
    "CNA": {"root": {"shortName": "mitre"}, "type": ["Open Source", "Vendor"]}
  }
]`

func TestParseCNAList(t *testing.T) {
	rows, err := parseCNAList([]byte(cnaFixture))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(rows) != 2 {
		t.Fatalf("rows = %d, want 2", len(rows))
	}
	a := rows[0]
	if a.ShortName != "apache" || a.CNAID != "CNA-2016-0004" {
		t.Errorf("identity = %s/%s", a.ShortName, a.CNAID)
	}
	if a.Email != "security@apache.org" {
		t.Errorf("email = %q", a.Email)
	}
	if a.ContactURL != "https://apache.org/security/" {
		t.Errorf("contact url = %q", a.ContactURL)
	}
	if a.PolicyURL != "https://apache.org/security/committers.html" {
		t.Errorf("policy url = %q", a.PolicyURL)
	}
	if a.AdvisoryURL != "https://apache.org/security/projects.html" {
		t.Errorf("advisory url = %q", a.AdvisoryURL)
	}
	if a.Root != "mitre" || a.Types != "Open Source" {
		t.Errorf("root/types = %s/%s", a.Root, a.Types)
	}
	if a.FetchedAt == nil {
		t.Errorf("FetchedAt not set")
	}
	if a.Metadata == "" {
		t.Errorf("Metadata not preserved")
	}
	c := rows[1]
	if c.Email != "" || c.PolicyURL != "" {
		t.Errorf("empty arrays should yield empty strings: %+v", c)
	}
	if c.Types != "Open Source,Vendor" {
		t.Errorf("types = %q", c.Types)
	}
}

func TestSyncCNAs_upsertsByShortName(t *testing.T) {
	gdb, err := db.Open("file::memory:")
	if err != nil {
		t.Fatal(err)
	}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(cnaFixture))
	}))
	defer srv.Close()

	n, err := SyncCNAs(context.Background(), gdb, srv.URL)
	if err != nil {
		t.Fatalf("first sync: %v", err)
	}
	if n != 2 {
		t.Fatalf("n = %d, want 2", n)
	}
	var count int64
	gdb.Model(&db.CNA{}).Count(&count)
	if count != 2 {
		t.Fatalf("rows after first sync = %d", count)
	}

	// Second sync should update in place, not duplicate.
	if _, err := SyncCNAs(context.Background(), gdb, srv.URL); err != nil {
		t.Fatalf("second sync: %v", err)
	}
	gdb.Model(&db.CNA{}).Count(&count)
	if count != 2 {
		t.Errorf("rows after second sync = %d, want 2 (upsert, not insert)", count)
	}

	var apache db.CNA
	gdb.Where("short_name = ?", "apache").First(&apache)
	if apache.Scope != "All Apache Software Foundation projects" {
		t.Errorf("apache scope = %q", apache.Scope)
	}
}
