package web

import (
	"testing"

	"scrutineer/internal/db"
)

func TestResumeOpts(t *testing.T) {
	uintPtr := func(v uint) *uint { return &v }

	cases := []struct {
		name       string
		scan       db.Scan
		wantSID    string
		wantResume *uint
	}{
		{
			name:    "failed with session resumes from its own id",
			scan:    db.Scan{ID: 7, Status: db.ScanFailed, SessionID: "s1"},
			wantSID: "s1", wantResume: uintPtr(7),
		},
		{
			name:    "failed retry keeps the lineage root",
			scan:    db.Scan{ID: 9, Status: db.ScanFailed, SessionID: "s1", ResumedFromScanID: uintPtr(7)},
			wantSID: "s1", wantResume: uintPtr(7),
		},
		{
			name: "done scan retries fresh",
			scan: db.Scan{ID: 7, Status: db.ScanDone, SessionID: ""},
		},
		{
			name: "failed but no session retries fresh",
			scan: db.Scan{ID: 7, Status: db.ScanFailed, SessionID: ""},
		},
		{
			name: "cancelled scan retries fresh even with a session",
			scan: db.Scan{ID: 7, Status: db.ScanCancelled, SessionID: "s1"},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			sid, resume := resumeOpts(tc.scan)
			if sid != tc.wantSID {
				t.Errorf("sessionID = %q, want %q", sid, tc.wantSID)
			}
			switch {
			case tc.wantResume == nil && resume != nil:
				t.Errorf("resumeOf = %v, want nil", *resume)
			case tc.wantResume != nil && resume == nil:
				t.Errorf("resumeOf = nil, want %d", *tc.wantResume)
			case tc.wantResume != nil && *resume != *tc.wantResume:
				t.Errorf("resumeOf = %d, want %d", *resume, *tc.wantResume)
			}
		})
	}
}
