package web

import "testing"

func TestLookupCWE(t *testing.T) {
	id, c, ok := LookupCWE("79")
	if !ok || id != "CWE-79" || c.Name == "" {
		t.Fatalf("CWE-79: ok=%v id=%q name=%q", ok, id, c.Name)
	}
	if _, c2, _ := LookupCWE("cwe-79"); c2.Name != c.Name {
		t.Error("case-insensitive lookup failed")
	}
	if _, _, ok := LookupCWE("CWE-999999"); ok {
		t.Error("unknown id should miss")
	}
	if _, _, ok := LookupCWE(""); ok {
		t.Error("empty id should miss")
	}
}
