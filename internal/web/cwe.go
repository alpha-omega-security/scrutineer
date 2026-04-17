package web

import (
	_ "embed"
	"encoding/json"
	"strings"
)

//go:embed cwe.json
var cweJSON []byte

// CWE is one entry from the MITRE catalogue (cwe.mitre.org/data/csv/1000.csv).
// The JSON is generated once at build time; see README.
type CWE struct {
	Name        string `json:"name"`
	Description string `json:"description"`
}

var cweIndex map[string]CWE

func init() {
	_ = json.Unmarshal(cweJSON, &cweIndex)
}

// LookupCWE accepts "CWE-79", "cwe-79" or "79" and returns the entry plus the
// canonical id. Second return is false when unknown.
func LookupCWE(id string) (string, CWE, bool) {
	id = strings.ToUpper(strings.TrimSpace(id))
	if id == "" {
		return "", CWE{}, false
	}
	if !strings.HasPrefix(id, "CWE-") {
		id = "CWE-" + id
	}
	c, ok := cweIndex[id]
	return id, c, ok
}
