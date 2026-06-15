package web

import (
	_ "embed"
	"encoding/json"
	"sort"
	"strings"

	"gorm.io/gorm"
)

//go:embed cwe.json
var cweJSON []byte

// CWE is one entry from the MITRE catalogue. The JSON is generated from the
// CWE XML download; see development.md. Category is the View-1400
// ("Comprehensive Categorization for Software Assurance Trends") bucket the
// weakness belongs to, or empty when the weakness is not mapped (e.g. items
// outside View-1400's Weakness scope).
type CWE struct {
	Name        string `json:"name"`
	Description string `json:"description"`
	Category    string `json:"category,omitempty"`
}

var (
	cweIndex       map[string]CWE
	cweCategories  []string
	cweByCategory  map[string][]string
	categorizedIDs []string
)

// UncategorizedCWE is the filter token shown to users for entries that are
// not mapped to a View-1400 bucket.
const UncategorizedCWE = "Uncategorized"

// categoryCWEID maps each View-1400 category label to its own CWE-ID. The
// mapping is canonical and stable (MITRE never renumbers View-1400), so it
// is hardcoded rather than re-derived from cwe.json at startup.
var categoryCWEID = map[string]string{
	"Access Control":        "CWE-1396",
	"Comparison":            "CWE-1397",
	"Component Interaction": "CWE-1398",
	"Memory Safety":         "CWE-1399",
	"Concurrency":           "CWE-1401",
	"Encryption":            "CWE-1402",
	"Exposed Resource":      "CWE-1403",
	"File Handling":         "CWE-1404",
	"Improper Check or Handling of Exceptional Conditions": "CWE-1405",
	"Improper Input Validation":                            "CWE-1406",
	"Improper Neutralization":                              "CWE-1407",
	"Incorrect Calculation":                                "CWE-1408",
	"Injection":                                            "CWE-1409",
	"Insufficient Control Flow Management":                 "CWE-1410",
	"Insufficient Verification of Data Authenticity":       "CWE-1411",
	"Poor Coding Practices":                                "CWE-1412",
	"Protection Mechanism Failure":                         "CWE-1413",
	"Randomness":                                           "CWE-1414",
	"Resource Control":                                     "CWE-1415",
	"Resource Lifecycle Management":                        "CWE-1416",
	"Sensitive Information Exposure":                       "CWE-1417",
	"Violation of Secure Design Principles":                "CWE-1418",
}

func init() {
	_ = json.Unmarshal(cweJSON, &cweIndex)
	seen := map[string]bool{}
	cweByCategory = map[string][]string{}
	for id, c := range cweIndex {
		if c.Category == "" {
			continue
		}
		cweByCategory[c.Category] = append(cweByCategory[c.Category], id)
		categorizedIDs = append(categorizedIDs, id)
		if !seen[c.Category] {
			seen[c.Category] = true
			cweCategories = append(cweCategories, c.Category)
		}
	}
	sort.Strings(cweCategories)
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

// CWECategories returns the View-1400 category labels in alphabetical order.
// Used to populate the category filter dropdown.
func CWECategories() []string { return cweCategories }

// CategoryLabel formats a View-1400 category label with its CWE-ID prefix,
// e.g. "Injection" becomes "CWE-1409 — Injection". The pseudo-category
// UncategorizedCWE and any unknown name are returned unchanged.
func CategoryLabel(name string) string {
	if id, ok := categoryCWEID[name]; ok {
		return id + " — " + name
	}
	return name
}

// CWECategoryID returns the View-1400 category CWE-ID for a given weakness
// CWE-ID (e.g. "CWE-352" -> "CWE-1411"). Returns "" when the weakness is
// unknown or not mapped to a View-1400 bucket.
func CWECategoryID(cwe string) string { return categoryCWEID[cweIndex[cwe].Category] }

// CWEsInCategory returns the CWE-IDs that belong to a View-1400 category,
// or nil for an unknown category. The UncategorizedCWE bucket is handled
// by applyCWECategoryFilter, not here.
func CWEsInCategory(category string) []string {
	return cweByCategory[category]
}

// applyCWECategoryFilter restricts a findings query to the CWE-IDs in the
// given View-1400 category. UncategorizedCWE matches findings whose cwe is
// empty or absent from the catalogue. An unknown category matches nothing.
func applyCWECategoryFilter(q *gorm.DB, category string) *gorm.DB {
	if category == UncategorizedCWE {
		if len(categorizedIDs) == 0 {
			return q.Where("cwe = ''")
		}
		// categorizedIDs is the full View-1400 catalogue, so the
		// NOT IN list is large. Fine on sqlite; revisit if the project
		// ever moves to a backend with a tighter IN-list cap.
		return q.Where("cwe = '' OR cwe NOT IN ?", categorizedIDs)
	}
	ids := CWEsInCategory(category)
	if len(ids) == 0 {
		return q.Where("1 = 0")
	}
	return q.Where("cwe IN ?", ids)
}
