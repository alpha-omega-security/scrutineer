package web

import (
	"github.com/git-pkgs/cwe"
	"gorm.io/gorm"
)

// CWE aliases the catalogue entry so templates that already say .Name and
// .Category keep working without a template change.
type CWE = cwe.Entry

// UncategorizedCWE is the filter token shown to users for entries that are
// not mapped to a View-1400 bucket.
const UncategorizedCWE = "Uncategorized"

// LookupCWE, CWECategories, CWECategoryID and CWEsInCategory are thin
// wrappers over github.com/git-pkgs/cwe kept so template-func registration
// and existing callers in this package do not need to change.
func LookupCWE(id string) (string, CWE, bool) { return cwe.Lookup(id) }
func CWECategories() []string                 { return cwe.Categories() }
func CWECategoryID(id string) string          { return cwe.CategoryOf(id) }
func CWEsInCategory(label string) []string    { return cwe.InCategory(label) }

// CategoryLabel formats a View-1400 category label with its CWE-ID prefix,
// e.g. "Injection" becomes "CWE-1409 — Injection". The pseudo-category
// UncategorizedCWE and any unknown name are returned unchanged.
func CategoryLabel(name string) string {
	if id := cwe.CategoryID(name); id != "" {
		return id + " — " + name
	}
	return name
}

// applyCWECategoryFilter restricts a findings query to the CWE-IDs in the
// given View-1400 category. UncategorizedCWE matches findings whose cwe is
// empty or absent from the catalogue. An unknown category matches nothing.
func applyCWECategoryFilter(q *gorm.DB, category string) *gorm.DB {
	if category == UncategorizedCWE {
		catalogued := cwe.CategorizedIDs()
		if len(catalogued) == 0 {
			return q.Where("cwe = ''")
		}
		// The full View-1400 catalogue, so the NOT IN list is large. Fine on
		// sqlite; revisit if the project ever moves to a backend with a
		// tighter IN-list cap.
		return q.Where("cwe = '' OR cwe NOT IN ?", catalogued)
	}
	ids := cwe.InCategory(category)
	if len(ids) == 0 {
		return q.Where("1 = 0")
	}
	return q.Where("cwe IN ?", ids)
}
