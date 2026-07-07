package web

import (
	"maps"
	"net/url"
	"strings"
)

// sortCtx builds column-sort URLs and reports the active sort direction for
// the index tables. render() injects one, built from the current request, as
// ".Sorter" in every template so the th-sort partial can drive header links
// without each handler threading path/query through by hand.
//
// Direction is folded into the sort token rather than carried in a separate
// query param: "severity" means the column's natural default direction and
// "severity.asc"/"severity.desc" pin it. Because that one `sort` value is
// already propagated by every filter and pagination link, direction survives
// filtering and paging with no extra plumbing.
type sortCtx struct {
	path  string
	query url.Values
}

// splitSort parses a "key.dir" sort token. The direction suffix is only
// honoured when it is exactly "asc" or "desc"; otherwise defDir is returned,
// so callers can pass a per-column default (or "" to detect "unset").
func splitSort(token, defDir string) (key, dir string) {
	key, rest, ok := strings.Cut(token, ".")
	if ok && (rest == "asc" || rest == "desc") {
		return key, rest
	}
	return token, defDir
}

// dirOr returns dir when it is a valid direction ("asc"/"desc"), else def. It
// resolves the request direction for the NON-SQL callers — the template arrow
// (sortCtx.Dir) and the in-memory org comparator (dirLess). SQL ORDER BY
// clauses do not use this: they go through orderByExpr, which carries the
// direction as a boolean so the request never reaches the query at all.
func dirOr(dir, def string) string {
	if dir == "asc" || dir == "desc" {
		return dir
	}
	return def
}

// wantDesc resolves a validated direction to a boolean; defaultDesc applies
// when dir is unset. It is the single point that turns the (allowlisted)
// request direction into a bool, so callers build an ORDER BY without ever
// concatenating the request's own bytes into SQL.
func wantDesc(dir string, defaultDesc bool) bool {
	switch dir {
	case "asc":
		return false
	case "desc":
		return true
	default:
		return defaultDesc
	}
}

// orderBySuffix appends ASC or DESC — a code literal, chosen by a boolean — to
// a TRUSTED, constant SQL expression. Because the direction is a bool and the
// suffix is literal, the request contributes no bytes to the clause; the result
// is provably one of two fixed strings.
//
// expr MUST be a compile-time constant; never pass request-derived text (a SQL
// ORDER BY direction cannot be a bind parameter, so a raw expression here is
// the boundary — keep it constant).
func orderBySuffix(expr string, desc bool) string {
	if desc {
		return expr + " DESC"
	}
	return expr + " ASC"
}

// orderByExpr is the common case: resolve dir against defaultDesc, then suffix
// the trusted expr. Every index sort builds its ORDER BY through this (or
// orderBySuffix directly, for the severity rank whose expression inverts the
// logical direction), so no sort concatenates the request direction into SQL.
func orderByExpr(expr, dir string, defaultDesc bool) string {
	return orderBySuffix(expr, wantDesc(dir, defaultDesc))
}

// URL returns the current index URL re-sorted by key. When key is already the
// active sort it flips direction; otherwise it applies def, the column's
// natural default. Every other query param (filters, search) is preserved and
// pagination resets to page 1.
func (c sortCtx) URL(key, def string) string {
	curKey, curDir := splitSort(c.query.Get("sort"), "")
	next := def
	if curKey == key {
		eff := curDir
		if eff == "" {
			eff = def
		}
		if eff == "asc" {
			next = "desc"
		} else {
			next = "asc"
		}
	}
	token := key
	if next != def {
		token = key + "." + next
	}
	q := url.Values{}
	maps.Copy(q, c.query)
	q.Set("sort", token)
	q.Del("page") // re-sorting starts on page 1
	return c.path + "?" + q.Encode()
}

// Dir reports the active direction for key ("asc"/"desc") so a header can draw
// its arrow, or "" when key is not the current sort.
func (c sortCtx) Dir(key, def string) string {
	curKey, curDir := splitSort(c.query.Get("sort"), "")
	if curKey != key {
		return ""
	}
	return dirOr(curDir, def)
}

// sortKey returns just the column key of a sort token, dropping any direction
// suffix. Templates use it to keep a sort dropdown's label and active-item
// highlight in sync with a compound token like "severity.asc".
func sortKey(token string) string {
	key, _ := splitSort(token, "")
	return key
}
