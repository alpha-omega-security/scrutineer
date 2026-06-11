package db

import (
	gocvss30 "github.com/pandatix/go-cvss/30"
	gocvss31 "github.com/pandatix/go-cvss/31"
	gocvss40 "github.com/pandatix/go-cvss/40"
)

// BaseScoreFromVector computes the CVSS base score for a v3.0 or v3.1
// vector. Returns (0, false) when the vector is empty or unparseable;
// callers should clear cvss_score in that case rather than pinning a
// stale value next to a fresh (or removed) vector. v4 vectors are
// handled by ScoreFromV4Vector — the two scales are not interchangeable
// and a single helper would mislead callers about which version they
// got back.
func BaseScoreFromVector(vector string) (float64, bool) {
	if vector == "" {
		return 0, false
	}
	if v, err := gocvss31.ParseVector(vector); err == nil {
		return v.BaseScore(), true
	}
	if v, err := gocvss30.ParseVector(vector); err == nil {
		return v.BaseScore(), true
	}
	return 0, false
}

// ScoreFromV4Vector computes the CVSS v4.0 base score for a vector.
// Returns (0, false) when the vector is empty or unparseable, matching
// BaseScoreFromVector's contract.
func ScoreFromV4Vector(vector string) (float64, bool) {
	if vector == "" {
		return 0, false
	}
	v, err := gocvss40.ParseVector(vector)
	if err != nil {
		return 0, false
	}
	return v.Score(), true
}
