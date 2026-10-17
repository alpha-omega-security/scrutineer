package web

import (
	"context"

	"scrutineer/internal/db"
)

// AddRepository adds the repository and queues the default triage pipeline
// the same way the add form does. It is used by `scrutineer audit`. isNew is
// false when the repository was already present, in which case no scan is
// queued.
func (s *Server) AddRepository(ctx context.Context, raw string) (db.Repository, bool, error) {
	input, err := ParseRepoInput(raw)
	if err != nil {
		return db.Repository{}, false, err
	}
	return s.createOrTriageRepo(ctx, input, "", true)
}
