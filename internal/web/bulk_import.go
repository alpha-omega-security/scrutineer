package web

import "context"

func (s *Server) bulkImportRepo(ctx context.Context, input RepoInput, model string, rescan bool) (created, queued bool, err error) {
	repo, created, err := s.createOrTriageRepo(ctx, input, model, false)
	if err != nil {
		return created, false, err
	}
	if !created && !rescan && input.Branch == "" && input.SubPath == "" {
		return false, false, nil
	}
	queued, err = s.enqueueDefaultTriage(ctx, repo, input, model)
	return created, queued, err
}
