package web

import (
	"context"
	"time"

	"scrutineer/internal/db"
)

const repositoryHealthInterval = time.Hour

// StartRepositoryHealthScorer keeps Repository.Health fresh as time-dependent
// inputs such as pushed_at age. It runs once at startup, then periodically.
func (s *Server) StartRepositoryHealthScorer(ctx context.Context) {
	s.repositoryHealthTick(time.Now())
	t := time.NewTicker(repositoryHealthInterval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case now := <-t.C:
			s.repositoryHealthTick(now)
		}
	}
}

func (s *Server) repositoryHealthTick(now time.Time) {
	var repos []db.Repository
	if err := s.DB.Select("id").Find(&repos).Error; err != nil {
		s.Log.Error("repository health: list repositories", "err", err)
		return
	}
	for _, repo := range repos {
		if _, err := db.RefreshRepositoryHealth(s.DB, repo.ID, now); err != nil {
			s.Log.Error("repository health: refresh", "repo", repo.ID, "err", err)
		}
	}
}
