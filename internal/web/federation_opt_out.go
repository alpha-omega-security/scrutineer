package web

import (
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	"gorm.io/gorm"

	"scrutineer/internal/db"
	"scrutineer/internal/worker"
)

// repoFederationOptOut records or clears the maintainer's request that
// federated instances neither scan this repository nor contact them about
// it. Setting it blocks new scans everywhere the enqueue path reaches and
// stops the work already under way. An edit that only changes the reason keeps
// the original request date, since that date is what a federated peer is told
// the request was made on.
func (s *Server) repoFederationOptOut(w http.ResponseWriter, r *http.Request) {
	repo, ok := loadByID[db.Repository](s, w, r)
	if !ok {
		return
	}
	unlock := s.lockRepoFederation(repo.ID)
	defer unlock()
	optOut := r.FormValue("opt_out") != ""
	updates := map[string]any{"federation_opt_out_at": nil, "federation_opt_out_reason": ""}
	if optOut {
		at := time.Now().UTC()
		if repo.FederationOptOutAt != nil {
			at = *repo.FederationOptOutAt
		}
		updates["federation_opt_out_at"] = &at
		updates["federation_opt_out_reason"] = strings.TrimSpace(r.FormValue("reason"))
	}
	if err := s.DB.Model(&db.Repository{}).Where("id = ?", repo.ID).Updates(updates).Error; err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	// Sweep only after the flag is committed: from here on every enqueue path
	// refuses this repository, so nothing slips in behind the sweep, and a scan
	// the worker claims from the queue meanwhile hits its own dispatch gate.
	if optOut {
		if err := s.stopScansForOptOut(repo.ID); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
	}
	s.redirect(w, r, fmt.Sprintf("/repositories/%d", repo.ID))
}

// stopScansForOptOut cancels every scan still alive on a repository that just
// opted out. Recording the request has to stop the work already under way, not
// only refuse the next one: a queued or paused scan would otherwise still run
// later, and a running one keeps reading the maintainer's code and talking to
// their host. Queued and paused rows are flipped in bulk (neither is in
// flight, and the queue handler drops a cancelled row on pickup); a running
// scan is signalled through the worker, which unwinds it and writes its own
// terminal row. The caller redirects to the repo page, so the flipped rows
// re-render from the database rather than over per-scan SSE pushes.
func (s *Server) stopScansForOptOut(repoID uint) error {
	now := time.Now()
	if err := s.DB.Model(&db.Scan{}).
		Where("repository_id = ? AND status IN ?", repoID, []db.ScanStatus{db.ScanQueued, db.ScanPaused}).
		Updates(scanStatusUpdates(db.ScanCancelled, worker.OptOutCancelReason, &now, nil)).Error; err != nil {
		return err
	}
	var running []db.Scan
	if err := s.DB.Select("id, repository_id").
		Where("repository_id = ? AND status = ?", repoID, db.ScanRunning).
		Find(&running).Error; err != nil {
		return err
	}
	for i := range running {
		s.cancelScan(&running[i], worker.OptOutCancelReason)
	}
	return nil
}

// lockRepoFederation takes one repository's federation section and returns its
// release. Two sections must not straddle each other: recording the opt-out plus
// the sweep that stops the work already under way, and the scheduler's read of
// the flag followed by the upstream push and remote HEAD lookup it gates. A live
// read alone only narrows that second window, since the opt-out can commit
// between the read and the network call it was meant to prevent. Held per
// repository rather than globally because the section spans git I/O, and a slow
// repository must not stall an unrelated maintainer's request; one mutex per
// repository is left in the map for the process's lifetime, which is bounded by
// the repository table.
func (s *Server) lockRepoFederation(repoID uint) func() {
	s.repoFederationMu.Lock()
	if s.repoFederationLocks == nil {
		s.repoFederationLocks = map[uint]*sync.Mutex{}
	}
	mu, ok := s.repoFederationLocks[repoID]
	if !ok {
		mu = &sync.Mutex{}
		s.repoFederationLocks[repoID] = mu
	}
	s.repoFederationMu.Unlock()
	mu.Lock()
	return mu.Unlock
}

// repoFederationOptedOut reads the live opt-out state for one repository. A
// path holding a repository snapshot from an earlier query re-reads through
// this before doing anything the opt-out forbids, so the window between the
// snapshot and the act is one statement rather than a whole scheduler tick.
func (s *Server) repoFederationOptedOut(repoID uint) (bool, error) {
	var repo db.Repository
	if err := s.DB.Select("id, federation_opt_out_at").First(&repo, repoID).Error; err != nil {
		return false, err
	}
	return repo.FederationOptedOut(), nil
}

// optedOutRepoIDs is the subquery of repositories whose maintainer asked not
// to be scanned, for the bulk resume path: it re-queues scans directly instead
// of going through enqueueSkillWith, so it has no per-repository gate of its
// own. Built fresh per use rather than shared, since a GORM statement carries
// state once it has been consumed.
func (s *Server) optedOutRepoIDs() *gorm.DB {
	return s.DB.Model(&db.Repository{}).Select("id").Where(db.FederationHasOptedOut)
}
