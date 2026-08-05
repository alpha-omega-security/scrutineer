package web

import (
	"sort"
	"time"

	"gorm.io/gorm"

	"scrutineer/internal/db"
)

const migrationGuideRowLimit = 10

const (
	dependentCountHistoryLimit = 24
	dependentCountPlotWidth    = 600
	dependentCountPlotHeight   = 120
	dependentCountPlotPadding  = 12
	dependentCountPlotSides    = 2
)

type findingMigrationGuide struct {
	Health db.RepositoryHealth

	Packages         []db.Package
	Alternatives     []db.PackageAlternative
	CampaignStatuses []db.DependentCampaignStatus
	DependentTrend   *dependentCountTrend

	PriorityDependents []migrationDependentRow
	KnownSafeCount     int
	FixedCount         int
	TotalExposureRows  int
}

type dependentCountTrend struct {
	Points     []dependentCountPlotPoint
	Segments   []dependentCountPlotSegment
	Latest     int
	Change     int
	Maximum    int
	FirstAt    time.Time
	LatestAt   time.Time
	SampleSize int
}

type dependentCountPlotPoint struct {
	X              int
	Y              int
	DependentRepos int
	ObservedAt     time.Time
}

type dependentCountPlotSegment struct {
	X1 int
	Y1 int
	X2 int
	Y2 int
}

type migrationDependentRow struct {
	DependentID       uint
	Name              string
	Ecosystem         string
	RepositoryURL     string
	DependentRepos    int
	Status            string
	Rationale         string
	UpdatedAt         time.Time
	CampaignStatus    db.DependentCampaignStatus
	CampaignNote      string
	CampaignUpdatedAt *time.Time
}

func loadFindingMigrationGuide(
	gdb *gorm.DB,
	repo db.Repository,
	exposureRows []db.FindingDependent,
	dependentsByID map[uint]db.Dependent,
) (*findingMigrationGuide, error) {
	alternatives, err := loadPackageAlternatives(gdb, repo.ID)
	if err != nil {
		return nil, err
	}
	if !showPackageAlternatives(repo, alternatives) {
		return nil, nil
	}

	var packages []db.Package
	if err := gdb.Where("repository_id = ?", repo.ID).
		Order("dependent_repos desc, downloads desc, id asc").
		Limit(migrationGuideRowLimit).
		Find(&packages).Error; err != nil {
		return nil, err
	}
	trend, err := loadDependentCountTrend(gdb, repo.ID)
	if err != nil {
		return nil, err
	}

	guide := findingMigrationGuide{
		Health:           repo.Health,
		Packages:         packages,
		Alternatives:     alternatives,
		CampaignStatuses: db.DependentCampaignStatuses,
		DependentTrend:   trend,
	}
	loadMigrationGuideDependents(exposureRows, dependentsByID, &guide)
	return &guide, nil
}

func loadDependentCountTrend(gdb *gorm.DB, repoID uint) (*dependentCountTrend, error) {
	var snapshots []db.DependentCountSnapshot
	if err := gdb.Where("repository_id = ?", repoID).
		Order("observed_at desc, id desc").
		Limit(dependentCountHistoryLimit).
		Find(&snapshots).Error; err != nil {
		return nil, err
	}
	if len(snapshots) == 0 {
		return nil, nil
	}
	for left, right := 0, len(snapshots)-1; left < right; left, right = left+1, right-1 {
		snapshots[left], snapshots[right] = snapshots[right], snapshots[left]
	}
	return buildDependentCountTrend(snapshots), nil
}

func buildDependentCountTrend(snapshots []db.DependentCountSnapshot) *dependentCountTrend {
	if len(snapshots) == 0 {
		return nil
	}
	trend := &dependentCountTrend{
		Maximum:    snapshots[0].DependentRepos,
		FirstAt:    snapshots[0].ObservedAt,
		LatestAt:   snapshots[len(snapshots)-1].ObservedAt,
		Latest:     snapshots[len(snapshots)-1].DependentRepos,
		Change:     snapshots[len(snapshots)-1].DependentRepos - snapshots[0].DependentRepos,
		SampleSize: len(snapshots),
		Points:     make([]dependentCountPlotPoint, 0, len(snapshots)),
	}
	for _, snapshot := range snapshots {
		trend.Maximum = max(trend.Maximum, snapshot.DependentRepos)
	}
	scaleMax := max(trend.Maximum, 1)
	plotWidth := dependentCountPlotWidth - dependentCountPlotSides*dependentCountPlotPadding
	plotHeight := dependentCountPlotHeight - dependentCountPlotSides*dependentCountPlotPadding
	for i, snapshot := range snapshots {
		x := dependentCountPlotWidth / dependentCountPlotSides
		if len(snapshots) > 1 {
			x = dependentCountPlotPadding + i*plotWidth/(len(snapshots)-1)
		}
		y := dependentCountPlotHeight - dependentCountPlotPadding - snapshot.DependentRepos*plotHeight/scaleMax
		trend.Points = append(trend.Points, dependentCountPlotPoint{
			X:              x,
			Y:              y,
			DependentRepos: snapshot.DependentRepos,
			ObservedAt:     snapshot.ObservedAt,
		})
	}
	trend.Segments = make([]dependentCountPlotSegment, 0, len(trend.Points)-1)
	for i := 1; i < len(trend.Points); i++ {
		previous, current := trend.Points[i-1], trend.Points[i]
		trend.Segments = append(trend.Segments, dependentCountPlotSegment{
			X1: previous.X, Y1: previous.Y, X2: current.X, Y2: current.Y,
		})
	}
	return trend
}

func loadMigrationGuideDependents(
	exposureRows []db.FindingDependent,
	dependentsByID map[uint]db.Dependent,
	guide *findingMigrationGuide,
) {
	guide.TotalExposureRows = len(exposureRows)
	if len(exposureRows) == 0 {
		return
	}

	actionableRows := make([]migrationDependentRow, 0, len(exposureRows))
	trackedResolvedRows := make([]migrationDependentRow, 0)
	for _, row := range exposureRows {
		row.Status = migrationExposureStatus(row.Status)
		actionable := true
		if row.Status == db.ExposureKnownNotAffected {
			guide.KnownSafeCount++
			actionable = false
		}
		if row.Status == db.ExposureFixed {
			guide.FixedCount++
			actionable = false
		}
		if !actionable && row.CampaignStatus == "" {
			continue
		}
		dep, ok := dependentsByID[row.DependentID]
		if !ok {
			continue
		}
		viewRow := migrationDependentRow{
			DependentID:       dep.ID,
			Name:              dep.Name,
			Ecosystem:         dep.Ecosystem,
			RepositoryURL:     dep.RepositoryURL,
			DependentRepos:    dep.DependentRepos,
			Status:            row.Status,
			Rationale:         row.Rationale,
			UpdatedAt:         row.UpdatedAt,
			CampaignStatus:    row.CampaignStatus,
			CampaignNote:      row.CampaignNote,
			CampaignUpdatedAt: row.CampaignUpdatedAt,
		}
		if actionable {
			actionableRows = append(actionableRows, viewRow)
		} else {
			trackedResolvedRows = append(trackedResolvedRows, viewRow)
		}
	}
	sortMigrationDependentRows(actionableRows)
	sortMigrationDependentRows(trackedResolvedRows)
	if len(actionableRows) > migrationGuideRowLimit {
		actionableRows = actionableRows[:migrationGuideRowLimit]
	}
	guide.PriorityDependents = make([]migrationDependentRow, 0, len(actionableRows)+len(trackedResolvedRows))
	guide.PriorityDependents = append(guide.PriorityDependents, actionableRows...)
	guide.PriorityDependents = append(guide.PriorityDependents, trackedResolvedRows...)
}

func sortMigrationDependentRows(rows []migrationDependentRow) {
	sort.Slice(rows, func(i, j int) bool {
		if rows[i].DependentRepos != rows[j].DependentRepos {
			return rows[i].DependentRepos > rows[j].DependentRepos
		}
		return rows[i].Name < rows[j].Name
	})
}

func migrationExposureStatus(status string) string {
	if status == "" {
		return db.ExposureUnderInvestigation
	}
	return status
}
