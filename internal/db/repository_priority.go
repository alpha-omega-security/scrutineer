package db

import (
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"gorm.io/gorm"
)

const priorityRefreshAge = 30 * 24 * time.Hour

type PrioritySignal struct {
	ID, Evidence string
	ScanID       uint
}

func (s PrioritySignal) Label() string {
	switch s.ID {
	case "archived":
		return "Archived"
	case "memory-unsafe":
		return "Memory-unsafe language"
	case "no-releases":
		return "No releases"
	case "old-release":
		return "Old release"
	case "single-maintainer":
		return "One maintainer"
	case "inactive-maintainers":
		return "Inactive maintainers"
	default:
		return s.ID
	}
}

type PriorityConsumer struct {
	ID       uint
	URL      string
	Direct   bool
	Evidence []string
}

type PriorityInventory struct {
	ID         uint
	FinishedAt *time.Time
}

type RepositoryPriority struct {
	ID              uint
	URL, Languages  string
	Inventory       *PriorityInventory
	Consumers       []PriorityConsumer
	DirectConsumers int
	Signals         []PrioritySignal
	Refresh         []string
	Gaps            []string
	PushedAt        *time.Time
	usedPackages    map[priorityIdentity]bool
}

type priorityRegistryPackage struct {
	Name      string `json:"name"`
	Ecosystem string `json:"ecosystem"`
	PURL      string `json:"purl"`
	Versions  *int   `json:"versions_count"`
	Latest    string `json:"latest_release_published_at"`
}

type RepositoryPriorities struct {
	Rows                                               []*RepositoryPriority
	InventoryCount, Packages, Unresolved, UnknownScope int
}

type priorityIdentity struct{ ecosystem, namespace, name string }

func priorityKey(purl, ecosystem, name string) priorityIdentity {
	eco, ns, pkg := ecosystemKey(purl, ecosystem, name)
	return priorityIdentity{eco, ns, pkg}
}

type priorityOccurrence struct {
	Name      string `json:"name"`
	Ecosystem string `json:"ecosystem"`
	PURL      string `json:"purl"`
	Path      string `json:"manifest_path"`
}

type priorityInventoryReport struct {
	Error    json.RawMessage `json:"error"`
	Analyses struct {
		Inventory struct {
			Status string               `json:"status"`
			Result []priorityOccurrence `json:"result"`
		} `json:"inventory"`
	} `json:"analyses"`
}

type prioritySource struct {
	ConsumerID, ScanID, SourceRepositoryID uint
	Name, Ecosystem, PURL, Scope           string
}

// LoadRepositoryPriorities counts distinct consumers in the local inventory cohort.
// Reports retain manifest provenance even when a later scan replaces Dependency rows.
func LoadRepositoryPriorities(g *gorm.DB, now time.Time) (*RepositoryPriorities, error) {
	repos, err := loadPriorityRepositories(g)
	if err != nil {
		return nil, err
	}
	inventories, err := loadPriorityInventories(g, repos, now)
	if err != nil {
		return nil, err
	}
	if err := loadPriorityMaintainers(g, repos); err != nil {
		return nil, err
	}
	var sources []prioritySource
	err = g.Table("sbom_packages p").
		Select("u.repository_id AS consumer_id, u.scan_id, p.source_repository_id, p.name, p.ecosystem, p.p_url, p.scope").
		Joins("JOIN sbom_uploads u ON u.id = p.sbom_upload_id").
		Where("u.origin = ? AND u.current = ?", SBOMOriginGenerated, true).
		Where("p.source_repository_id IS NOT NULL OR p.scope <> ''").Scan(&sources).Error
	if err != nil {
		return nil, err
	}
	view := &RepositoryPriorities{}
	countPriorityConsumers(view, repos, inventories, sources)
	if err := loadPriorityReleases(g, repos, now); err != nil {
		return nil, err
	}
	for _, repo := range repos {
		view.Rows = append(view.Rows, repo)
		if repo.Inventory != nil {
			view.InventoryCount++
		}
	}
	slices.SortFunc(view.Rows, func(a, b *RepositoryPriority) int { return strings.Compare(a.URL, b.URL) })
	return view, nil
}

func loadPriorityRepositories(g *gorm.DB) (map[uint]*RepositoryPriority, error) {
	rows, err := g.Model(&Repository{}).Select("id, url, languages, archived, pushed_at, ecosystems_repo_data").Rows()
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	repos := map[uint]*RepositoryPriority{}
	for rows.Next() {
		var source Repository
		if err := g.ScanRows(rows, &source); err != nil {
			return nil, err
		}
		repo := &RepositoryPriority{ID: source.ID, URL: source.URL, Languages: source.Languages, PushedAt: source.PushedAt}
		priorityMetadata(repo, source)
		repo.usedPackages = map[priorityIdentity]bool{}
		repos[repo.ID] = repo
	}
	return repos, rows.Err()
}

func priorityMetadata(repo *RepositoryPriority, source Repository) {
	var cached struct {
		Language string     `json:"language"`
		Archived *bool      `json:"archived"`
		PushedAt *time.Time `json:"pushed_at"`
	}
	if json.Unmarshal([]byte(source.EcosystemsRepoData), &cached) == nil {
		if repo.Languages == "" {
			repo.Languages = cached.Language
		}
		if cached.Archived != nil {
			source.Archived = *cached.Archived
		}
		if cached.PushedAt != nil {
			repo.PushedAt = cached.PushedAt
		}
	}
	if source.Archived {
		repo.Signals = append(repo.Signals, PrioritySignal{ID: "archived", Evidence: "Repository is archived"})
	}
	if repo.Languages == "" {
		repo.Gaps = append(repo.Gaps, "Language unknown")
	}
	for language := range strings.SplitSeq(repo.Languages, ",") {
		switch strings.ToLower(strings.TrimSpace(language)) {
		case "c", "c++", "objective-c", "assembly":
			repo.Signals = append(repo.Signals, PrioritySignal{ID: "memory-unsafe", Evidence: "Contains " + strings.TrimSpace(language) + "; check whether this is shipped code or fixtures"})
		}
	}
}

func priorityReleases(repo *RepositoryPriority, raw string, now time.Time) {
	var packages []priorityRegistryPackage
	if err := json.Unmarshal([]byte(raw), &packages); err != nil {
		packages = nil
	}
	matched := map[priorityIdentity]bool{}
	for _, pkg := range packages {
		key := priorityKey(pkg.PURL, pkg.Ecosystem, pkg.Name)
		if !repo.usedPackages[key] || matched[key] {
			continue
		}
		matched[key] = true
		if pkg.Versions != nil && *pkg.Versions == 0 {
			repo.Signals = append(repo.Signals, PrioritySignal{ID: "no-releases", Evidence: pkg.Name + ": registry reports no releases"})
		}
		if date, err := time.Parse(time.RFC3339, pkg.Latest); err == nil && now.Sub(date) >= healthStaleReleaseWindow {
			repo.Signals = append(repo.Signals, PrioritySignal{ID: "old-release", Evidence: pkg.Name + ": last release " + date.Format("2006-01-02") + " (at least 18 months ago; may be stable)"})
		}
	}
	if len(matched) < len(repo.usedPackages) {
		repo.Gaps = append(repo.Gaps, "Release metadata missing for some dependencies in this selection")
	}
}

const priorityInventoryColumns = "scans.id, scans.repository_id, scans.finished_at, scans.report"

func priorityDependencyScans(g *gorm.DB) *gorm.DB {
	return g.Model(&Scan{}).Joins("JOIN skills ON skills.id = scans.skill_id").
		Where("skills.output_kind = ? AND COALESCE(scans.sub_path, '') = '' AND COALESCE(scans.ref, '') = ''", "dependencies")
}

func priorityEligibleScans(g *gorm.DB) *gorm.DB {
	return priorityDependencyScans(g).Where("scans.status = ?", ScanDone).
		Where("scans.cost_capped = ? OR scans.cost_capped IS NULL", false).
		Where("scans.max_turns_hit = ? OR scans.max_turns_hit IS NULL", false)
}

func loadPriorityInventories(g *gorm.DB, repos map[uint]*RepositoryPriority, now time.Time) (map[uint][]priorityOccurrence, error) {
	var attempts []struct{ RepositoryID, ID uint }
	if err := priorityDependencyScans(g).Select("scans.repository_id, MAX(scans.id) AS id").Group("scans.repository_id").Scan(&attempts).Error; err != nil {
		return nil, err
	}
	candidates := priorityEligibleScans(g).Select("MAX(scans.id)").Group("scans.repository_id")
	var scans []Scan
	if err := g.Select(priorityInventoryColumns).Where("id IN (?)", candidates).Find(&scans).Error; err != nil {
		return nil, err
	}
	inventories := map[uint][]priorityOccurrence{}
	for _, scan := range scans {
		repo := repos[scan.RepositoryID]
		if repo == nil {
			continue
		}
		inventory, occurrences, err := priorityUsableInventory(g, scan)
		if err != nil {
			return nil, err
		}
		if inventory != nil {
			repo.Inventory = inventory
			inventories[repo.ID] = occurrences
		}
	}
	for _, attempt := range attempts {
		if repo := repos[attempt.RepositoryID]; repo != nil {
			priorityFreshness(repo, attempt.ID, now)
		}
	}
	return inventories, nil
}

func priorityUsableInventory(g *gorm.DB, scan Scan) (*PriorityInventory, []priorityOccurrence, error) {
	for {
		var report priorityInventoryReport
		if json.Unmarshal([]byte(scan.Report), &report) == nil && priorityReportOK(report) {
			return &PriorityInventory{scan.ID, scan.FinishedAt}, report.Analyses.Inventory.Result, nil
		}
		var older Scan
		err := priorityEligibleScans(g).Select(priorityInventoryColumns).
			Where("scans.repository_id = ? AND scans.id < ?", scan.RepositoryID, scan.ID).
			Order("scans.id DESC").Take(&older).Error
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, nil, nil
		}
		if err != nil {
			return nil, nil, err
		}
		scan = older
	}
}

func loadPriorityReleases(g *gorm.DB, repos map[uint]*RepositoryPriority, now time.Time) error {
	var ids []uint
	for id, repo := range repos {
		if len(repo.usedPackages) > 0 {
			ids = append(ids, id)
		}
	}
	const batchSize = 200
	for batch := range slices.Chunk(ids, batchSize) {
		var sources []struct {
			ID                     uint
			EcosystemsPackagesData string
		}
		if err := g.Model(&Repository{}).Select("id, ecosystems_packages_data").Where("id IN ?", batch).Scan(&sources).Error; err != nil {
			return err
		}
		for _, source := range sources {
			priorityReleases(repos[source.ID], source.EcosystemsPackagesData, now)
		}
	}
	return nil
}

func priorityReportOK(report priorityInventoryReport) bool {
	hasError := len(report.Error) > 0 && string(report.Error) != "null" && string(report.Error) != `""`
	return !hasError && report.Analyses.Inventory.Status == "ok" && report.Analyses.Inventory.Result != nil
}

func priorityFreshness(repo *RepositoryPriority, latest uint, now time.Time) {
	if repo.Inventory == nil {
		if latest != 0 {
			repo.Gaps = append(repo.Gaps, "No usable completed inventory")
		}
		return
	}
	if latest != repo.Inventory.ID {
		repo.Refresh = append(repo.Refresh, "Newer inventory attempt is incomplete or unusable")
	}
	if repo.Inventory.FinishedAt == nil {
		repo.Gaps = append(repo.Gaps, "Inventory date unknown")
		return
	}
	if now.Sub(*repo.Inventory.FinishedAt) >= priorityRefreshAge {
		repo.Refresh = append(repo.Refresh, "Inventory is at least 30 days old")
	}
	if repo.PushedAt != nil && repo.PushedAt.After(*repo.Inventory.FinishedAt) {
		repo.Refresh = append(repo.Refresh, "Repository pushed after inventory")
	}
}

type priorityScopeKey struct {
	consumer uint
	pkg      priorityIdentity
}

func prioritySourceMaps(repos map[uint]*RepositoryPriority, sources []prioritySource) (map[priorityIdentity]map[uint]bool, map[priorityScopeKey]string) {
	owners := map[priorityIdentity]map[uint]bool{}
	scopes := map[priorityScopeKey]string{}
	for _, source := range sources {
		key := priorityKey(source.PURL, source.Ecosystem, source.Name)
		if source.SourceRepositoryID != 0 && repos[source.SourceRepositoryID] != nil {
			if owners[key] == nil {
				owners[key] = map[uint]bool{}
			}
			owners[key][source.SourceRepositoryID] = true
		}
		consumer := repos[source.ConsumerID]
		if consumer == nil || consumer.Inventory == nil || consumer.Inventory.ID != source.ScanID {
			continue
		}
		sk := priorityScopeKey{source.ConsumerID, key}
		// A direct edge in any component version proves direct use by this consumer.
		if scopes[sk] != "direct" {
			scopes[sk] = source.Scope
		}
	}
	return owners, scopes
}

func countPriorityConsumers(view *RepositoryPriorities, repos map[uint]*RepositoryPriority, inventories map[uint][]priorityOccurrence, sources []prioritySource) {
	owners, scopes := prioritySourceMaps(repos, sources)
	packages, unresolved := map[priorityIdentity]bool{}, map[priorityIdentity]bool{}
	edges := map[uint]map[uint]*PriorityConsumer{}
	unknown := map[priorityScopeKey]bool{}
	for id, occurrences := range inventories {
		for _, occurrence := range occurrences {
			if !priorityOccurrenceVisible(occurrence) {
				continue
			}
			key := priorityKey(occurrence.PURL, occurrence.Ecosystem, occurrence.Name)
			packages[key] = true
			sk := priorityScopeKey{id, key}
			if scopes[sk] == "" {
				unknown[sk] = true
			}
			if len(owners[key]) != 1 {
				unresolved[key] = true
				continue
			}
			for owner := range owners[key] {
				if owner != id {
					repos[owner].usedPackages[key] = true
					addPriorityEdge(edges, owner, repos[id], occurrence, scopes[sk])
				}
			}
		}
	}
	for owner, consumers := range edges {
		for _, consumer := range consumers {
			slices.Sort(consumer.Evidence)
			repos[owner].Consumers = append(repos[owner].Consumers, *consumer)
			if consumer.Direct {
				repos[owner].DirectConsumers++
			}
		}
		slices.SortFunc(repos[owner].Consumers, func(a, b PriorityConsumer) int { return strings.Compare(a.URL, b.URL) })
	}
	view.Packages, view.Unresolved, view.UnknownScope = len(packages), len(unresolved), len(unknown)
}

func priorityOccurrenceVisible(occurrence priorityOccurrence) bool {
	for segment := range strings.SplitSeq(strings.ReplaceAll(strings.ToLower(occurrence.Path), `\`, "/"), "/") {
		switch segment {
		case "testdata", "fixtures", "examples", "samples":
			return false
		}
	}
	return true
}

func addPriorityEdge(edges map[uint]map[uint]*PriorityConsumer, owner uint, repo *RepositoryPriority, occurrence priorityOccurrence, scope string) {
	if edges[owner] == nil {
		edges[owner] = map[uint]*PriorityConsumer{}
	}
	consumer := edges[owner][repo.ID]
	if consumer == nil {
		consumer = &PriorityConsumer{ID: repo.ID, URL: repo.URL}
		edges[owner][repo.ID] = consumer
	}
	consumer.Direct = consumer.Direct || scope == "direct"
	evidence := fmt.Sprintf("%s (%s) · %s", occurrence.Name, occurrence.Ecosystem, occurrence.Path)
	if !slices.Contains(consumer.Evidence, evidence) {
		consumer.Evidence = append(consumer.Evidence, evidence)
	}
}

func loadPriorityMaintainers(g *gorm.DB, repos map[uint]*RepositoryPriority) error {
	var scans []Scan
	latest := g.Table("scans").Select("MAX(scans.id)").Joins("JOIN skills ON skills.id = scans.skill_id").
		Where("skills.output_kind = ? AND COALESCE(scans.sub_path, '') = '' AND COALESCE(scans.ref, '') = ''", "maintainers").Group("scans.repository_id")
	if err := g.Select("id, repository_id, status, report, cost_capped, max_turns_hit").Where("id IN (?)", latest).Find(&scans).Error; err != nil {
		return err
	}
	seen := map[uint]bool{}
	for _, scan := range scans {
		if repo := repos[scan.RepositoryID]; repo != nil {
			seen[repo.ID] = true
			priorityMaintainers(repo, scan)
		}
	}
	for _, repo := range repos {
		if !seen[repo.ID] {
			repo.Gaps = append(repo.Gaps, "Maintainers not assessed")
		}
	}
	return nil
}

func priorityMaintainers(repo *RepositoryPriority, scan Scan) {
	var report struct {
		Error       json.RawMessage `json:"error"`
		Maintainers []struct {
			Login  string `json:"login"`
			Role   string `json:"role"`
			Status string `json:"status"`
		} `json:"maintainers"`
	}
	if scan.Status != ScanDone || scan.CostCapped || scan.MaxTurnsHit || json.Unmarshal([]byte(scan.Report), &report) != nil || report.Maintainers == nil || (len(report.Error) > 0 && string(report.Error) != "null") {
		repo.Gaps = append(repo.Gaps, "Latest maintainer assessment incomplete or unusable")
		return
	}
	active, inactive := map[string]bool{}, map[string]bool{}
	for _, person := range report.Maintainers {
		if person.Role != "lead" && person.Role != "maintainer" {
			continue
		}
		login := strings.ToLower(strings.TrimSpace(person.Login))
		if login == "" {
			continue
		}
		switch person.Status {
		case "active":
			active[login] = true
		case "inactive":
			inactive[login] = true
		}
	}
	switch {
	case len(active) == 1:
		repo.Signals = append(repo.Signals, PrioritySignal{ID: "single-maintainer", Evidence: "One active maintainer identified in assessment", ScanID: scan.ID})
	case len(active) == 0 && len(inactive) > 0:
		repo.Signals = append(repo.Signals, PrioritySignal{ID: "inactive-maintainers", Evidence: "Assessment identifies inactive maintainers and no active maintainer", ScanID: scan.ID})
	case len(active) == 0:
		repo.Gaps = append(repo.Gaps, "Maintainer activity unknown")
	}
}
