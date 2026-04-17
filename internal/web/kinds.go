package web

import (
	"scrutineer/internal/db"
	"scrutineer/internal/worker"
)

// Kind describes one job type for the /scanners catalogue page. The Prompt
// is rendered against a placeholder repository so the page shows exactly
// what would be sent to claude, schema and all.
type Kind struct {
	ID          string
	Name        string
	Description string
	Priority    int
	Prompt      string
	Schema      string
}

func (s *Server) kinds() []Kind {
	placeholder := db.Repository{URL: "https://github.com/OWNER/REPO"}
	claude := worker.LocalClaude{}
	return []Kind{
		{
			ID:          worker.JobMetadata,
			Name:        "Metadata",
			Description: "Looks the repository up on repos.ecosyste.ms and stores description, language, stars, license and the full payload on the repository row.",
			Priority:    worker.PrioMetadata,
		},
		{
			ID:          worker.JobPackages,
			Name:        "Packages",
			Description: "Fetches package registry entries from packages.ecosyste.ms for this repository URL. Shows which registries publish artefacts from this source.",
			Priority:    worker.PrioMetadata,
		},
		{
			ID:          worker.JobCommits,
			Name:        "Commits",
			Description: "Fetches commit stats (total committers, DDS score, bot ratio) from commits.ecosyste.ms.",
			Priority:    worker.PrioMetadata,
		},
		{
			ID:          worker.JobMaintainers,
			Name:        "Maintainers",
			Description: "Model-backed job: fetches commit, issue/PR and package maintainer data from ecosyste.ms, hands it to claude to identify the real maintainers, their roles, and the best disclosure channel.",
			Priority:    worker.PrioScan,
		},
		{
			ID:          worker.JobBrief,
			Name:        "Brief",
			Description: "Runs git-pkgs/brief on the clone to produce a structured project summary: languages, package managers, frameworks, tools, dependencies and layout.",
			Priority:    worker.PrioFastTool,
		},
		{
			ID:          worker.JobGitPkgs,
			Name:        "git-pkgs",
			Description: "Runs git-pkgs init + list against the clone to index all dependency manifests and produce a JSON inventory of packages at HEAD.",
			Priority:    worker.PrioFastTool,
		},
		{
			ID:          worker.JobSBOM,
			Name:        "SBOM",
			Description: "Generates a CycloneDX SBOM using git-pkgs sbom. Requires the git-pkgs index (built by the git-pkgs job or on first run).",
			Priority:    worker.PrioFastTool,
		},
		{
			ID:          worker.JobAdvisories,
			Name:        "Advisories",
			Description: "Fetches known security advisories for this repository from advisories.ecosyste.ms.",
			Priority:    worker.PrioMetadata,
		},
		{
			ID:          worker.JobDependents,
			Name:        "Dependents",
			Description: "Fetches the top runtime dependents for each of this repo's packages from packages.ecosyste.ms. Requires the packages job to have run first.",
			Priority:    worker.PrioFastTool,
		},
		{
			ID:          worker.JobSemgrep,
			Name:        "Semgrep",
			Description: "Runs semgrep with p/security-audit and p/secrets rulesets. Output is SARIF.",
			Priority:    worker.PrioTool,
		},
		{
			ID:          worker.JobZizmor,
			Name:        "Zizmor",
			Description: "Audits GitHub Actions workflows for security issues. Output is SARIF. Skipped if the repository has no .github/workflows.",
			Priority:    worker.PrioTool,
		},
		{
			ID:          worker.JobClaude,
			Name:        "Claude audit",
			Description: "Clones the repository and runs claude -p with the audit spec. Writes structured findings to report.json which are parsed into the findings table.",
			Priority:    worker.PrioScan,
			Prompt:      claude.Prompt(placeholder, s.Spec),
			Schema:      worker.DefsSchema + "\n\n" + worker.FindingsSchema,
		},
	}
}
