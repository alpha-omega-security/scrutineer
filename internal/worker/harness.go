package worker

import "github.com/alpha-omega-security/harness"

// The Harness interface, backend implementations, and registry live in
// github.com/alpha-omega-security/harness. These aliases keep the -backend
// flag validation, the container runner, and the web layer's model-list
// wiring unchanged. Adding a fourth backend (copilot) came for free.

type (
	Harness      = harness.Harness
	ModelDefault = harness.ModelDefault

	ClaudeHarness   = harness.ClaudeHarness
	CodexHarness    = harness.CodexHarness
	CopilotHarness  = harness.CopilotHarness
	OpencodeHarness = harness.OpencodeHarness
)

//nolint:ireturn // registry; the concrete type is the registrant's choice
func HarnessByName(name string) (Harness, error) { return harness.ByName(name) }
func HarnessName(h Harness) string               { return harness.Name(h) }
func HarnessNames() string                       { return harness.Names() }

// CodexModelCatalogRelease is the Codex release whose visible model catalog
// DefaultModelsFor mirrors. The runner version-pin check requires this to
// match both CODEX_*_LOCK tags, turning a future CLI catalog change into a
// reviewable CI failure instead of silently seeding removed model ids.
const CodexModelCatalogRelease = "rust-v0.154.0"

// DefaultModelsFor returns the model list Scrutineer exposes for a harness.
// Harness v0.1.14 predates Codex's 5.6/Astra catalog and still defaults to the
// removed gpt-5.3-codex id, so keep the compatibility catalog here until the
// module publishes matching defaults.
func DefaultModelsFor(h Harness) []ModelDefault {
	if HarnessName(h) == "codex" {
		return []ModelDefault{
			{Name: "GPT-5.6 Sol", ID: modelGPT56SolID, Tier: "high"},
			{Name: "GPT-5.6 Terra", ID: "gpt-5.6-terra"},
			{Name: "GPT-5.6 Luna", ID: "gpt-5.6-luna", Tier: "mid"},
			{Name: "GPT-6 Astra", ID: modelGPT6AstraID, Tier: "max"},
			{Name: "GPT-5.5", ID: "gpt-5.5"},
			{Name: "GPT-5.2", ID: "gpt-5.2"},
		}
	}
	return h.DefaultModels()
}

// copilotTopEffort is the strongest level `copilot --effort` accepts.
const copilotTopEffort = "xhigh"

// CappedEffort lowers an effort level the backend's CLI would reject. harness
// forwards Job.Effort straight to `copilot --effort`, whose choices stop at
// xhigh, so scrutineer's "max" fails the scan on flag parsing.
func CappedEffort(h Harness, effort string) string {
	if effort == "max" && HarnessName(h) == "copilot" {
		return copilotTopEffort
	}
	return effort
}
