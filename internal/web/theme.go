package web

import (
	"context"
	"fmt"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"time"

	"scrutineer/internal/config"
	"scrutineer/internal/db"
	"scrutineer/internal/worker"
)

// Bounds for the operator-tunable knobs on the Settings page. They guard
// against nonsense values (a 0 or 5000-wide concurrency, a 1-turn cap that
// fails every scan) rather than enforcing a hard system limit.
const (
	minConcurrency = 1
	maxConcurrency = 64
	minMaxTurns    = 1
	maxMaxTurns    = 500
)

const cookieMaxAge = 365 * 24 * 60 * 60 //nolint:mnd

var defaultTheme = "claude"

func SetTheme(name string) {
	if name == "" {
		return
	}
	defaultTheme = name
}

func resolveTheme(r *http.Request) string {
	if c, err := r.Cookie("theme"); err == nil && c.Value != "" {
		if config.ValidateTheme(c.Value) == nil {
			return c.Value
		}
	}
	return defaultTheme
}

var colorSchemes = []string{"system", "light", "dark"}

func resolveColorScheme(r *http.Request) string {
	if c, err := r.Cookie("color_scheme"); err == nil && c.Value != "" {
		for _, s := range colorSchemes {
			if c.Value == s {
				return s
			}
		}
	}
	return "system"
}

func (s *Server) settingsShow(w http.ResponseWriter, r *http.Request) {
	var stats struct {
		Repos           int64
		Scans           int64
		Findings        int64
		ScannerFindings int64
		Packages        int64
		Advisories      int64
		Maintainers     int64
		Skills          int64
	}
	s.DB.Table("repositories").Count(&stats.Repos)
	s.DB.Table("scans").Count(&stats.Scans)
	// Split findings the same way the repo page does: deep-dive (curated
	// audit) findings versus tool-scanner output (zizmor, semgrep, …).
	dd := findingsScanIDs(s.DB)
	s.DB.Model(&db.Finding{}).Where("scan_id IN (?)", dd).Count(&stats.Findings)
	s.DB.Model(&db.Finding{}).Where("scan_id NOT IN (?)", dd).Count(&stats.ScannerFindings)
	s.DB.Table("packages").Count(&stats.Packages)
	s.DB.Table("advisories").Count(&stats.Advisories)
	s.DB.Table("maintainers").Count(&stats.Maintainers)
	s.DB.Table("skills").Count(&stats.Skills)

	var dbSizeBytes int64
	s.DB.Raw("SELECT page_count * page_size FROM pragma_page_count(), pragma_page_size()").Scan(&dbSizeBytes)

	var dbPath string
	s.DB.Raw("SELECT file FROM pragma_database_list WHERE name = 'main'").Scan(&dbPath)

	meta := s.toolMetadataCached(r.Context())
	// Overlay the boot-time staleness verdict onto the (separately cached)
	// version metadata. This is the verdict from the startup check; it is not
	// re-probed per request, so it reflects the runner image as of boot.
	if st := s.runnerImageStatus(); st.Stale {
		meta.Stale = true
		meta.StaleDays = st.AgeDays
		meta.PullCommand = st.PullCommand
	}

	// ConcurrencyInput pre-fills the form with the persisted value when set,
	// else the value the runner is actually using now. MaxTurns is 0 when
	// unconfigured; the template then shows an empty field whose placeholder
	// names the built-in fallback rather than asserting an active number.
	concurrencyInput := s.Queue.Concurrency()
	if v := db.SettingInt(s.DB, db.SettingConcurrency); v > 0 {
		concurrencyInput = v
	}

	s.render(w, r, "settings.html", map[string]any{
		"Themes":           config.Themes,
		"Models":           Models,
		"ModelTiers":       ModelTiers,
		"TierModels":       ModelTierValues(s.DB, s.DefaultModel()),
		"Efforts":          Efforts,
		"DefaultEffort":    s.DefaultEffort(),
		"ColorScheme":      resolveColorScheme(r),
		"Concurrency":      s.Queue.Concurrency(),
		"ConcurrencyInput": concurrencyInput,
		"MaxTurns":         db.SettingInt(s.DB, db.SettingDefaultMaxTurns),
		"DefaultMaxTurns":  worker.DefaultSkillMaxTurns,
		"Stats":            stats,
		"DBSize":           dbSizeBytes,
		"DBPath":           dbPath,
		"WorkDir":          s.Worker.DataDir,
		"Commit":           s.Commit,
		"Meta":             meta,
	})
}

// toolMetadata is the runtime version info shown on the settings page:
// the scanner tools baked into the runner image plus the host container
// runtime version and the runner image name itself.
type toolMetadata struct {
	worker.RunnerToolVersions
	// Backend is the active -backend name (e.g. "claude", "codex"), used
	// as the label for the Harness version row.
	Backend     string
	Runtime     string
	RunnerImage string
	// Revision is the git commit the runner image was built from (its
	// org.opencontainers.image.revision label), folded into the displayed image
	// reference so the settings page names an actual build. "" when the image
	// carries no such label.
	Revision string
	// Staleness of the runner image, from the boot-time check (issue #337).
	// Overlaid onto the cached metadata per request; the verdict itself is the
	// one computed at startup and is not refreshed for the process lifetime.
	Stale       bool
	StaleDays   int
	PullCommand string
}

// shortSHALen is how many leading hex chars of a commit to show -- enough to be
// unambiguous in practice without spilling the truncated metadata row.
const shortSHALen = 12

// RunnerImageRef is the runner image annotated with the git commit it was built
// from, e.g. "ghcr.io/.../scrutineer-runner @ abc123def456", for the settings
// "Runner image" row. The rolling ":latest" tag says nothing about which build
// is running, so it's dropped in favour of the commit. Falls back to the bare
// image reference when the revision label is absent.
func (m toolMetadata) RunnerImageRef() string {
	if m.Revision == "" {
		return m.RunnerImage
	}
	rev := m.Revision
	if len(rev) > shortSHALen {
		rev = rev[:shortSHALen]
	}
	return strings.TrimSuffix(m.RunnerImage, ":latest") + " @ " + rev
}

// toolMetadataTTL bounds how long a gathered version set is reused. Versions
// only change when the operator pulls a new image or restarts the runtime, so
// a generous TTL keeps the settings page DB-fast without going stale for long.
const toolMetadataTTL = 5 * time.Minute

// toolMetadataTimeout caps EACH runtime shell-out (not a shared budget across
// them) so a hung or missing daemon degrades to "unavailable" instead of
// stalling the settings page. It is generous enough for Apple's container
// runtime, whose first `container run` cold-starts a VM and can take several
// seconds: a shorter shared budget let that slow tool-version probe expire the
// deadline before the fast `container --version` runtime probe even ran, so the
// whole panel read "unavailable".
const toolMetadataTimeout = 15 * time.Second

func (s *Server) toolMetadataCached(ctx context.Context) toolMetadata {
	s.toolMetaMu.Lock()
	defer s.toolMetaMu.Unlock()
	if time.Now().Before(s.toolMetaTTL) {
		return s.toolMetaCache
	}
	rt := worker.RuntimeOf(s.Worker.Runner)
	image := worker.RunnerImageName(s.Worker.Runner)
	// Each probe gets its own deadline so the slow tool-version `container run`
	// cannot starve the fast runtime-version `container --version`.
	toolsCtx, toolsCancel := context.WithTimeout(ctx, toolMetadataTimeout)
	defer toolsCancel()
	h, _ := worker.HarnessByName(s.Backend)
	tools := worker.QueryRunnerToolVersions(toolsCtx, rt, image, h.Binary())

	rtCtx, rtCancel := context.WithTimeout(ctx, toolMetadataTimeout)
	defer rtCancel()
	runtimeVer := worker.RuntimeServerVersion(rtCtx, rt)

	meta := toolMetadata{
		RunnerToolVersions: tools,
		Backend:            s.Backend,
		Runtime:            runtimeVer,
		RunnerImage:        image,
		Revision:           worker.RunnerImageRevision(ctx, rt, image),
	}
	s.toolMetaCache = meta
	s.toolMetaTTL = time.Now().Add(toolMetadataTTL)
	return meta
}

func (s *Server) settingsUpdateTheme(w http.ResponseWriter, r *http.Request) {
	theme := r.FormValue("theme")
	if config.ValidateTheme(theme) != nil {
		http.Error(w, "unknown theme", http.StatusUnprocessableEntity)
		return
	}
	http.SetCookie(w, &http.Cookie{
		Name:     "theme",
		Value:    theme,
		Path:     "/",
		MaxAge:   cookieMaxAge,
		HttpOnly: true,
		SameSite: http.SameSiteStrictMode,
	})
	setFlash(w, Flash{Category: successKey, Title: "Theme updated"})
	s.redirect(w, r, "/settings")
}

func (s *Server) settingsUpdateModel(w http.ResponseWriter, r *http.Request) {
	model := r.FormValue("model")
	if !ValidModel(model) {
		http.Error(w, "unknown model", http.StatusUnprocessableEntity)
		return
	}
	tier := r.FormValue("tier")
	if tier != "" {
		if !ValidModelTier(tier) {
			http.Error(w, "unknown model tier", http.StatusUnprocessableEntity)
			return
		}
		if err := db.SetSetting(s.DB, modelTierSettingKey(tier), model); err != nil {
			http.Error(w, "could not save setting", http.StatusInternalServerError)
			return
		}
		setFlash(w, Flash{Category: successKey, Title: "Model tier updated"})
		s.redirect(w, r, "/settings")
		return
	}
	s.SetDefaultModel(model)
	setFlash(w, Flash{Category: successKey, Title: "Default model updated"})
	s.redirect(w, r, "/settings")
}

func (s *Server) settingsUpdateEffort(w http.ResponseWriter, r *http.Request) {
	effort := r.FormValue("effort")
	if !ValidEffort(effort) {
		http.Error(w, "unknown effort", http.StatusUnprocessableEntity)
		return
	}
	s.SetDefaultEffort(effort)
	setFlash(w, Flash{Category: successKey, Title: "Default effort updated"})
	s.redirect(w, r, "/settings")
}

func (s *Server) settingsUpdateColorScheme(w http.ResponseWriter, r *http.Request) {
	scheme := r.FormValue("color_scheme")
	if !slices.Contains(colorSchemes, scheme) {
		http.Error(w, "unknown color scheme", http.StatusUnprocessableEntity)
		return
	}
	http.SetCookie(w, &http.Cookie{
		Name:     "color_scheme",
		Value:    scheme,
		Path:     "/",
		MaxAge:   cookieMaxAge,
		SameSite: http.SameSiteStrictMode,
	})
	setFlash(w, Flash{Category: successKey, Title: "Color scheme updated"})
	s.redirect(w, r, "/settings")
}

func (s *Server) settingsUpdateConcurrency(w http.ResponseWriter, r *http.Request) {
	n, err := strconv.Atoi(r.FormValue("concurrency"))
	if err != nil || n < minConcurrency || n > maxConcurrency {
		http.Error(w, "concurrency must be between 1 and 64", http.StatusUnprocessableEntity)
		return
	}
	if err := db.SetSetting(s.DB, db.SettingConcurrency, strconv.Itoa(n)); err != nil {
		http.Error(w, "could not save setting", http.StatusInternalServerError)
		return
	}
	if n == s.Queue.Concurrency() {
		setFlash(w, Flash{Category: successKey, Title: "Concurrency saved"})
		s.redirect(w, r, "/settings")
		return
	}
	// The runner's limit is fixed at construction, so applying a new value
	// means standing up a fresh runner, which aborts whatever is mid-flight.
	// With nothing running there's nothing to lose, so apply immediately;
	// otherwise ask before cancelling.
	var running int64
	s.DB.Model(&db.Scan{}).Where("status = ?", db.ScanRunning).Count(&running)
	if running == 0 {
		s.Queue.Reconfigure(n)
		setFlash(w, Flash{Category: successKey, Title: "Concurrency applied", Description: fmt.Sprintf("Runner now runs %d scans in parallel.", n)})
		s.redirect(w, r, "/settings")
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if execErr := s.tmpl.ExecuteTemplate(w, "concurrency-confirm-oob", map[string]any{
		"Concurrency": n,
		"Running":     running,
	}); execErr != nil {
		s.Log.Error("render concurrency-confirm-oob", "err", execErr)
	}
}

// settingsRestartRunner rebuilds the runner at the saved concurrency, applying
// it live. In-flight scans are cancelled by the swap; queued scans survive.
func (s *Server) settingsRestartRunner(w http.ResponseWriter, r *http.Request) {
	n := db.SettingInt(s.DB, db.SettingConcurrency)
	if n <= 0 {
		n = s.Queue.Concurrency()
	}
	s.Queue.Reconfigure(n)
	setFlash(w, Flash{Category: successKey, Title: "Runner restarted", Description: fmt.Sprintf("Now running %d scans in parallel; in-flight scans were cancelled.", n)})
	s.redirect(w, r, "/settings")
}

func (s *Server) settingsUpdateMaxTurns(w http.ResponseWriter, r *http.Request) {
	n, err := strconv.Atoi(r.FormValue("max_turns"))
	if err != nil || n < minMaxTurns || n > maxMaxTurns {
		http.Error(w, "default turns must be between 1 and 500", http.StatusUnprocessableEntity)
		return
	}
	if err := db.SetSetting(s.DB, db.SettingDefaultMaxTurns, strconv.Itoa(n)); err != nil {
		http.Error(w, "could not save setting", http.StatusInternalServerError)
		return
	}
	setFlash(w, Flash{Category: successKey, Title: "Default turns updated", Description: "Applies to the next scan."})
	s.redirect(w, r, "/settings")
}
