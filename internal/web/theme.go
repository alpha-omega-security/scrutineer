package web

import (
	"context"
	"net/http"
	"slices"
	"time"

	"scrutineer/internal/config"
	"scrutineer/internal/db"
	"scrutineer/internal/worker"
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
	s.DB.Model(&db.Finding{}).Where("scan_id IN (?)", deepDiveScanIDs(s.DB)).Count(&stats.Findings)
	s.DB.Model(&db.Finding{}).Where("scan_id NOT IN (?)", deepDiveScanIDs(s.DB)).Count(&stats.ScannerFindings)
	s.DB.Table("packages").Count(&stats.Packages)
	s.DB.Table("advisories").Count(&stats.Advisories)
	s.DB.Table("maintainers").Count(&stats.Maintainers)
	s.DB.Table("skills").Count(&stats.Skills)

	var dbSizeBytes int64
	s.DB.Raw("SELECT page_count * page_size FROM pragma_page_count(), pragma_page_size()").Scan(&dbSizeBytes)

	var dbPath string
	s.DB.Raw("SELECT file FROM pragma_database_list WHERE name = 'main'").Scan(&dbPath)

	meta := s.toolMetadataCached(r.Context())

	s.render(w, r, "settings.html", map[string]any{
		"Themes":        config.Themes,
		"Models":        Models,
		"DefaultModel":  DefaultModel(),
		"Efforts":       Efforts,
		"DefaultEffort": DefaultEffort(),
		"ColorScheme":   resolveColorScheme(r),
		"Concurrency":   s.Queue.Concurrency,
		"Stats":         stats,
		"DBSize":        dbSizeBytes,
		"DBPath":        dbPath,
		"WorkDir":       s.Worker.DataDir,
		"Commit":        s.Commit,
		"Meta":          meta,
	})
}

// toolMetadata is the runtime version info shown on the settings page:
// the scanner tools baked into the runner image plus the host docker
// daemon and the runner image name itself.
type toolMetadata struct {
	worker.RunnerToolVersions
	Docker      string
	RunnerImage string
}

// toolMetadataTTL bounds how long a gathered version set is reused. Versions
// only change when the operator pulls a new image or restarts docker, so a
// generous TTL keeps the settings page DB-fast without going stale for long.
const toolMetadataTTL = 5 * time.Minute

// toolMetadataTimeout caps the docker shell-outs so a hung or missing daemon
// degrades to "unavailable" instead of stalling the settings page.
const toolMetadataTimeout = 5 * time.Second

func (s *Server) toolMetadataCached(ctx context.Context) toolMetadata {
	s.toolMetaMu.Lock()
	defer s.toolMetaMu.Unlock()
	if time.Now().Before(s.toolMetaTTL) {
		return s.toolMetaCache
	}
	ctx, cancel := context.WithTimeout(ctx, toolMetadataTimeout)
	defer cancel()
	image := worker.RunnerImageName(s.Worker.Runner)
	meta := toolMetadata{
		RunnerToolVersions: worker.QueryRunnerToolVersions(ctx, image),
		Docker:             worker.DockerServerVersion(ctx),
		RunnerImage:        image,
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
	SetDefaultModel(model)
	setFlash(w, Flash{Category: successKey, Title: "Default model updated"})
	s.redirect(w, r, "/settings")
}

func (s *Server) settingsUpdateEffort(w http.ResponseWriter, r *http.Request) {
	effort := r.FormValue("effort")
	if !ValidEffort(effort) {
		http.Error(w, "unknown effort", http.StatusUnprocessableEntity)
		return
	}
	SetDefaultEffort(effort)
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
