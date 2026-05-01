package web

import (
	"net/http"
	"slices"

	"scrutineer/internal/config"
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
		Repos       int64
		Scans       int64
		Findings    int64
		Packages    int64
		Advisories  int64
		Maintainers int64
		Skills      int64
	}
	s.DB.Table("repositories").Count(&stats.Repos)
	s.DB.Table("scans").Count(&stats.Scans)
	s.DB.Table("findings").Count(&stats.Findings)
	s.DB.Table("packages").Count(&stats.Packages)
	s.DB.Table("advisories").Count(&stats.Advisories)
	s.DB.Table("maintainers").Count(&stats.Maintainers)
	s.DB.Table("skills").Count(&stats.Skills)

	var dbSizeBytes int64
	s.DB.Raw("SELECT page_count * page_size FROM pragma_page_count(), pragma_page_size()").Scan(&dbSizeBytes)

	var dbPath string
	s.DB.Raw("SELECT file FROM pragma_database_list WHERE name = 'main'").Scan(&dbPath)

	s.render(w, r, "settings.html", map[string]any{
		"Themes":       config.Themes,
		"Models":       Models,
		"DefaultModel": DefaultModel(),
		"ColorScheme":  resolveColorScheme(r),
		"Concurrency":  s.Queue.Concurrency,
		"Stats":        stats,
		"DBSize":       dbSizeBytes,
		"DBPath":       dbPath,
		"WorkDir":      s.Worker.DataDir,
	})
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
	setFlash(w, Flash{Category: "success", Title: "Theme updated"})
	s.redirect(w, r, "/settings")
}

func (s *Server) settingsUpdateModel(w http.ResponseWriter, r *http.Request) {
	model := r.FormValue("model")
	if !ValidModel(model) {
		http.Error(w, "unknown model", http.StatusUnprocessableEntity)
		return
	}
	SetDefaultModel(model)
	setFlash(w, Flash{Category: "success", Title: "Default model updated"})
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
	setFlash(w, Flash{Category: "success", Title: "Color scheme updated"})
	s.redirect(w, r, "/settings")
}
