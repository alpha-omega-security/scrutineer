package web

import (
	"encoding/json"
	"strings"

	"scrutineer/internal/db"
	"scrutineer/internal/repoconfig"
)

type focusAreaView struct {
	Name    string
	Paths   string
	Surface string
	Group   string
}

func (v focusAreaView) Tooltip() string {
	var parts []string
	if v.Paths != "" {
		parts = append(parts, "paths: "+v.Paths)
	}
	if v.Surface != "" {
		parts = append(parts, "surface: "+v.Surface)
	}
	if v.Group != "" {
		parts = append(parts, "batch: "+v.Group)
	}
	return strings.Join(parts, "\n")
}

// Display legacy focus areas even if they no longer pass enqueue validation.
func scanFocus(scan db.Scan) focusAreaView {
	view := focusAreaView{Group: scan.ScanGroup}
	var area repoconfig.FocusArea
	if err := json.Unmarshal([]byte(scan.FocusArea), &area); err != nil {
		return view
	}
	if name := strings.TrimSpace(area.Name); name != "" {
		view.Name = name
		view.Paths = strings.Join(area.Paths, ", ")
		view.Surface = strings.TrimSpace(area.Surface)
	}
	return view
}
