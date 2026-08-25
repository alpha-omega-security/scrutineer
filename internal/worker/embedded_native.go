package worker

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/git-pkgs/clone"
)

const embeddedNativeComponentsFile = "embedded-native-components.json"

type embeddedNativeComponent struct {
	Path        string `json:"path"`
	URL         string `json:"url"`
	Commit      string `json:"commit"`
	PURL        string `json:"purl"`
	Initialized bool   `json:"initialized"`
	Status      string `json:"status"`
	Error       string `json:"error"`
}

func stageEmbeddedNativeComponents(ctx context.Context, workRoot, subPath string) error {
	src := filepath.Join(workRoot, "src")
	modules := []clone.Submodule{}
	if gitHead(src) != "" {
		var err error
		modules, err = clone.Submodules(ctx, src)
		if err != nil {
			return fmt.Errorf("map embedded native submodules: %w", err)
		}
	}

	components := make([]embeddedNativeComponent, 0, len(modules))
	for _, module := range modules {
		if !embeddedNativeComponentInScope(module.Path, subPath) {
			continue
		}
		components = append(components, embeddedNativeComponent{
			Path:        module.Path,
			URL:         module.URL,
			Commit:      module.Commit,
			PURL:        module.PURL,
			Initialized: module.Initialized,
			Status:      string(module.Status),
			Error:       module.Error,
		})
	}

	raw, err := json.Marshal(components)
	if err != nil {
		return fmt.Errorf("encode embedded native submodules: %w", err)
	}
	raw = append(raw, '\n')
	if err := os.WriteFile(filepath.Join(workRoot, embeddedNativeComponentsFile), raw, filePerm); err != nil {
		return fmt.Errorf("write embedded native submodules: %w", err)
	}
	return nil
}

func embeddedNativeComponentInScope(componentPath, subPath string) bool {
	componentPath = strings.Trim(filepath.ToSlash(filepath.Clean(componentPath)), "/")
	subPath = strings.Trim(filepath.ToSlash(filepath.Clean(subPath)), "/")
	if subPath == "" || subPath == "." {
		return true
	}
	return componentPath == subPath ||
		strings.HasPrefix(componentPath, subPath+"/") ||
		strings.HasPrefix(subPath, componentPath+"/")
}
