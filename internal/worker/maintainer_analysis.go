package worker

import (
	"context"
	_ "embed"
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"

	"scrutineer/internal/db"
)

//go:embed maintainer_schema.json
var maintainerSchema string

// gatherMaintainerContext fetches live from all three ecosyste.ms endpoints
// and assembles a JSON document for the model.
func gatherMaintainerContext(ctx context.Context, repoURL string, emit func(Event)) string {
	sections := map[string]json.RawMessage{}

	endpoints := map[string]string{
		"commits": "https://commits.ecosyste.ms/api/v1/repositories/lookup?url=" + url.QueryEscape(repoURL),
		"issues":  "https://issues.ecosyste.ms/api/v1/repositories/lookup?url=" + url.QueryEscape(repoURL),
		"packages": "https://packages.ecosyste.ms/api/v1/packages/lookup?repository_url=" + url.QueryEscape(repoURL),
	}

	for name, endpoint := range endpoints {
		emit(Event{Kind: KindText, Text: "GET " + endpoint})
		raw, err := fetchJSONFollow(ctx, endpoint)
		if err != nil {
			emit(Event{Kind: KindText, Text: name + ": " + err.Error()})
			continue
		}
		sections[name] = raw
	}

	out, _ := json.Marshal(sections)
	return string(out)
}

func gatherPrompt(repoURL, gathered, schema string) string {
	return fmt.Sprintf(
		"You are analyzing the maintainer landscape of %s.\n\n"+
			"Below is raw data from three sources: commit history (who wrote code and how much, including past year activity),"+
			" issue/PR activity (who reviews and responds), and package registry listings (who publishes releases).\n\n"+
			"From this data, identify the actual maintainers -- the people who would need to know about"+
			" a security vulnerability. Distinguish active leads from occasional contributors. Filter out bots.\n\n"+
			"Raw data:\n```json\n%s\n```\n\n"+
			"Write your analysis as JSON to ./report.json conforming exactly to this schema:\n\n"+
			"```json\n%s\n```\n",
		repoURL, gathered, schema)
}

func (w *Worker) doMaintainerAnalysis(ctx context.Context, scan *db.Scan, emit func(Event)) (string, error) {
	gathered := gatherMaintainerContext(ctx, scan.Repository.URL, emit)
	prompt := gatherPrompt(scan.Repository.URL, gathered, maintainerSchema)

	scan.Prompt = prompt
	w.DB.Model(scan).Update("prompt", prompt)

	work := filepath.Join(w.DataDir, fmt.Sprintf("repo-%d", scan.RepositoryID))
	if err := os.MkdirAll(work, dirPerm); err != nil {
		return "", err
	}
	reportPath := filepath.Join(work, "report.json")
	_ = os.Remove(reportPath)

	args := []string{
		"-p",
		"--output-format", "stream-json",
		"--verbose",
		"--permission-mode", "bypassPermissions",
		"--model", scan.Model,
	}
	args = append(args, prompt)

	cmd := exec.CommandContext(ctx, "claude", args...)
	cmd.Dir = work
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return "", err
	}
	cmd.Stderr = cmd.Stdout

	emit(Event{Kind: KindText, Text: "$ claude <maintainer analysis prompt>"})
	if err := cmd.Start(); err != nil {
		return "", fmt.Errorf("start claude: %w", err)
	}
	ParseStream(stdout, emit)
	waitErr := cmd.Wait()
	if cmd.Process != nil {
		_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGTERM)
	}

	report, _ := os.ReadFile(reportPath)
	if waitErr != nil && len(report) == 0 {
		return "", fmt.Errorf("claude exited: %w", waitErr)
	}
	if len(report) == 0 {
		return "", fmt.Errorf("claude exited 0 but wrote no report")
	}

	// Parse and upsert maintainers
	var result struct {
		Maintainers []struct {
			Login      string `json:"login"`
			Name       string `json:"name"`
			Email      string `json:"email"`
			Role       string `json:"role"`
			Status     string `json:"status"`
			Confidence string `json:"confidence"`
			Evidence   string `json:"evidence"`
		} `json:"maintainers"`
		DisclosureChannel string `json:"disclosure_channel"`
		Notes             string `json:"notes"`
	}
	if err := json.Unmarshal(report, &result); err != nil {
		return string(report), fmt.Errorf("parse report: %w", err)
	}

	var repo db.Repository
	w.DB.First(&repo, scan.RepositoryID)
	var linked []db.Maintainer

	for _, rm := range result.Maintainers {
		if rm.Login == "" {
			continue
		}
		var m db.Maintainer
		w.DB.Where(db.Maintainer{Login: rm.Login}).FirstOrCreate(&m)
		if rm.Name != "" {
			m.Name = rm.Name
		}
		if validEmail(rm.Email) {
			m.Email = rm.Email
		}
		switch rm.Status {
		case "active":
			m.Status = db.MaintainerActive
		case "inactive":
			m.Status = db.MaintainerInactive
		}
		if rm.Evidence != "" {
			m.Notes = rm.Role + ": " + rm.Evidence
		}
		w.DB.Save(&m)
		linked = append(linked, m)
	}

	if len(linked) > 0 {
		_ = w.DB.Model(&repo).Association("Maintainers").Replace(linked)
	}
	emit(Event{Kind: KindText, Text: fmt.Sprintf("identified %d maintainer(s)", len(result.Maintainers))})

	out, _ := json.MarshalIndent(result, "", "  ")
	return string(out), nil
}
