package worker

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"scrutineer/internal/coverage"
	"scrutineer/internal/db"
	"scrutineer/internal/skills"
)

// The probe only resolves executable names; it never executes repository tools.
// Feature availability comes from runner policy, not installed CLI names. Current
// runners do not provision nested daemons or FUSE devices/mount privileges.
const capabilityProbeTimeout = 30 * time.Second

const capabilityProbeScript = `
has_executable() {
 search="${PATH}:"
 while [ -n "$search" ]; do
  directory="${search%%:*}"
  search="${search#*:}"
  if [ -z "$directory" ]; then directory=.; fi
  if [ -f "$directory/$1" ] && [ -x "$directory/$1" ]; then return 0; fi
 done
 return 1
}
egress="$1"
shift
for requirement do
 case "$requirement" in
  command:*)
   name="${requirement#command:}"
   if has_executable "$name"; then continue; fi
   ;;
  feature:network-egress)
   if [ "$egress" = "yes" ]; then continue; fi
   ;;
 esac
 printf '%s\n' "$requirement"
done
printf 'preflight-ok\n'
`

func (sj SkillJob) checkCapabilities(ctx context.Context, prefix []string, env map[string]string, egress bool, emit func(Event)) error {
	if len(sj.RequiresCommands) == 0 && len(sj.RequiresFeatures) == 0 {
		return nil
	}
	result := coverage.Preflight{Status: coverage.PreflightReady, Missing: []string{}}
	if err := skills.ValidateCapabilities(sj.RequiresCommands, sj.RequiresFeatures); err != nil {
		result.Error = err.Error()
	} else {
		missing, err := sj.probeCapabilities(ctx, prefix, env, egress)
		if err != nil {
			result.Error = err.Error()
		} else {
			result.Missing = missing
		}
	}
	if result.Error != "" || len(result.Missing) > 0 {
		result.Status = coverage.PreflightBlocked
		if result.Error == "" && sj.DegradedMode {
			result.Status = coverage.PreflightDegraded
			result.Degraded = true
		}
	}
	if sj.RecordPreflight != nil {
		if err := sj.RecordPreflight(result); err != nil {
			return fmt.Errorf("record capability preflight: %w", err)
		}
	}
	detail := "capability preflight " + result.Status
	if len(result.Missing) > 0 {
		detail += ": " + strings.Join(result.Missing, ", ")
	}
	if result.Error != "" {
		detail += ": " + result.Error
	}
	emit(Event{Kind: KindText, Text: detail})
	if result.Status == coverage.PreflightBlocked {
		return fmt.Errorf("%s", detail)
	}
	return nil
}

func (sj SkillJob) probeCapabilities(ctx context.Context, prefix []string, env map[string]string, egress bool) ([]string, error) {
	requirements := make([]string, 0, len(sj.RequiresCommands)+len(sj.RequiresFeatures))
	for _, name := range sj.RequiresCommands {
		requirements = append(requirements, "command:"+name)
	}
	for _, name := range sj.RequiresFeatures {
		requirements = append(requirements, "feature:"+name)
	}
	policy := "no"
	if egress {
		policy = "yes"
	}
	argv := append(slices.Clone(prefix), "/bin/sh", "-c", capabilityProbeScript, "capability-preflight", policy)
	argv = append(argv, requirements...)
	probeCtx, cancel := context.WithTimeout(ctx, capabilityProbeTimeout)
	defer cancel()
	cmd := exec.CommandContext(probeCtx, argv[0], argv[1:]...)
	cmd.Dir = sj.WorkRoot
	cmd.Env = environmentWith(os.Environ(), env)
	output, err := cmd.Output()
	if err != nil {
		if probeCtx.Err() != nil {
			return nil, fmt.Errorf("capability probe: %w", probeCtx.Err())
		}
		// Do not surface container stderr, which can contain credentials/config.
		return nil, fmt.Errorf("capability probe did not complete: %w", err)
	}
	return parseCapabilityProbe(string(output), requirements)
}

func parseCapabilityProbe(output string, requirements []string) ([]string, error) {
	lines := strings.Split(strings.TrimSuffix(output, "\n"), "\n")
	if len(lines) == 0 || lines[len(lines)-1] != "preflight-ok" {
		return nil, fmt.Errorf("capability probe returned incomplete output")
	}
	missing := []string{}
	for _, line := range lines[:len(lines)-1] {
		if !slices.Contains(requirements, line) || slices.Contains(missing, line) {
			return nil, fmt.Errorf("capability probe returned invalid output")
		}
		missing = append(missing, line)
	}
	slices.Sort(missing)
	return missing, nil
}

func (w *Worker) configureCapabilityPreflight(ctx context.Context, scan *db.Scan, skill *db.Skill, sj *SkillJob) {
	sj.RequiresCommands = skills.SplitPatterns(skill.RequiresCommands)
	sj.RequiresFeatures = skills.SplitPatterns(skill.RequiresFeatures)
	sj.DegradedMode = skill.DegradedMode
	sj.RecordPreflight = func(result coverage.Preflight) error {
		rec, ok := coverage.Parse(scan.Coverage)
		if !ok && strings.TrimSpace(scan.Coverage) != "" {
			return fmt.Errorf("stored coverage did not decode")
		}
		// A repair turn cannot erase a reduced-coverage attempt earlier in this scan.
		if rec.Preflight == nil || rec.Preflight.Status == coverage.PreflightReady || result.Status != coverage.PreflightReady {
			rec.Preflight = &result
		}
		if rec.Completeness == "" {
			rec.Completeness = coverage.CompletenessUnknown
			rec.Reason = "no enumerable scope for this scan mode"
		}
		setCoverage(scan, rec)
		update := w.DB.WithContext(ctx).Model(scan).Updates(map[string]any{"coverage": scan.Coverage, "completeness": scan.Completeness})
		if update.Error != nil {
			return update.Error
		}
		if update.RowsAffected != 1 {
			return fmt.Errorf("scan no longer exists")
		}
		return stageCapabilityPreflight(sj.WorkRoot, sj.SkillDir, result)
	}
}

func stageCapabilityPreflight(workRoot, skillDir string, result coverage.Preflight) error {
	// Keep both copies in sync, including after whole-tree restaging or a retry.
	for _, dir := range []string{workRoot, skillDir} {
		path := filepath.Join(dir, "context.json")
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		var document map[string]json.RawMessage
		if err := json.Unmarshal(data, &document); err != nil {
			return err
		}
		var contextFields map[string]json.RawMessage
		if err := json.Unmarshal(document["scrutineer"], &contextFields); err != nil {
			return err
		}
		if contextFields == nil {
			return fmt.Errorf("missing scrutineer context")
		}
		raw, err := json.Marshal(result)
		if err != nil {
			return err
		}
		contextFields["preflight"] = raw
		document["scrutineer"], err = json.Marshal(contextFields)
		if err != nil {
			return err
		}
		data, err = json.MarshalIndent(document, "", "  ")
		if err != nil {
			return err
		}
		if err := os.WriteFile(path, data, filePerm); err != nil {
			return err
		}
	}
	return nil
}
