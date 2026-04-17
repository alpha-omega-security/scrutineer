// Package worker provides a DockerRunner that executes claude in an ephemeral
// container. Used when docker is available on the host; falls back to
// LocalClaude otherwise. The scrutineer process runs on the host (not
// containerised) and calls docker directly -- no socket mounting needed (T12).
package worker

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"

	"scrutineer/internal/db"
)

const (
	defaultRunnerImage = "scrutineer-runner"
)

// DockerRunner launches claude inside an ephemeral container with the
// workspace mounted read-only. It implements ClaudeRunner.
type DockerRunner struct {
	Image  string // container image (default: scrutineer-runner)
	Effort string
}

func (d DockerRunner) image() string {
	if d.Image != "" {
		return d.Image
	}
	return defaultRunnerImage
}

func (d DockerRunner) Prompt(repo db.Repository, spec string) string {
	return LocalClaude{Effort: d.Effort}.Prompt(repo, spec)
}

func (d DockerRunner) Run(ctx context.Context, job Job, emit func(Event)) (Result, error) {
	// Ensure clone exists on the host
	src, err := ensureClone(ctx, job.Repo, job.DataDir, emit)
	if err != nil {
		return Result{}, err
	}
	commit := gitHead(src)
	work := filepath.Dir(src)

	// Output dir for the report -- mounted read-write
	outDir := filepath.Join(work, "out")
	if err := os.MkdirAll(outDir, dirPerm); err != nil {
		return Result{}, err
	}
	reportPath := filepath.Join(outDir, "report.json")
	_ = os.Remove(reportPath)

	// Build the claude command that runs INSIDE the container.
	// The container sees /src (read-only) and /out (read-write).
	claudeArgs := []string{
		"claude", "-p",
		"--output-format", "stream-json",
		"--verbose",
		"--permission-mode", "bypassPermissions",
		"--model", job.Model,
	}
	if d.Effort != "" {
		claudeArgs = append(claudeArgs, "--effort", d.Effort)
	}

	// The prompt tells claude to read /src and write /out/report.json
	prompt := strings.Replace(job.Prompt,
		"is cloned at ./src",
		"is mounted read-only at /src", 1)
	prompt = strings.Replace(prompt,
		"Write your results as JSON to ./report.json",
		"Write your results as JSON to /out/report.json", 1)
	claudeArgs = append(claudeArgs, prompt)

	// Absolute paths for docker -v
	absSrc, _ := filepath.Abs(src)
	absOut, _ := filepath.Abs(outDir)

	dockerArgs := []string{
		"run", "--rm",
		"--network", "none",
		"--read-only",
		"--cap-drop", "ALL",
		"--tmpfs", "/tmp:rw,noexec,nosuid,size=256m",
		"-v", absSrc + ":/src:ro",
		"-v", absOut + ":/out",
	}

	// Pass API key into container if set
	if key := os.Getenv("ANTHROPIC_API_KEY"); key != "" {
		dockerArgs = append(dockerArgs, "-e", "ANTHROPIC_API_KEY")
	}

	dockerArgs = append(dockerArgs, d.image())
	dockerArgs = append(dockerArgs, claudeArgs...)

	cmd := exec.CommandContext(ctx, "docker", dockerArgs...)
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}

	// Pass through ANTHROPIC_API_KEY from host env
	cmd.Env = os.Environ()

	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return Result{}, err
	}
	cmd.Stderr = cmd.Stdout

	emit(Event{Kind: KindText, Text: "$ docker run --rm --network none --read-only " + d.image() + " claude <prompt>"})
	if err := cmd.Start(); err != nil {
		return Result{}, fmt.Errorf("start docker: %w", err)
	}

	ParseStream(stdout, emit)
	waitErr := cmd.Wait()

	if cmd.Process != nil {
		_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGTERM)
	}

	report, _ := os.ReadFile(reportPath)
	res := Result{Commit: commit, Report: string(report)}
	if waitErr != nil && len(report) == 0 {
		return res, fmt.Errorf("docker exited: %w", waitErr)
	}
	if len(report) == 0 {
		return res, fmt.Errorf("container exited 0 but wrote no report")
	}
	return res, nil
}

// DockerAvailable checks if docker is in PATH and the daemon is reachable.
func DockerAvailable() bool {
	out, err := exec.Command("docker", "info", "--format", "{{.ServerVersion}}").Output()
	return err == nil && len(out) > 0
}
