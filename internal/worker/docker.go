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
	"syscall"
)

const DefaultRunnerImage = "ghcr.io/alpha-omega-security/scrutineer-runner:latest"

// DockerRunner launches claude inside an ephemeral container with the scan
// workspace (clone + staged skill + output file) mounted at /work. It
// implements SkillRunner.
type DockerRunner struct {
	Image     string
	Effort    string
	ProxyURL  string // http://user:token@host.docker.internal:port; "" disables egress
	FullClone bool
}

func (d DockerRunner) image() string {
	if d.Image != "" {
		return d.Image
	}
	return DefaultRunnerImage
}

// RunSkill runs a skill inside an ephemeral container. The whole workspace
// (clone + staged .claude/skills + context.json + output) is mounted at
// /work read-write so claude can read the skill files and write its output.
// Egress is routed through scrutineer's allowlisting proxy on the host;
// see EgressProxy. tmpfs/cap-drop rules mirror the local runner's intent.
func (d DockerRunner) RunSkill(ctx context.Context, sj SkillJob, emit func(Event)) (SkillResult, error) {
	src, err := ensureClone(ctx, sj.Repo, sj.WorkRoot, d.FullClone, emit)
	if err != nil {
		return SkillResult{}, err
	}
	commit := gitHead(src)
	work := sj.WorkRoot
	absWork, _ := filepath.Abs(work)

	var outPath string
	if sj.OutputFile != "" {
		outPath = filepath.Join(work, sj.OutputFile)
		_ = os.Remove(outPath)
	}

	claudeArgs := []string{
		"claude", "-p",
		"--output-format", "stream-json",
		"--verbose",
		"--permission-mode", "bypassPermissions",
		"--model", sj.Model,
	}
	if d.Effort != "" {
		claudeArgs = append(claudeArgs, "--effort", d.Effort)
	}
	claudeArgs = append(claudeArgs, buildSkillPrompt(sj.Name, sj.OutputFile))

	dockerArgs := []string{
		"run", "--rm",
		"--cap-drop", "ALL",
		"--tmpfs", "/tmp:rw,noexec,nosuid,size=256m",
		"-v", absWork + ":/work",
		"-w", "/work",
		"--add-host", HostGatewayAlias + ":host-gateway",
	}
	if d.ProxyURL != "" {
		dockerArgs = append(dockerArgs,
			"-e", "HTTPS_PROXY="+d.ProxyURL,
			"-e", "HTTP_PROXY="+d.ProxyURL,
			"-e", "ALL_PROXY="+d.ProxyURL,
			"-e", "NO_PROXY=",
		)
	} else {
		dockerArgs = append(dockerArgs, "--network", "none")
	}
	if os.Getenv("ANTHROPIC_API_KEY") != "" {
		dockerArgs = append(dockerArgs, "-e", "ANTHROPIC_API_KEY")
	}
	if os.Getenv("CLAUDE_CODE_OAUTH_TOKEN") != "" {
		dockerArgs = append(dockerArgs, "-e", "CLAUDE_CODE_OAUTH_TOKEN")
	}
	dockerArgs = append(dockerArgs, d.image())
	dockerArgs = append(dockerArgs, claudeArgs...)

	cmd := exec.CommandContext(ctx, "docker", dockerArgs...)
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Env = os.Environ()

	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return SkillResult{}, err
	}
	cmd.Stderr = cmd.Stdout

	emit(Event{Kind: KindText, Text: "$ docker run --rm " + d.image() + " <skill:" + sj.Name + ">"})
	if err := cmd.Start(); err != nil {
		return SkillResult{}, fmt.Errorf("start docker: %w", err)
	}

	ParseStream(stdout, emit)
	waitErr := cmd.Wait()
	if cmd.Process != nil {
		_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGTERM)
	}

	res := SkillResult{Commit: commit}
	if outPath != "" {
		res.Report = readCappedReport(outPath, emit)
	}
	if waitErr != nil {
		return res, fmt.Errorf("docker exited: %w", waitErr)
	}
	return res, nil
}

// DockerAvailable checks if docker is in PATH and the daemon is reachable.
func DockerAvailable() bool {
	out, err := exec.Command("docker", "info", "--format", "{{.ServerVersion}}").Output()
	return err == nil && len(out) > 0
}
