package worker

import (
	"context"
	"fmt"
	"os/exec"
	"syscall"
)

// runSpec describes a command to launch and stream output from.
type runSpec struct {
	Name string   // binary name (e.g. "claude", "docker")
	Args []string // arguments
	Dir  string   // working directory; "" = inherit
	Env  []string // environment; nil = inherit
	Log  string   // line emitted before start (e.g. "$ claude -p ...")
}

// runCommand executes a command, streams its stdout/stderr through
// ParseStream, and handles the max-turns sentinel. It returns the
// process exit error (nil on success) or a MaxTurnsReachedError.
func runCommand(ctx context.Context, spec runSpec, emit func(Event)) error {
	cmd := exec.CommandContext(ctx, spec.Name, spec.Args...)
	if spec.Dir != "" {
		cmd.Dir = spec.Dir
	}
	if spec.Env != nil {
		cmd.Env = spec.Env
	}
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}

	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return err
	}
	cmd.Stderr = cmd.Stdout

	emit(Event{Kind: KindText, Text: spec.Log})
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("start %s: %w", spec.Name, err)
	}

	hitMaxTurns := false
	ParseStream(stdout, func(e Event) {
		if e.Kind == KindError && e.Text == "hit max turns" {
			hitMaxTurns = true
		}
		emit(e)
	})
	waitErr := cmd.Wait()
	if cmd.Process != nil {
		_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGTERM)
	}

	if waitErr != nil {
		if hitMaxTurns {
			return &MaxTurnsReachedError{}
		}
		return fmt.Errorf("%s exited: %w", spec.Name, waitErr)
	}
	return nil
}
