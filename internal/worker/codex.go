package worker

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"

	codex "github.com/pmenglund/codex-sdk-go"
)

// CodexRunner implements SkillRunner using the codex-sdk-go library.
type CodexRunner struct {
	Model     string // fallback model; SkillJob.Model wins when set
	FullClone bool
	MaxTurns  int
}

func (c CodexRunner) RunSkill(ctx context.Context, sj SkillJob, emit func(Event)) (SkillResult, error) {
	src, err := ensureClone(ctx, sj.Repo, sj.WorkRoot, c.FullClone, sj.Ref, emit)
	if err != nil {
		return SkillResult{}, err
	}
	commit := gitHead(src)
	work := sj.WorkRoot

	var outPath string
	if sj.OutputFile != "" {
		outPath = filepath.Join(work, sj.OutputFile)
		_ = os.Remove(outPath)
	}

	model := sj.Model
	if model == "" {
		model = c.Model
	}
	if model == "" {
		model = "codex-mini-latest"
	}

	prompt := buildSkillPrompt(sj.Name, sj.OutputFile)

	emit(Event{Kind: KindText, Text: fmt.Sprintf("$ codex sdk --model %s <skill:%s>", model, sj.Name)})

	client, err := codex.New(ctx, codex.Options{
		Spawn:           codex.SpawnOptions{Stderr: io.Discard},
		ApprovalHandler: codex.AutoApproveHandler{},
	})
	if err != nil {
		return SkillResult{}, fmt.Errorf("start codex: %w", err)
	}
	defer client.Close()

	thread, err := client.StartThread(ctx, codex.ThreadStartOptions{
		Model:          model,
		Cwd:            work,
		ApprovalPolicy: codex.ApprovalPolicyNever,
		SandboxPolicy:  codex.SandboxModeDangerFullAccess,
	})
	if err != nil {
		return SkillResult{}, fmt.Errorf("start thread: %w", err)
	}

	result, err := thread.Run(ctx, prompt, nil)
	if err != nil {
		emit(Event{Kind: KindResult, Text: "done"})
		res := SkillResult{Commit: commit}
		if outPath != "" {
			res.Report = readCappedReport(outPath, emit)
		}
		return res, fmt.Errorf("codex turn: %w", err)
	}

	if result.FinalResponse != "" {
		emit(Event{Kind: KindText, Text: result.FinalResponse})
	}

	emit(Event{Kind: KindResult, Text: "done"})

	res := SkillResult{Commit: commit}
	if outPath != "" {
		res.Report = readCappedReport(outPath, emit)
	}
	return res, nil
}
