package worker

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path"
	"strings"
	"unicode/utf8"

	"gorm.io/gorm"

	"scrutineer/internal/db"
)

// chatAllowedTools is the read-only tool set a chat turn asks for: the agent
// reads and searches the clone and the staged findings snapshot but does not
// write, edit, or run shell commands. buildClaudeArgs appends the
// harness's own Skill tool. Only claude enforces this list; on codex and
// opencode the same restriction is stated in the prompt and backed by the
// container, as it is for scans.
const chatAllowedTools = "Read,Grep,Glob"

// chatSnapshotFile is the workspace-relative read-only snapshot of what
// scrutineer knows about the repository, staged before each turn so the agent
// has "access to the database" without a live callback token.
const chatSnapshotFile = "scrutineer-context.md"

// chatSnapshotFindingCap bounds how many findings the snapshot lists so a repo
// with thousands of findings does not bloat the prompt context.
const chatSnapshotFindingCap = 200

// chatHistoryCap bounds how many prior messages a fresh (non-resume) run
// replays into its prompt, so a long conversation cannot grow it without
// limit.
const chatHistoryCap = 20

// chatHistoryBudget bounds that replay in bytes as well. The prompt is handed
// to the harness as a single argv element, and Linux caps one argument at
// 128 KiB (MAX_ARG_STRLEN), so a message count is not a bound on its own: a
// handful of long answers would push execve into E2BIG and wedge every fresh
// turn of that conversation. Leaves ample room for the framing paragraph.
const chatHistoryBudget = 48 << 10

// chatMessageCap bounds one message inside the prompt. The budget above is not
// a bound on its own: the trim always keeps the newest turn, and the new
// message is appended after it, so a single pasted log or diff larger than
// MAX_ARG_STRLEN would push execve into E2BIG on the opening turn and on every
// later fresh restart, wedging the conversation for good.
const chatMessageCap = 8 << 10

// chatFindingFieldCap truncates each free-text field of the focused finding in
// the snapshot; a single audit narrative can run to tens of kilobytes and the
// snapshot is read into the model's context on every turn.
const chatFindingFieldCap = 4 << 10

// chatSrcReadyFile marks a chat workspace whose ./src is fully populated. The
// directory existing is not enough: a clone or copy that died halfway leaves a
// partial tree that every later turn would then reuse forever.
const chatSrcReadyFile = ".src-ready"

// ChatRunner drives a persisted conversation by running the configured harness
// in a conversation-stable workspace with read-only access to the clone and a
// snapshot of the repository's findings. It reuses the same
// SkillRunner (local or container) the worker uses for scans, so chat inherits
// the operator's isolation posture.
type ChatRunner struct {
	Runner  SkillRunner
	DB      *gorm.DB
	DataDir string
	// PrepareSrc populates <workRoot>/src from the shared per-URL clone
	// cache, the same path scans take, so a conversation costs a copy rather
	// than its own network clone. Always wired in production; nil leaves the
	// clone to RunSkill, which lands after ensureSrc and so misses its
	// agent-directive strip: a test double only.
	PrepareSrc func(ctx context.Context, url, ref, workRoot string, emit func(Event)) (string, error)
	// MaxTurns caps a single chat turn's agent loop; 0 leaves the runner's
	// own default.
	MaxTurns int
	// Effort is the harness --effort level for chat turns; "" leaves the
	// runner default.
	Effort string
}

// ChatTurnResult is the outcome of one chat turn.
type ChatTurnResult struct {
	Response  string // the assistant's final answer
	SessionID string // harness session to resume on the next turn
	Backend   string // harness that owns SessionID
}

// RunTurn runs one turn of conv: it stages a snapshot of the repository's
// findings, runs the configured harness against the clone with the read-only
// tool set, streams activity through emit, and returns the assistant's answer
// plus the session to resume next time. A conversation carrying a SessionID
// from a prior turn is resumed so the model keeps full history; a -backend
// switch since the last turn, or a session the harness no longer has, starts
// fresh with the transcript replayed into the prompt.
func (c *ChatRunner) RunTurn(ctx context.Context, conv *db.Conversation, userMessage string, emit func(Event)) (ChatTurnResult, error) {
	var repo db.Repository
	if err := c.DB.First(&repo, conv.RepositoryID).Error; err != nil {
		return ChatTurnResult{}, fmt.Errorf("load repository: %w", err)
	}

	workRoot := chatWorkRoot(c.DataDir, conv.ID)
	if err := os.MkdirAll(workRoot, dirPerm); err != nil {
		return ChatTurnResult{}, fmt.Errorf("create chat workspace: %w", err)
	}
	snapshot, err := c.buildSnapshot(&repo, conv.FindingID)
	if err != nil {
		return ChatTurnResult{}, err
	}
	if err := replaceWorkspaceFile(workRoot, chatSnapshotFile, []byte(snapshot)); err != nil {
		return ChatTurnResult{}, fmt.Errorf("stage snapshot: %w", err)
	}

	srcReady, err := c.ensureSrc(ctx, &repo, workRoot, emit)
	if err != nil {
		return ChatTurnResult{}, err
	}

	backend := ""
	if br, ok := c.Runner.(BackendReporter); ok {
		backend = br.Backend()
	}

	sj := SkillJob{
		Repo:         repo,
		WorkRoot:     workRoot,
		Model:        conv.Model,
		Effort:       c.Effort,
		Name:         "chat",
		MaxTurns:     c.MaxTurns,
		AllowedTools: chatAllowedTools,
		// A chat only reads the clone, so skip profile auto-detection: it
		// would build a language image (minutes, for ruby-ext or swift) for a
		// Read/Grep/Glob session that never touches the toolchain.
		Profile:  "default",
		SrcReady: srcReady,
		StateDir: chatHarnessStateDir(c.DataDir, conv.ID),
		// A chat turn has no scan row, and a hardened runner refuses to run
		// without a per-job network name. Key on the conversation in its own
		// namespace so a turn neither shares network "0" nor collides with the
		// scan whose id happens to match.
		IsolationKey: fmt.Sprintf("chat-%d", conv.ID),
	}
	// Resume the prior session only while the backend still matches; handing
	// one harness's id to another's --resume would fail. Prompt is filled on
	// both branches: on a resume it is the fresh-restart fallback the runner
	// uses when the harness no longer has the session, without which the
	// conversation would retry a dead id on every later turn.
	sj.Prompt = buildChatPrompt(&repo, conv, userMessage)
	if conv.SessionID != "" && conv.Backend == backend {
		sj.ResumeSessionID = conv.SessionID
		// Capped for the same argv reason as the transcript replay: a resume
		// hands the raw message to the harness as one argument.
		sj.ResumePrompt = capBytes(userMessage, chatMessageCap, "\n... (message truncated)")
	}

	// The assistant's answer is the terminal result event's text when the
	// harness carries one (claude); codex and opencode close a turn with a
	// payload-less result event, so the last agent text block is the fallback.
	// harnessStarted gates that fallback on the agent stream having begun --
	// every harness announces its session before saying anything -- so
	// scrutineer's own log lines, which reach the same callback before the
	// agent runs, can never be mistaken for an answer. sealed does the same for
	// the other end: a result event freezes the text seen so far. What
	// scrutineer logs once the harness is done is excluded by kind rather than
	// by ordering (KindEgress for the sidecar's lines), because a turn killed
	// mid-stream never produces a result event to seal on and would otherwise
	// fall back to a proxy log line as the reply. Everything still flows to
	// emit for the live activity view.
	var answer, lastText, sealed string
	harnessStarted := false
	wrapped := func(e Event) {
		switch {
		case e.Kind == KindResult:
			if strings.TrimSpace(e.Text) != "" {
				answer = e.Text
			}
			sealed = lastText
		case e.Kind == KindText && harnessStarted && strings.TrimSpace(e.Text) != "":
			lastText = e.Text
		}
		harnessStarted = harnessStarted || e.Kind != KindText
		emit(e)
	}
	res, err := c.Runner.RunSkill(ctx, sj, wrapped)
	if strings.TrimSpace(answer) == "" {
		answer = sealed
	}
	if strings.TrimSpace(answer) == "" {
		answer = lastText
	}
	// A turn that failed late (max turns, timeout, a killed container) has
	// usually already streamed a usable answer; hand it back with the error so
	// the caller can keep it instead of replacing it with the failure text.
	if err != nil {
		return ChatTurnResult{Response: answer, SessionID: res.SessionID, Backend: backend}, err
	}
	if strings.TrimSpace(answer) == "" {
		return ChatTurnResult{SessionID: res.SessionID, Backend: backend}, fmt.Errorf("chat turn produced no answer")
	}
	return ChatTurnResult{Response: answer, SessionID: res.SessionID, Backend: backend}, nil
}

// ensureSrc populates the conversation's ./src on the first turn and reports
// whether it is ready for the runner. A local (file://) repo can't be cloned
// by RunSkill (ensureClone rejects non-https URLs), so its working tree is
// copied in; a remote repo goes through the shared per-URL clone cache like a
// scan does. Later turns reuse the tree, so the whole conversation reasons
// about one revision of the code.
func (c *ChatRunner) ensureSrc(ctx context.Context, repo *db.Repository, workRoot string, emit func(Event)) (bool, error) {
	if chatSrcReady(workRoot) {
		return true, nil
	}
	switch {
	case repo.IsLocal():
		if err := prepareLocalSrc(repo.LocalPath(), workRoot, emit); err != nil {
			return false, fmt.Errorf("copy local source: %w", err)
		}
	case c.PrepareSrc != nil:
		if _, err := c.PrepareSrc(ctx, repo.URL, "", workRoot, emit); err != nil {
			return false, fmt.Errorf("prepare source: %w", err)
		}
	default:
		return false, nil // no cache wired: RunSkill clones into the workspace
	}
	// The clone cache holds the repository verbatim, and a chat turn is a
	// Read/Grep session over it, so it gets the same unconditional strip a scan
	// applies to its own ./src: without it a planted CLAUDE.md/.claude/ steers
	// the answers the analyst is shown. See threatmodel.md T5.
	if err := stripWorkspaceAgentDirectives(workRoot, emit); err != nil {
		return false, err
	}
	// The workspace persists across turns and the agent writes to it, so the
	// marker is replaced through the workspace root like the snapshot: a link
	// the agent left in its place cannot turn this write into a file created
	// elsewhere on the host.
	if err := replaceWorkspaceFile(workRoot, chatSrcReadyFile, nil); err != nil {
		return false, fmt.Errorf("mark chat source ready: %w", err)
	}
	return true, nil
}

// chatSrcReady reports whether the workspace carries the source-ready marker
// as a regular file. Anything else at that name — a link the agent planted, a
// directory — is not proof of a finished clone; the source is prepared again
// and the entry replaced.
func chatSrcReady(workRoot string) bool {
	root, err := os.OpenRoot(workRoot)
	if err != nil {
		return false
	}
	defer func() { _ = root.Close() }()
	info, err := root.Lstat(chatSrcReadyFile)
	return err == nil && info.Mode().IsRegular()
}

// buildChatPrompt is the fresh-run prompt for a conversation: it frames the
// session, points the agent at the clone and the snapshot, states the
// read-only constraint, and replays the transcript. Follow-up turns normally
// resume the harness session and pass the raw message as ResumePrompt instead,
// falling back to this prompt when the session is gone.
func buildChatPrompt(repo *db.Repository, conv *db.Conversation, userMessage string) string {
	var b strings.Builder
	fmt.Fprintf(&b, "You are helping a security analyst in a conversation about the repository %q", repo.Name)
	if repo.URL != "" {
		fmt.Fprintf(&b, " (%s)", repo.URL)
	}
	b.WriteString(".\n")
	b.WriteString("The repository is cloned at ./src. A snapshot of what scrutineer knows about it (repository metadata and its findings) is in ./" + chatSnapshotFile + "; read it for database context.\n")
	if conv.FindingID != nil {
		fmt.Fprintf(&b, "This conversation is focused on finding #%d; its details are in ./%s.\n", *conv.FindingID, chatSnapshotFile)
	}
	b.WriteString("Only read and search: do not modify any file and do not run shell commands. Answer the analyst's questions about the code and findings concisely.\n\n")
	writeChatTranscript(&b, conv.Messages, userMessage)
	return b.String()
}

// writeChatTranscript replays the conversation so a fresh (non-resume) run
// still sees its history; without it the model answers the newest message with
// no context while the page shows the whole thread. The web handler persists
// the analyst's message before starting the turn, so it is already the last
// row: it is appended only when missing, for a caller driving RunTurn directly.
func writeChatTranscript(b *strings.Builder, msgs []db.ChatMessage, userMessage string) {
	kept := msgs
	if len(kept) > chatHistoryCap {
		kept = kept[len(kept)-chatHistoryCap:]
	}
	// Drop from the oldest end until the replay fits chatHistoryBudget, always
	// keeping the newest turn.
	budget := chatHistoryBudget
	first := len(kept)
	for first > 0 {
		budget -= len(kept[first-1].Content)
		if budget < 0 && first < len(kept) {
			break
		}
		first--
	}
	kept = kept[first:]
	if len(kept) < len(msgs) {
		b.WriteString("(earlier turns of this conversation are omitted)\n\n")
	}
	for _, m := range kept {
		who := "Analyst"
		if m.Role == db.ChatRoleAssistant {
			who = "You"
		}
		fmt.Fprintf(b, "%s: %s\n\n", who, capBytes(m.Content, chatMessageCap, "\n... (message truncated)"))
	}
	if n := len(kept); n > 0 && kept[n-1].Role == db.ChatRoleUser && kept[n-1].Content == userMessage {
		return
	}
	b.WriteString("Analyst: " + capBytes(userMessage, chatMessageCap, "\n... (message truncated)") + "\n")
}

// buildSnapshot renders the read-only scrutineer-context.md: repository
// metadata, the focused finding's detail when the conversation is
// finding-scoped, and a bounded list of the repository's findings. A query
// failure is returned rather than swallowed: an empty list renders as "no
// findings recorded", which the agent would then assert as fact.
func (c *ChatRunner) buildSnapshot(repo *db.Repository, findingID *uint) (string, error) {
	var b strings.Builder
	b.WriteString("# scrutineer context (read-only)\n\n")
	b.WriteString("## Repository\n\n")
	fmt.Fprintf(&b, "- Name: %s\n", repo.Name)
	if repo.URL != "" {
		fmt.Fprintf(&b, "- URL: %s\n", repo.URL)
	}
	if repo.DefaultBranch != "" {
		fmt.Fprintf(&b, "- Default branch: %s\n", repo.DefaultBranch)
	}
	if repo.Languages != "" {
		fmt.Fprintf(&b, "- Languages: %s\n", repo.Languages)
	}
	if repo.Description != "" {
		fmt.Fprintf(&b, "- Description: %s\n", repo.Description)
	}
	b.WriteString("\n")

	if findingID != nil {
		var f db.Finding
		switch err := c.DB.First(&f, *findingID).Error; {
		case err == nil:
			b.WriteString("## Focused finding\n\n")
			writeFindingDetail(&b, &f)
			b.WriteString("\n")
		case !errors.Is(err, gorm.ErrRecordNotFound):
			return "", fmt.Errorf("load focused finding %d: %w", *findingID, err)
		}
	}

	var findings []db.Finding
	if err := c.DB.Select("id, title, severity, confidence, status, cwe, location, sub_path").
		Where("repository_id = ?", repo.ID).
		Order(db.SeverityOrderSQL()).Order("id").
		Limit(chatSnapshotFindingCap + 1).
		Find(&findings).Error; err != nil {
		return "", fmt.Errorf("load repository findings: %w", err)
	}

	truncated := len(findings) > chatSnapshotFindingCap
	if truncated {
		findings = findings[:chatSnapshotFindingCap]
	}
	b.WriteString("## Findings\n\n")
	if len(findings) == 0 {
		b.WriteString("_No findings recorded._\n")
		return b.String(), nil
	}
	for _, f := range findings {
		fmt.Fprintf(&b, "- #%d [%s/%s] %s (confidence %s, %s) @ %s\n",
			f.ID, nonEmpty(f.Severity, "?"), nonEmpty(string(f.Status), "?"), f.Title,
			nonEmpty(f.Confidence, "?"), nonEmpty(f.CWE, "no CWE"), nonEmpty(repoRelLocations(f.SubPath, f.Location), "-"))
	}
	if truncated {
		fmt.Fprintf(&b, "\n_(showing the first %d findings; more exist)_\n", chatSnapshotFindingCap)
	}
	return b.String(), nil
}

// writeFindingDetail renders one finding's fields for the focused-finding
// section of the snapshot. The audit narrative (trace, boundary, validation,
// rating) and the captured snippet are included: they only exist in the
// database, so without them a finding-scoped chat cannot answer the questions
// it is opened for ("is this exploitable?") from the clone alone.
func writeFindingDetail(b *strings.Builder, f *db.Finding) {
	fmt.Fprintf(b, "- ID: #%d (%s)\n", f.ID, f.FindingID)
	fmt.Fprintf(b, "- Title: %s\n", f.Title)
	fmt.Fprintf(b, "- Severity: %s\n", nonEmpty(f.Severity, "?"))
	fmt.Fprintf(b, "- Confidence: %s\n", nonEmpty(f.Confidence, "?"))
	fmt.Fprintf(b, "- Status: %s\n", nonEmpty(string(f.Status), "?"))
	if f.CVSSScore > 0 {
		fmt.Fprintf(b, "- CVSS: %.1f %s\n", f.CVSSScore, f.CVSSVector)
	}
	for _, kv := range [][2]string{
		{"CWE", f.CWE},
		{"CVE", f.CVEID},
		{"GHSA", f.GHSAID},
		{"Location", repoRelLocations(f.SubPath, f.Location)},
		{"Locations", repoRelLocations(f.SubPath, f.Locations)},
		{"Affected", f.Affected},
		{"Reachability", f.Reachability},
		{"Snippet", f.Snippet},
		{"Trace", f.Trace},
		{"Boundary", f.Boundary},
		{"Validation", f.Validation},
		{"Rating", f.Rating},
	} {
		if kv[1] == "" {
			continue
		}
		fmt.Fprintf(b, "- %s: %s\n", kv[0], capBytes(kv[1], chatFindingFieldCap, "... (truncated)"))
	}
}

// repoRelLocations rewrites newline-joined finding locations to be relative to
// the repository root, which is what the agent sees at ./src: they are stored
// relative to the finding's sub_path, so on a monorepo the raw value resolves
// against the wrong subproject or nothing at all. The positional suffix
// (":line", ":line:column", ":start-end") rides along on the last segment.
func repoRelLocations(subPath, locations string) string {
	if subPath == "" || locations == "" {
		return locations
	}
	lines := strings.Split(locations, "\n")
	for i, l := range lines {
		if l != "" {
			lines[i] = path.Join(subPath, l)
		}
	}
	return strings.Join(lines, "\n")
}

// capBytes truncates s to at most n bytes, appending suffix when it had to cut.
// Bytes and not runes because both callers bound a byte budget (the argv limit
// and the snapshot file's size), and a rune count is up to 4x that. The cut
// backs off to a rune boundary: slicing mid-rune stores invalid UTF-8, which the
// page renders as a replacement character and the harness receives as a broken
// argument.
func capBytes(s string, n int, suffix string) string {
	if len(s) <= n {
		return s
	}
	cut := n
	for cut > 0 && !utf8.RuneStart(s[cut]) {
		cut--
	}
	return s[:cut] + suffix
}

func nonEmpty(s, fallback string) string {
	if strings.TrimSpace(s) == "" {
		return fallback
	}
	return s
}
