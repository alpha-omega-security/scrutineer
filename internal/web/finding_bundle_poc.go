package web

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/yuin/goldmark/ast"
	"github.com/yuin/goldmark/text"

	"scrutineer/internal/poc"
)

var pocLanguage = regexp.MustCompile(`^[a-zA-Z0-9_+.-]+$`)

// probeExt maps a fence info string (already lowercased) to the
// filename its body is written as under poc/. Only explicit shell script
// fences become run.sh; console, shell-session, text, and unmarked fences
// are transcripts and may contain prompts or observed output.
var probeExt = map[string]string{
	"":             "transcript.txt",
	"sh":           "run.sh",
	"bash":         "run.sh",
	"shell":        "run.sh",
	"zsh":          "run.sh",
	"console":      "session.txt",
	"shellsession": "session.txt",
	"text":         "transcript.txt",
	"python":       "probe.py",
	"python3":      "probe.py",
	"py":           "probe.py",
	"ruby":         "probe.rb",
	"rb":           "probe.rb",
	"javascript":   "probe.js",
	"js":           "probe.js",
	"typescript":   "probe.ts",
	"ts":           "probe.ts",
	"go":           "probe.go",
	"golang":       "probe.go",
	"rust":         "probe.rs",
	"rs":           "probe.rs",
	"swift":        "probe.swift",
	"c":            "probe.c",
	"cpp":          "probe.cpp",
	"c++":          "probe.cpp",
	"java":         "Probe.java",
	"php":          "probe.php",
	"perl":         "probe.pl",
	"ocaml":        "probe.ml",
	"json":         "input.json",
	"xml":          "input.xml",
	"yaml":         "input.yaml",
	"yml":          "input.yaml",
	"http":         "request.http",
}

// probeRunner maps a probe filename to the shell line that runs it, for
// the generated run.sh when the validation prose supplied a language
// probe but no shell driver. Filenames not listed here (transcripts,
// input.*, .go, .rs, .c, .cpp, .java, request.http) have no obvious
// one-line runner; the generated run.sh points at README.md instead.
var probeRunner = map[string]string{
	"probe.py":  "exec python3 probe.py \"$@\"",
	"probe.rb":  "exec ruby probe.rb \"$@\"",
	"probe.js":  "exec node probe.js \"$@\"",
	"probe.ts":  "exec npx ts-node probe.ts \"$@\"",
	"probe.php": "exec php probe.php \"$@\"",
	"probe.pl":  "exec perl probe.pl \"$@\"",
}

const runShMode = 0o755

type pocBlock struct {
	name string
	lang string
	body []byte
}

// Named fences preserve paths relative to poc/; unnamed fences retain the
// language-based filenames used by older reports.
func bundlePoC(validation string) ([]bundleEntry, error) {
	blocks, err := parsePoCBlocks(validation)
	if err != nil {
		return nil, err
	}
	used := map[string]bool{"readme.md": true}
	for _, block := range blocks {
		if block.name == "" {
			continue
		}
		if poc.NameConflict(used, block.name) {
			return nil, fmt.Errorf("conflicting PoC filename %q", block.name)
		}
		used[strings.ToLower(block.name)] = true
	}
	if !used["run.sh"] && poc.NameConflict(used, "run.sh") {
		return nil, fmt.Errorf("PoC filename conflicts with generated run.sh")
	}

	var entries []bundleEntry
	var firstProbe string
	haveRunSh := false

	for _, block := range blocks {
		name := block.name
		legacyName, ok := probeExt[block.lang]
		if !ok {
			legacyName = "probe." + block.lang
		}
		if name == "" {
			name = legacyName
			for n := 2; poc.NameConflict(used, name); n++ {
				name = suffixBeforeExt(legacyName, n)
			}
			used[strings.ToLower(name)] = true
		}
		if !poc.ValidPath(name) {
			return nil, fmt.Errorf("invalid PoC filename %q", name)
		}
		var mode int64
		if legacyName == "run.sh" || name == "run.sh" {
			mode = runShMode
		}
		if name == "run.sh" {
			haveRunSh = true
		}
		if firstProbe == "" && block.name == "" && strings.HasPrefix(name, "probe.") {
			firstProbe = name
		}
		entries = append(entries, bundleEntry{Name: "poc/" + name, Data: block.body, Mode: mode})
	}
	if len(entries) == 0 {
		return nil, nil
	}

	if !haveRunSh {
		entries = append([]bundleEntry{{
			Name: "poc/run.sh",
			Data: []byte(generatedRunSh(firstProbe)),
			Mode: runShMode,
		}}, entries...)
	}

	entries = append(entries, bundleEntry{
		Name: "poc/README.md",
		Data: []byte(pocReadme(validation)),
	})
	return entries, nil
}

func parsePoCBlocks(validation string) ([]pocBlock, error) {
	source := []byte(validation)
	var blocks []pocBlock
	err := ast.Walk(pocMarkdown.Parser().Parse(text.NewReader(source)), func(node ast.Node, entering bool) (ast.WalkStatus, error) {
		fence, ok := node.(*ast.FencedCodeBlock)
		if !entering || !ok {
			return ast.WalkContinue, nil
		}
		block := pocBlock{lang: strings.ToLower(string(fence.Language(source))), body: fence.Lines().Value(source)}
		if block.lang != "" && !pocLanguage.MatchString(block.lang) {
			block.lang = "text"
		}
		if fence.Info != nil {
			fields := strings.Fields(string(fence.Info.Value(source)))
			for _, field := range fields {
				if name, named := strings.CutPrefix(field, "filename="); named {
					if block.name != "" || len(fields) != 2 || fields[0] == field || !validPoCFilename(name) {
						return ast.WalkStop, fmt.Errorf("invalid PoC filename in %q", fence.Info.Value(source))
					}
					block.name = name
				}
			}
		}
		if block.name != "" {
			if closed, _ := fence.AttributeString(pocClosedAttribute); closed != true {
				return ast.WalkStop, fmt.Errorf("unterminated PoC fence for %q", block.name)
			}
		}
		if block.name != "" || strings.TrimSpace(string(block.body)) != "" {
			blocks = append(blocks, block)
		}
		return ast.WalkContinue, nil
	})
	return blocks, err
}

func validPoCFilename(name string) bool {
	if !poc.ValidPath(name) {
		return false
	}
	if strings.EqualFold(name, "run.sh") && name != "run.sh" {
		return false
	}
	return true
}

// suffixBeforeExt inserts -n before the final dot: probe.py, 2 -> probe-2.py.
// A name with no dot gets the suffix appended.
func suffixBeforeExt(name string, n int) string {
	i := strings.LastIndexByte(name, '.')
	if i <= 0 {
		return fmt.Sprintf("%s-%d", name, n)
	}
	return fmt.Sprintf("%s-%d%s", name[:i], n, name[i:])
}

func generatedRunSh(firstProbe string) string {
	var b strings.Builder
	b.WriteString("#!/bin/sh\n")
	b.WriteString("# Generated by scrutineer from the finding's Validation field.\n")
	b.WriteString("# See README.md in this directory for expected output and context.\n")
	b.WriteString("cd \"$(dirname \"$0\")\"\n")
	if run, ok := probeRunner[firstProbe]; ok {
		b.WriteString(run + "\n")
	} else {
		b.WriteString("echo 'No shell driver in the original reproduction; see README.md and probe files.' >&2\n")
		b.WriteString("exit 2\n")
	}
	return b.String()
}

func pocReadme(validation string) string {
	var b strings.Builder
	b.WriteString("# Reproduction\n\n")
	b.WriteString("This directory is the finding's Validation step materialised as files. ")
	b.WriteString("Fenced code blocks use their declared filenames, or language-based names when unnamed. They are written alongside ")
	b.WriteString("this README; run.sh is either the shell block from the reproduction or ")
	b.WriteString("a generated stub that invokes the first probe.\n\n")
	b.WriteString("## Validation (verbatim)\n\n")
	b.WriteString(strings.TrimSpace(validation))
	b.WriteString("\n")
	return b.String()
}
