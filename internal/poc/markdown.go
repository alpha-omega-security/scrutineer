package poc

import (
	"fmt"
	"io/fs"
	"regexp"
	"strings"

	"github.com/yuin/goldmark/ast"
	"github.com/yuin/goldmark/text"
)

var pocPathChars = regexp.MustCompile(`^[a-zA-Z0-9_./-]+$`)
var pocLanguage = regexp.MustCompile(`^[a-zA-Z0-9_+.-]+$`)
var fileHeader = regexp.MustCompile(`^---[ \t]+\S.*[ \t]+---$`)

type Block struct {
	Name     string
	Language string
	Body     []byte
}

// Parse preserves unnamed fences and glued closing fences in older reports.
func Parse(validation string) ([]Block, error) {
	return parse(validation, false)
}

// Validate checks newly generated reproduction Markdown without legacy repairs.
func Validate(validation string) error {
	_, err := parse(validation, true)
	return err
}

func parse(validation string, strict bool) ([]Block, error) {
	source := []byte(validation)
	var blocks []Block
	markdown := legacyMarkdown
	if strict {
		markdown = strictMarkdown
	}
	err := ast.Walk(markdown.Parser().Parse(text.NewReader(source)), func(node ast.Node, entering bool) (ast.WalkStatus, error) {
		if !entering {
			return ast.WalkContinue, nil
		}
		if strict {
			if err := validateProse(node, source); err != nil {
				return ast.WalkStop, err
			}
		}
		fence, ok := node.(*ast.FencedCodeBlock)
		if !ok {
			return ast.WalkContinue, nil
		}
		block, err := parseFence(fence, source, strict)
		if err != nil {
			return ast.WalkStop, err
		}
		if block.Name != "" || strings.TrimSpace(string(block.Body)) != "" {
			blocks = append(blocks, block)
		}
		return ast.WalkContinue, nil
	})
	if err == nil {
		err = validateNames(blocks)
	}
	return blocks, err
}

func parseFence(fence *ast.FencedCodeBlock, source []byte, strict bool) (Block, error) {
	block := Block{Language: strings.ToLower(string(fence.Language(source))), Body: fence.Lines().Value(source)}
	if block.Language != "" && !pocLanguage.MatchString(block.Language) {
		if strict {
			return block, fmt.Errorf("invalid PoC fence language %q", block.Language)
		}
		block.Language = "text"
	}
	if fence.Info != nil {
		fields := strings.Fields(string(fence.Info.Value(source)))
		for _, field := range fields {
			if name, named := strings.CutPrefix(field, "filename="); named {
				if block.Name != "" || len(fields) != 2 || fields[0] == field || !validPoCFilename(name) {
					return block, fmt.Errorf("invalid PoC filename in %q", fence.Info.Value(source))
				}
				block.Name = name
			}
		}
	}
	if strict || block.Name != "" {
		if closed, _ := fence.AttributeString(pocClosedAttribute); closed != true {
			return block, fmt.Errorf("unterminated PoC fence for %q; close the fence on its own line", block.Name)
		}
	}
	if strict && block.Name == "" {
		switch block.Language {
		case "", "text", "console", "shellsession":
		default:
			return block, fmt.Errorf("PoC %s fence needs filename=relative/path; use an unnamed text or console fence for output", block.Language)
		}
	}
	return block, nil
}

func validateProse(node ast.Node, source []byte) error {
	switch node.(type) {
	case *ast.CodeBlock:
		return fmt.Errorf("indented PoC block needs a closed Markdown fence with language filename=relative/path")
	case *ast.Paragraph, *ast.TextBlock, *ast.Heading:
		for i := 0; i < node.Lines().Len(); i++ {
			line := node.Lines().At(i)
			if fileHeader.MatchString(strings.TrimSpace(string(line.Value(source)))) {
				return fmt.Errorf("PoC file header uses --- FILENAME ---; put each file in a closed Markdown fence with language filename=relative/path")
			}
		}
	}
	return nil
}

func validateNames(blocks []Block) error {
	used := map[string]bool{"readme.md": true}
	for _, block := range blocks {
		if block.Name == "" {
			continue
		}
		if NameConflict(used, block.Name) {
			return fmt.Errorf("conflicting PoC filename %q", block.Name)
		}
		used[strings.ToLower(block.Name)] = true
	}
	if !used["run.sh"] && NameConflict(used, "run.sh") {
		return fmt.Errorf("PoC filename conflicts with generated run.sh")
	}
	return nil
}

func validPoCFilename(name string) bool {
	if !fs.ValidPath(name) || name == "." || !pocPathChars.MatchString(name) {
		return false
	}
	if strings.EqualFold(name, "run.sh") && name != "run.sh" {
		return false
	}
	for _, part := range strings.Split(name, "/") {
		if strings.HasSuffix(part, ".") {
			return false
		}
	}
	return true
}

func NameConflict(used map[string]bool, name string) bool {
	name = strings.ToLower(name)
	for other := range used {
		if name == other || strings.HasPrefix(name, other+"/") || strings.HasPrefix(other, name+"/") {
			return true
		}
	}
	return false
}
