package poc

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/yuin/goldmark/v2/ast"
)

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
	markdown := legacyParser
	if strict {
		markdown = strictParser
	}
	err := ast.Walk(markdown.Parse(source), func(node ast.Node, entering bool) (ast.WalkStatus, error) {
		if !entering {
			return ast.WalkContinue, nil
		}
		if strict {
			if err := validateProse(node, source); err != nil {
				return ast.WalkStop, err
			}
		}
		fence, ok := node.(*ast.CodeBlock)
		if !ok || fence.CodeBlockKind != ast.CodeBlockKindFenced {
			return ast.WalkContinue, nil
		}
		block, err := parseFence(fence, source, strict)
		if err != nil {
			return ast.WalkStop, err
		}
		if block.Name != "" || strings.TrimSpace(string(block.Body)) != "" {
			blocks = append(blocks, block)
			if len(blocks) > MaxBlocks {
				return ast.WalkStop, fmt.Errorf("PoC markdown has more than %d code fences", MaxBlocks)
			}
		}
		return ast.WalkContinue, nil
	})
	if err == nil {
		err = validateNames(blocks)
	}
	return blocks, err
}

// MaxBlocks caps the number of code fences a PoC validation markdown may
// carry. validateNames is quadratic and bundlePoC's unnamed-fence suffix
// search is roughly cubic in the fence count, and the markdown comes from
// scan output, so an uncapped count is a host-side CPU lever. A legitimate
// PoC is a handful of files.
const MaxBlocks = 64

func parseFence(fence *ast.CodeBlock, source []byte, strict bool) (Block, error) {
	// Str is the raw info string; Value and Language decode escapes and entities.
	info := fence.Info.Str(source)
	language, _, _ := strings.Cut(info, " ")
	block := Block{Language: strings.ToLower(language), Body: fence.Value.Bytes(source)}
	if block.Language != "" && !pocLanguage.MatchString(block.Language) {
		if strict {
			return block, fmt.Errorf("invalid PoC fence language %q", block.Language)
		}
		block.Language = "text"
	}
	fields := strings.Fields(info)
	for _, field := range fields {
		if name, named := strings.CutPrefix(field, "filename="); named {
			if block.Name != "" || len(fields) != 2 || fields[0] == field || !validPoCFilename(name) {
				return block, fmt.Errorf("invalid PoC filename in %q", info)
			}
			block.Name = name
		}
	}
	if strict || block.Name != "" {
		if _, closed := fence.Attribute(pocClosedAttribute); !closed {
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
	switch node := node.(type) {
	case *ast.CodeBlock:
		if node.CodeBlockKind == ast.CodeBlockKindIndented {
			return fmt.Errorf("indented PoC block needs a closed Markdown fence with language filename=relative/path")
		}
	case *ast.Paragraph, *ast.Heading:
		for _, line := range node.(ast.BlockNode).Source() {
			if fileHeader.MatchString(strings.TrimSpace(string(line.Bytes(source)))) {
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
	return ValidPath(name) && (name == "run.sh" || !strings.EqualFold(name, "run.sh"))
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
