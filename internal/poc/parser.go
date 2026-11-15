package poc

import (
	"bytes"
	"strings"

	"github.com/yuin/goldmark/v2/ast"
	"github.com/yuin/goldmark/v2/extension"
	"github.com/yuin/goldmark/v2/parser"
	"github.com/yuin/goldmark/v2/text"
	"github.com/yuin/goldmark/v2/util"
)

// Run before Goldmark's standard fenced block parser (priority 700).
const pocFencePriority = 699

const (
	pocLegacyAttribute = "poc-legacy"
	pocClosedAttribute = "poc-closed"
)

var legacyParser = newParser(false)
var strictParser = newParser(true)

var pocFlag = text.NewMultiLineValueFromString("true", text.IdentityDecoder)

//nolint:ireturn // Goldmark exposes its constructor through this interface.
func newParser(strict bool) parser.Parser {
	return parser.New(
		parser.WithExtensions(extension.NewGFMParser()),
		parser.WithBlockParsers(util.Prioritized[parser.BlockParser](
			&pocFenceParser{BlockParser: parser.NewFencedCodeBlockParser(), strict: strict}, pocFencePriority,
		)),
	)
}

type pocFenceParser struct {
	parser.BlockParser
	strict bool
}

//nolint:ireturn // Required by Goldmark's BlockParser interface.
func (p *pocFenceParser) Open(parent ast.Node, reader text.Reader, pc parser.Context) (ast.Node, parser.State) {
	line, _ := reader.PeekLine()
	pos := pc.BlockOffset()
	node, state := p.BlockParser.Open(parent, reader, pc)
	if p.strict || node == nil || pos < 0 || !bytes.HasPrefix(line[pos:], []byte("```")) || bytes.HasPrefix(line[pos:], []byte("````")) {
		return node, state
	}
	for field := range strings.FieldsSeq(string(line[pos+3:])) {
		if strings.HasPrefix(field, "filename=") {
			return node, state
		}
	}
	node.SetAttribute(pocLegacyAttribute, pocFlag)
	return node, state
}

func (p *pocFenceParser) Continue(node ast.Node, reader text.Reader, pc parser.Context) parser.State {
	line, segment := reader.PeekLine()
	state := p.BlockParser.Continue(node, reader, pc)
	if state == parser.Close {
		node.SetAttribute(pocClosedAttribute, pocFlag)
		return state
	}
	if _, legacy := node.Attribute(pocLegacyAttribute); !legacy {
		return state
	}
	line = bytes.TrimRight(line, " \t\r\n")
	body, closed := bytes.CutSuffix(line, []byte("```"))
	if !closed || len(bytes.TrimSpace(body)) == 0 || body[len(body)-1] == '`' {
		return state
	}
	// Older reports glued the closing fence to the last content line.
	lines := node.(*ast.CodeBlock).Value.Segments()
	lines[len(lines)-1].Stop = segment.Start + len(body)
	return parser.Close
}
