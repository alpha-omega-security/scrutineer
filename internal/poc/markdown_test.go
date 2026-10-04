package poc

import (
	"strings"
	"testing"
)

func TestValidate(t *testing.T) {
	for _, tc := range []struct {
		name, markdown, want string
	}{
		{"static evidence", "Source review found no length check; execution was not attempted.", ""},
		{"named file", "```ocaml filename=src/input.ml\nlet () = ()\n```\n", ""},
		{"output", "```console\n$ ./run.sh\n--- output ---\n```\n", ""},
		{"plain output", "```\nobserved output\n```\n", ""},
		{"long fence", "````text filename=input.txt\n```\n--- input.ml ---\n````\n", ""},
		{"tilde fence", "~~~sh filename=run.sh\necho example\n~~~\n", ""},
		{"quoted fence", "> ```sh filename=run.sh\n> echo example\n> ```\n", ""},
		{"list fence", "- Reproduction:\n\n  ```sh filename=run.sh\n  echo example\n  ```\n", ""},
		{"inline delimiter", "Do not use `--- FILENAME ---` delimiters.\n", ""},
		{"horizontal rule", "Static inspection.\n\n---\n\nNo execution.\n", ""},
		{"dash header", "--- /work/src/poc/input.ml ---\nlet () = ()\n", "--- FILENAME ---"},
		{"quoted header", "> --- input.ml ---\n> let () = ()\n", "--- FILENAME ---"},
		{"list header", "- --- input.ml ---\n  let () = ()\n", "--- FILENAME ---"},
		{"unclosed named fence", "```sh filename=run.sh\necho example\n", "unterminated"},
		{"unclosed output", "```text\nexample\n", "unterminated"},
		{"short closing fence", "````sh filename=run.sh\necho example\n```\n", "unterminated"},
		{"glued closing fence", "```sh\necho example```\n", "unterminated"},
		{"unnamed code", "```ocaml\nlet () = ()\n```\n", "filename=relative/path"},
		{"indented code", "    let () = ()\n", "indented PoC block"},
		{"unsafe name", "```sh filename=../run.sh\necho example\n```\n", "invalid PoC filename"},
		{"empty name", "```sh filename=\necho example\n```\n", "invalid PoC filename"},
		{"reserved name", "```text filename=README.md\nexample\n```\n", "conflicting"},
		{"driver directory", "```text filename=run.sh/input\nexample\n```\n", "conflicts with generated run.sh"},
		{"duplicate names", "```text filename=input.txt\na\n```\n```text filename=INPUT.txt\nb\n```\n", "conflicting"},
		{"file directory conflict", "```text filename=input\na\n```\n```text filename=input/file\nb\n```\n", "conflicting"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := Validate(tc.markdown)
			if tc.want == "" {
				if err != nil {
					t.Fatal(err)
				}
			} else if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("Validate() = %v, want %q", err, tc.want)
			}
		})
	}
}

func TestParseKeepsLegacyClosingFence(t *testing.T) {
	markdown := "```sh\necho example```\n"
	blocks, err := Parse(markdown)
	if err != nil || len(blocks) != 1 || string(blocks[0].Body) != "echo example\n" {
		t.Fatalf("Parse() = %+v, %v", blocks, err)
	}
	if Validate(markdown) == nil {
		t.Fatal("new report accepted a glued closing fence")
	}
}
