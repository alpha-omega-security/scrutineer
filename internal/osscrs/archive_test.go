package osscrs

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"errors"
	"strings"
	"testing"

	"scrutineer/internal/poc"
)

type entry struct {
	name     string
	body     string
	typeflag byte
}

func build(t *testing.T, entries ...entry) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	tw := tar.NewWriter(zw)
	for _, e := range entries {
		hdr := &tar.Header{Name: e.name, Mode: 0o644, Size: int64(len(e.body)), Typeflag: e.typeflag}
		if e.typeflag == 0 {
			hdr.Typeflag = tar.TypeReg
		}
		if hdr.Typeflag != tar.TypeReg {
			hdr.Size = 0
			hdr.Linkname = "../../etc/passwd"
		}
		if err := tw.WriteHeader(hdr); err != nil {
			t.Fatal(err)
		}
		if hdr.Typeflag == tar.TypeReg {
			if _, err := tw.Write([]byte(e.body)); err != nil {
				t.Fatal(err)
			}
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

const candidate = `{"version":"2.1.0","runs":[{"tool":{"driver":{"name":"crs-a"}},"results":[
	{"ruleId":"heap-overflow","message":{"text":"overflow in parse"},
	 "locations":[{"physicalLocation":{"artifactLocation":{"uri":"src/parse.c"},"region":{"startLine":12}}}],
	 "attachments":[{"artifactLocation":{"uri":"./povs/abc"}}]}]}]}`

func TestReadClassifiesEntries(t *testing.T) {
	a, err := Read(bytes.NewReader(build(t,
		entry{name: "bug-candidates/", typeflag: tar.TypeDir},
		entry{name: "bug-candidates/a.sarif", body: candidate},
		entry{name: "povs/abc", body: "\x00crash"},
		entry{name: "patches/fix.diff", body: "--- a\n+++ b\n"},
		entry{name: "reports/r.tar.gz", body: "report"},
		entry{name: "seeds/1", body: "s"},
		entry{name: "seeds/2", body: "s"},
		entry{name: "harnesses/h/build.sh", body: "x"},
	)))
	if err != nil {
		t.Fatal(err)
	}
	if len(a.Candidates) != 1 || a.Candidates[0].Tool != "crs-a" || len(a.Candidates[0].Findings) != 1 {
		t.Fatalf("candidates = %+v", a.Candidates)
	}
	if got := a.Candidates[0].Findings[0].Attachments; len(got) != 1 || got[0] != "povs/abc" {
		t.Errorf("attachments = %q, want normalised [povs/abc]", got)
	}
	var kinds []string
	for _, art := range a.Artifacts {
		kinds = append(kinds, art.Kind+":"+art.Path)
		if art.SHA256 != poc.Digest(art.Data) {
			t.Errorf("%s digest mismatch", art.Path)
		}
	}
	if strings.Join(kinds, ",") != "pov:povs/abc,patch:patches/fix.diff,report:reports/r.tar.gz" {
		t.Errorf("artifacts = %v", kinds)
	}
	if string(a.Artifacts[0].Data) != "\x00crash" {
		t.Errorf("PoV bytes = %q, want original bytes", a.Artifacts[0].Data)
	}
	want := []Skipped{
		{Path: "seeds/", Files: 2, Reason: "unsupported artifact type"},
		{Path: "harnesses/", Files: 1, Reason: "unsupported artifact type"},
	}
	if len(a.Skipped) != len(want) || a.Skipped[0] != want[0] || a.Skipped[1] != want[1] {
		t.Errorf("skipped = %+v, want %+v", a.Skipped, want)
	}
}

func TestReadReportsRejectedEntries(t *testing.T) {
	a, err := Read(bytes.NewReader(build(t,
		entry{name: "../povs/escape", body: "x"},
		entry{name: "povs/link", typeflag: tar.TypeSymlink},
		entry{name: "povs/hard", typeflag: tar.TypeLink},
		entry{name: "povs/big", body: strings.Repeat("a", poc.MaxFileBytes+1)},
		entry{name: "povs/dup", body: "1"},
		entry{name: "povs/dup", body: "2"},
		entry{name: "bug-candidates/notes.txt", body: "not sarif"},
		entry{name: "povs", body: "root file"},
	)))
	if err != nil {
		t.Fatal(err)
	}
	reasons := map[string]string{}
	for _, s := range a.Skipped {
		reasons[s.Path] = s.Reason
	}
	for name, want := range map[string]string{
		"../povs/escape":           "unsafe path",
		"povs/link":                "not a regular file",
		"povs/hard":                "not a regular file",
		"povs/big":                 "exceeds 1048576 bytes",
		"povs/dup":                 "duplicate path",
		"bug-candidates/notes.txt": "not a SARIF 2.1.0 bug candidate",
		"povs":                     "unsupported artifact type",
	} {
		if reasons[name] != want {
			t.Errorf("%s: reason = %q, want %q", name, reasons[name], want)
		}
	}
	if len(a.Artifacts) != 1 || string(a.Artifacts[0].Data) != "1" {
		t.Errorf("artifacts = %+v, want only the first povs/dup", a.Artifacts)
	}
}

func TestReadRejectsNonGzip(t *testing.T) {
	if _, err := Read(strings.NewReader(candidate)); err == nil {
		t.Fatal("want an error for a body that is not gzip")
	}
}

func TestReadBoundsRetainedBytes(t *testing.T) {
	var entries []entry
	body := strings.Repeat("a", poc.MaxFileBytes)
	for i := range MaxRetainedBytes/poc.MaxFileBytes + 1 {
		entries = append(entries, entry{name: "povs/" + strings.Repeat("p", i+1), body: body})
	}
	if _, err := Read(bytes.NewReader(build(t, entries...))); !errors.Is(err, ErrTooLarge) {
		t.Fatalf("err = %v, want ErrTooLarge", err)
	}
}

func TestLimitedReaderStopsAtLimit(t *testing.T) {
	l := &limitedReader{r: strings.NewReader("abcdef"), n: 4}
	buf := make([]byte, 10)
	n, _ := l.Read(buf)
	if n != 4 {
		t.Fatalf("read %d bytes, want 4", n)
	}
	if _, err := l.Read(buf); !errors.Is(err, ErrTooLarge) {
		t.Fatalf("err = %v, want ErrTooLarge", err)
	}
}
