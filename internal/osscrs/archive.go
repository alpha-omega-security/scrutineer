// Package osscrs reads the gzip tarball `oss-crs archive` writes for one
// run: bug-candidates/ (SARIF 2.1.0), povs/, patches/ and reports/ beside the
// fuzzing seeds/ and generated harnesses/.
package osscrs

import (
	"archive/tar"
	"compress/gzip"
	"errors"
	"fmt"
	"io"
	"path"
	"strings"

	"scrutineer/internal/ingest"
	"scrutineer/internal/poc"
)

const (
	// A seed corpus routinely holds thousands of files, so the entry and
	// expanded-size bounds are sized for skipping it, not for retaining it.
	MaxEntries       = 100_000
	MaxExpandedBytes = 2 << 30
	// MaxCandidateBytes bounds one SARIF file, MaxRetainedBytes everything
	// kept in memory across the archive.
	MaxCandidateBytes = 16 << 20
	MaxRetainedBytes  = 64 << 20
)

// Artifact kinds, named after the libCRS data types.
const (
	KindPoV    = "pov"
	KindPatch  = "patch"
	KindReport = "report"
)

var artifactDirs = map[string]string{"povs": KindPoV, "patches": KindPatch, "reports": KindReport}

const candidateDir = "bug-candidates"

type Artifact struct {
	Kind   string
	Path   string
	Data   []byte
	SHA256 string
}

// Skipped names an entry, or a whole unsupported directory with its file
// count, that the archive carried and the import did not keep.
type Skipped struct {
	Path   string `json:"path"`
	Files  int    `json:"files"`
	Reason string `json:"reason"`
}

type Archive struct {
	Candidates []ingest.Result
	Artifacts  []Artifact
	Skipped    []Skipped
}

var ErrTooLarge = errors.New("oss-crs archive exceeds its size or entry limits")

// Read streams the archive, so the skipped directories are decompressed but
// never buffered.
func Read(r io.Reader) (Archive, error) {
	zr, err := gzip.NewReader(r)
	if err != nil {
		return Archive{}, fmt.Errorf("oss-crs archive: %w", err)
	}
	defer func() { _ = zr.Close() }()
	tr := tar.NewReader(&limitedReader{r: zr, n: MaxExpandedBytes})
	rd := reader{seen: map[string]bool{}, unsupported: map[string]int{}}
	for entries := 0; ; entries++ {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return Archive{}, fmt.Errorf("oss-crs archive: %w", err)
		}
		if entries >= MaxEntries {
			return Archive{}, ErrTooLarge
		}
		if err := rd.entry(tr, hdr); err != nil {
			return Archive{}, err
		}
	}
	for _, dir := range rd.unsupportedOrder {
		rd.a.Skipped = append(rd.a.Skipped, Skipped{Path: dir + "/", Files: rd.unsupported[dir], Reason: "unsupported artifact type"})
	}
	return rd.a, nil
}

type reader struct {
	a                Archive
	seen             map[string]bool
	unsupported      map[string]int
	unsupportedOrder []string
	retained         int
}

func (rd *reader) entry(tr *tar.Reader, hdr *tar.Header) error {
	if hdr.Typeflag == tar.TypeDir {
		return nil
	}
	name := strings.TrimPrefix(hdr.Name, "./")
	if !poc.ValidPath(name) {
		rd.a.skip(name, "unsafe path")
		return nil
	}
	dir, _, inDir := strings.Cut(name, "/")
	if !inDir {
		rd.a.skip(name, "unsupported artifact type")
		return nil
	}
	kind, isArtifact := artifactDirs[dir]
	if !isArtifact && dir != candidateDir {
		if rd.unsupported[dir] == 0 {
			rd.unsupportedOrder = append(rd.unsupportedOrder, dir)
		}
		rd.unsupported[dir]++
		return nil
	}
	if hdr.Typeflag != tar.TypeReg {
		rd.a.skip(name, "not a regular file")
		return nil
	}
	if rd.seen[name] {
		rd.a.skip(name, "duplicate path")
		return nil
	}
	rd.seen[name] = true
	limit := int64(poc.MaxFileBytes)
	if !isArtifact {
		limit = MaxCandidateBytes
	}
	if hdr.Size > limit {
		rd.a.skip(name, fmt.Sprintf("exceeds %d bytes", limit))
		return nil
	}
	if rd.retained += int(hdr.Size); rd.retained > MaxRetainedBytes {
		return ErrTooLarge
	}
	data, err := io.ReadAll(tr)
	if err != nil {
		return fmt.Errorf("oss-crs archive %s: %w", name, err)
	}
	if isArtifact {
		rd.a.Artifacts = append(rd.a.Artifacts, Artifact{Kind: kind, Path: name, Data: data, SHA256: poc.Digest(data)})
		return nil
	}
	results, format, err := ingest.Parse(data)
	if err != nil || format != ingest.FormatSARIF {
		rd.a.skip(name, "not a SARIF 2.1.0 bug candidate")
		return nil
	}
	for i := range results {
		for j := range results[i].Findings {
			results[i].Findings[j].Attachments = normaliseAttachments(results[i].Findings[j].Attachments)
		}
	}
	rd.a.Candidates = append(rd.a.Candidates, results...)
	return nil
}

func (a *Archive) skip(name, reason string) {
	a.Skipped = append(a.Skipped, Skipped{Path: name, Files: 1, Reason: reason})
}

// normaliseAttachments maps a result's attachment URIs onto archive paths, so
// "./povs/x" and "povs/x" name the same entry.
func normaliseAttachments(uris []string) []string {
	out := make([]string, 0, len(uris))
	for _, uri := range uris {
		out = append(out, path.Clean(strings.TrimPrefix(uri, "./")))
	}
	return out
}

type limitedReader struct {
	r io.Reader
	n int64
}

func (l *limitedReader) Read(p []byte) (int, error) {
	if l.n <= 0 {
		return 0, ErrTooLarge
	}
	if int64(len(p)) > l.n {
		p = p[:l.n]
	}
	n, err := l.r.Read(p)
	l.n -= int64(n)
	return n, err
}
