package poc

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"os"
	"regexp"
	"slices"
	"strings"
)

const (
	MaxFiles        = 64
	MaxFileBytes    = 1 << 20
	MaxTotalBytes   = 2 << 20
	maxEntries      = 128
	maxPathBytes    = 256
	maxEncodedBytes = 3 << 20
)

var pathChars = regexp.MustCompile(`^[a-zA-Z0-9_./-]+$`)
var deviceName = regexp.MustCompile(`(?i)^(CON|PRN|AUX|NUL|COM[1-9]|LPT[1-9])(?:\.|$)`)

type File struct {
	Path       string `json:"path"`
	Data       []byte `json:"data"`
	SHA256     string `json:"sha256"`
	Executable bool   `json:"executable,omitempty"`
}

func ValidPath(name string) bool {
	if len(name) > maxPathBytes || !fs.ValidPath(name) || name == "." || !pathChars.MatchString(name) {
		return false
	}
	for _, part := range strings.Split(name, "/") {
		if strings.HasSuffix(part, ".") || deviceName.MatchString(part) {
			return false
		}
	}
	return true
}

func Digest(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

func Validate(files []File) error {
	if len(files) == 0 || len(files) > MaxFiles {
		return fmt.Errorf("PoC must contain 1 to %d files", MaxFiles)
	}
	seen := map[string]bool{}
	total := 0
	for _, file := range files {
		if !ValidPath(file.Path) {
			return fmt.Errorf("invalid PoC path %q", file.Path)
		}
		name := strings.ToLower(file.Path)
		for other := range seen {
			if name == other || strings.HasPrefix(name, other+"/") || strings.HasPrefix(other, name+"/") {
				return fmt.Errorf("conflicting PoC path %q", file.Path)
			}
		}
		seen[name] = true
		total += len(file.Data)
		if len(file.Data) > MaxFileBytes || total > MaxTotalBytes {
			return fmt.Errorf("PoC exceeds file or total byte limit")
		}
		if file.SHA256 != Digest(file.Data) {
			return fmt.Errorf("PoC checksum mismatch for %q", file.Path)
		}
	}
	return nil
}

func Decode(data []byte) ([]File, error) {
	if len(data) > maxEncodedBytes {
		return nil, fmt.Errorf("encoded PoC exceeds byte limit")
	}
	var files []File
	if err := json.Unmarshal(data, &files); err != nil {
		return nil, err
	}
	if err := Validate(files); err != nil {
		return nil, err
	}
	return files, nil
}

// OpenDir refuses symlinks at each directory boundary, including links back
// into the workspace where context.json contains the scan's API token.
func OpenDir(parent *os.Root, name string) (*os.Root, error) {
	before, err := parent.Lstat(name)
	if err != nil {
		return nil, err
	}
	if !before.IsDir() {
		return nil, fmt.Errorf("PoC directory %q is not a directory", name)
	}
	root, err := parent.OpenRoot(name)
	if err != nil {
		return nil, err
	}
	after, err := root.Stat(".")
	if err != nil || !os.SameFile(before, after) {
		_ = root.Close()
		return nil, fmt.Errorf("PoC directory %q changed while opening", name)
	}
	return root, nil
}

func Capture(root *os.Root) ([]File, error) {
	var files []File
	entries, total := 0, 0
	if err := captureDir(root, "", &files, &entries, &total); err != nil {
		return nil, err
	}
	slices.SortFunc(files, func(a, b File) int { return strings.Compare(a.Path, b.Path) })
	if err := Validate(files); err != nil {
		return nil, err
	}
	return files, nil
}

func captureDir(root *os.Root, prefix string, files *[]File, visited, total *int) error {
	dir, err := root.Open(".")
	if err != nil {
		return err
	}
	defer func() { _ = dir.Close() }()
	entries, err := dir.ReadDir(maxEntries + 1)
	if err != nil && err != io.EOF {
		return err
	}
	*visited += len(entries)
	if *visited > maxEntries {
		return fmt.Errorf("PoC exceeds directory entry limit")
	}
	for _, entry := range entries {
		name := prefix + entry.Name()
		if !ValidPath(name) {
			return fmt.Errorf("invalid PoC path %q", name)
		}
		if entry.IsDir() {
			child, err := OpenDir(root, entry.Name())
			if err != nil {
				return err
			}
			err = captureDir(child, name+"/", files, visited, total)
			_ = child.Close()
			if err != nil {
				return err
			}
			continue
		}
		if len(*files) >= MaxFiles {
			return fmt.Errorf("PoC exceeds %d files", MaxFiles)
		}
		file, err := readFile(root, entry.Name())
		if err != nil {
			return err
		}
		file.Path = name
		*total += len(file.Data)
		if *total > MaxTotalBytes {
			return fmt.Errorf("PoC exceeds %d total bytes", MaxTotalBytes)
		}
		*files = append(*files, file)
	}
	return nil
}

func readFile(root *os.Root, name string) (File, error) {
	before, err := root.Lstat(name)
	if err != nil {
		return File{}, err
	}
	if !before.Mode().IsRegular() || before.Size() > MaxFileBytes {
		return File{}, fmt.Errorf("PoC file %q must be a regular file of at most %d bytes", name, MaxFileBytes)
	}
	f, err := root.OpenFile(name, os.O_RDONLY|readFlags, 0)
	if err != nil {
		return File{}, err
	}
	defer func() { _ = f.Close() }()
	after, err := f.Stat()
	if err != nil || !after.Mode().IsRegular() || !os.SameFile(before, after) || !singleLink(f, after) {
		return File{}, fmt.Errorf("PoC file %q changed or is linked", name)
	}
	data, err := io.ReadAll(io.LimitReader(f, MaxFileBytes+1))
	if err != nil {
		return File{}, err
	}
	final, err := f.Stat()
	if err != nil || len(data) > MaxFileBytes || int64(len(data)) != final.Size() || !after.ModTime().Equal(final.ModTime()) {
		return File{}, fmt.Errorf("PoC file %q changed or exceeded the byte limit", name)
	}
	return File{Path: name, Data: data, SHA256: Digest(data), Executable: after.Mode().Perm()&0o111 != 0}, nil
}
