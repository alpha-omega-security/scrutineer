package poc

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func captureTestDir(t *testing.T, dir string) ([]File, error) {
	t.Helper()
	root, err := os.OpenRoot(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = root.Close() }()
	return Capture(root)
}

func writeTestFile(t *testing.T, dir, name string, data []byte) {
	t.Helper()
	path := filepath.Join(dir, name)
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestCapturePreservesBytes(t *testing.T) {
	dir := t.TempDir()
	payload := []byte{0, 255, '\r', '\n', '`'}
	writeTestFile(t, dir, "inputs/payload.bin", payload)
	writeTestFile(t, dir, "empty", nil)
	files, err := captureTestDir(t, dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(files) != 2 || files[0].Path != "empty" || files[1].Path != "inputs/payload.bin" || !bytes.Equal(files[1].Data, payload) {
		t.Fatalf("capture = %+v", files)
	}
	encoded, err := json.Marshal(files)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := Decode(encoded)
	if err != nil || !bytes.Equal(decoded[1].Data, payload) {
		t.Fatalf("stored bytes changed: %v", err)
	}
}

func TestCaptureRejectsLinks(t *testing.T) {
	for _, kind := range []string{"symlink", "directory-symlink", "hardlink"} {
		t.Run(kind, func(t *testing.T) {
			dir := t.TempDir()
			outside := t.TempDir()
			writeTestFile(t, outside, "secret", []byte("secret"))
			var err error
			switch kind {
			case "symlink":
				err = os.Symlink(filepath.Join(outside, "secret"), filepath.Join(dir, "link"))
			case "directory-symlink":
				err = os.Symlink(outside, filepath.Join(dir, "link"))
			case "hardlink":
				err = os.Link(filepath.Join(outside, "secret"), filepath.Join(dir, "link"))
			}
			if err != nil {
				t.Skipf("cannot create link: %v", err)
			}
			if files, err := captureTestDir(t, dir); err == nil || files != nil {
				t.Fatalf("accepted linked content: %+v, %v", files, err)
			}
		})
	}
}

func TestCaptureLimits(t *testing.T) {
	for _, kind := range []string{"file", "total", "count", "directories", "empty", "collision"} {
		t.Run(kind, func(t *testing.T) {
			dir := t.TempDir()
			switch kind {
			case "file":
				writeTestFile(t, dir, "large", make([]byte, MaxFileBytes+1))
			case "total":
				for i := 0; i <= MaxTotalBytes/MaxFileBytes; i++ {
					writeTestFile(t, dir, fmt.Sprintf("file-%d", i), make([]byte, MaxFileBytes))
				}
			case "count":
				for i := 0; i <= MaxFiles; i++ {
					writeTestFile(t, dir, fmt.Sprintf("file-%d", i), nil)
				}
			case "directories":
				for i := 0; i <= maxEntries; i++ {
					if err := os.Mkdir(filepath.Join(dir, fmt.Sprintf("dir-%d", i)), 0o700); err != nil {
						t.Fatal(err)
					}
				}
			case "collision":
				writeTestFile(t, dir, "FILE", nil)
				f, err := os.OpenFile(filepath.Join(dir, "file"), os.O_CREATE|os.O_EXCL, 0o600)
				if err != nil {
					t.Skip("filesystem is case insensitive")
				}
				_ = f.Close()
			}
			if files, err := captureTestDir(t, dir); err == nil || files != nil {
				t.Fatalf("accepted invalid capture: %+v, %v", files, err)
			}
		})
	}
}

func TestDecodeRejectsUnsafeOrCorruptFiles(t *testing.T) {
	for _, name := range []string{"../outside", "/absolute", "C:/drive", "dir\\file", "dir/../file", "file.", "dir//file", "CON", "aux.txt", "dir/LPT1"} {
		file := File{Path: name, Data: []byte("data"), SHA256: Digest([]byte("data"))}
		raw, err := json.Marshal([]File{file})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := Decode(raw); err == nil {
			t.Errorf("accepted %q", name)
		}
	}
	if _, err := Decode([]byte(`[{"path":"run.sh","data":"eA==","sha256":"wrong"}]`)); err == nil {
		t.Fatal("accepted corrupt file")
	}
}

func TestDecodeRejectsConflictingPaths(t *testing.T) {
	for _, names := range [][2]string{{"x.sh", "x.sh"}, {"x.sh", "X.sh"}, {"dir", "dir/x.sh"}, {"dir/x.sh", "dir"}} {
		t.Run(strings.Join(names[:], "+"), func(t *testing.T) {
			files := []File{
				{Path: names[0], SHA256: Digest(nil)},
				{Path: names[1], SHA256: Digest(nil)},
			}
			raw, err := json.Marshal(files)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := Decode(raw); err == nil {
				t.Fatal("accepted conflicting filenames")
			}
		})
	}
}
