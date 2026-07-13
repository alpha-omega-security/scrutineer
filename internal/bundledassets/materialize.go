// Package bundledassets materialises read-only files embedded in the
// Scrutineer binary into content-addressed directories below the data root.
// Disk-backed consumers can then keep using ordinary paths without requiring
// the source checkout to be present at runtime.
package bundledassets

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const (
	bundleDirPerm    = 0o700
	bundleFilePerm   = 0o600
	bundleScriptPerm = 0o700
	staleExtractAge  = 24 * time.Hour
)

type asset struct {
	path string
	data []byte
}

// Materialize writes fsys to a content-addressed directory below
// dataDir/cacheName and returns that directory and its content hash. Existing
// trees are reused, so an ordinary restart performs no writes after hashing
// the embedded assets. Extraction goes through an adjacent temporary directory
// and an atomic rename so a crash cannot leave a partial bundle at the final
// path.
//
// Only files below a top-level directory are included. This excludes the Go
// source file required to host //go:embed while including all nested runtime
// assets. Files under a scripts directory are owner-executable; every other
// file and all directories remain owner-only.
func Materialize(fsys fs.FS, dataDir, cacheName string) (dir, hash string, err error) {
	assets, hash, err := embeddedAssets(fsys)
	if err != nil {
		return "", "", err
	}
	if len(assets) == 0 {
		return "", "", fmt.Errorf("%s: embedded filesystem contains no runtime assets", cacheName)
	}

	root := filepath.Join(dataDir, cacheName)
	if err := os.MkdirAll(root, bundleDirPerm); err != nil {
		return "", "", fmt.Errorf("create %s root: %w", cacheName, err)
	}
	_ = os.Chmod(root, bundleDirPerm)
	cleanupStaleExtractions(root, time.Now())

	dst := filepath.Join(root, hash)
	if info, statErr := os.Stat(dst); statErr == nil && info.IsDir() {
		return dst, hash, nil
	} else if statErr != nil && !errors.Is(statErr, os.ErrNotExist) {
		return "", "", fmt.Errorf("stat %s: %w", cacheName, statErr)
	}

	tmp, err := os.MkdirTemp(root, ".extract-")
	if err != nil {
		return "", "", fmt.Errorf("create %s temporary directory: %w", cacheName, err)
	}
	defer func() { _ = os.RemoveAll(tmp) }()
	_ = os.Chmod(tmp, bundleDirPerm)

	for _, asset := range assets {
		target := filepath.Join(tmp, filepath.FromSlash(asset.path))
		if err := os.MkdirAll(filepath.Dir(target), bundleDirPerm); err != nil {
			return "", "", fmt.Errorf("create runtime asset directory for %s: %w", asset.path, err)
		}
		perm := fs.FileMode(bundleFilePerm)
		if isScriptAsset(asset.path) {
			perm = bundleScriptPerm
		}
		if err := os.WriteFile(target, asset.data, perm); err != nil {
			return "", "", fmt.Errorf("write runtime asset %s: %w", asset.path, err)
		}
	}

	if err := os.Rename(tmp, dst); err != nil {
		// Another process may have materialised the same immutable tree while
		// this one was extracting it. Treat that as success once the complete
		// destination is visible; every writer computed the same content hash.
		if info, statErr := os.Stat(dst); statErr == nil && info.IsDir() {
			return dst, hash, nil
		}
		return "", "", fmt.Errorf("install %s: %w", cacheName, err)
	}
	return dst, hash, nil
}

// cleanupStaleExtractions removes temporary trees left behind when a process
// terminates before its deferred cleanup runs. Recent trees are left alone
// because another Scrutineer process may still be materialising the bundle.
// Content-addressed bundle directories are deliberately retained: skill rows
// can continue to reference auxiliary files from an older bundled version.
func cleanupStaleExtractions(root string, now time.Time) {
	entries, err := os.ReadDir(root)
	if err != nil {
		return
	}
	cutoff := now.Add(-staleExtractAge)
	for _, entry := range entries {
		if !entry.IsDir() || !strings.HasPrefix(entry.Name(), ".extract-") {
			continue
		}
		info, err := entry.Info()
		if err != nil || !info.ModTime().Before(cutoff) {
			continue
		}
		_ = os.RemoveAll(filepath.Join(root, entry.Name()))
	}
}

func embeddedAssets(fsys fs.FS) ([]asset, string, error) {
	assets := make([]asset, 0)
	h := sha256.New()
	writeHashField := func(data []byte) {
		var length [8]byte
		binary.BigEndian.PutUint64(length[:], uint64(len(data)))
		_, _ = h.Write(length[:])
		_, _ = h.Write(data)
	}
	err := fs.WalkDir(fsys, ".", func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.IsDir() || !strings.Contains(path, "/") {
			return nil
		}
		if !entry.Type().IsRegular() {
			return fmt.Errorf("unsupported non-regular embedded asset %s", path)
		}
		data, err := fs.ReadFile(fsys, path)
		if err != nil {
			return err
		}
		assets = append(assets, asset{path: path, data: data})
		writeHashField([]byte(path))
		writeHashField(data)
		return nil
	})
	if err != nil {
		return nil, "", fmt.Errorf("walk embedded assets: %w", err)
	}
	return assets, hex.EncodeToString(h.Sum(nil)), nil
}

func isScriptAsset(path string) bool {
	return strings.Contains("/"+path+"/", "/scripts/")
}
