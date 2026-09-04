package worker

import (
	"fmt"
	"os"
	"path/filepath"
)

// The per-scan workspace and the chat workspace are bind-mounted read-write
// into the agent's container, so once an invocation has run in a workspace,
// every entry below its root is the agent's to shape. A host write that opens
// a workspace path by name would follow a symlink the agent left there. These
// two helpers are how the host writes into a workspace an agent has already
// used: either the tree is emptied first, or the write goes through a root
// opened at the workspace so it cannot leave it.

// resetWorkspace makes workRoot an empty directory. Every host-side write
// that follows — the clone copy, the staged skill, context.json with the
// scan's API token, patch and diff inputs — then lands in a tree the agent
// has never seen. Writing into whatever the previous invocation left behind
// would let a link it planted turn any of those writes into a write elsewhere
// on the host.
func resetWorkspace(workRoot string) error {
	if err := os.RemoveAll(workRoot); err != nil {
		return err
	}
	return os.MkdirAll(workRoot, dirPerm)
}

// replaceWorkspaceFile writes data to the workspace-relative rel as a
// host-readable regular file by removing whatever entry sits there and
// creating its replacement exclusively, all through a root opened at workRoot. A symlink, hard link, or directory the
// agent left at rel, or at any directory between workRoot and rel, cannot
// redirect the write: os.Root refuses a path that resolves outside the
// workspace, and O_EXCL refuses to open anything that already exists, so a
// concurrent replant fails the write instead of being followed. workRoot
// itself is a host-owned path: the agent sees only the inside of the mount
// and cannot rename or replace the mount point.
func replaceWorkspaceFile(workRoot, rel string, data []byte) error {
	if !filepath.IsLocal(rel) {
		return fmt.Errorf("workspace file %q is not workspace-relative", rel)
	}
	root, err := os.OpenRoot(workRoot)
	if err != nil {
		return err
	}
	defer func() { _ = root.Close() }()
	if dir := filepath.Dir(rel); dir != "." {
		if err := root.MkdirAll(dir, dirPerm); err != nil {
			return err
		}
	}
	if err := root.RemoveAll(rel); err != nil {
		return err
	}
	f, err := root.OpenFile(rel, os.O_WRONLY|os.O_CREATE|os.O_EXCL, filePerm)
	if err != nil {
		return err
	}
	if _, err := f.Write(data); err != nil {
		_ = f.Close()
		return err
	}
	return f.Close()
}
