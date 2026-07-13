// Package bundledskills exposes the scan skills shipped with the Scrutineer
// binary. The application materialises this read-only filesystem beneath its
// data directory at startup so the existing disk-backed skill loader and
// auxiliary-file staging paths keep working unchanged.
package bundledskills

import "embed"

// FS contains every bundled skill directory. Root-level Go source is also
// matched by the embed pattern, but the materialiser deliberately extracts
// only files below a top-level skill directory.
//
//go:embed all:*
var FS embed.FS
