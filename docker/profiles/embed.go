// Package bundledprofiles exposes the per-ecosystem runner profiles shipped
// with the Scrutineer binary. The application materialises this filesystem
// beneath its data directory when it is not running from a source checkout.
package bundledprofiles

import "embed"

// FS contains every bundled profile directory. The root-level Go source is
// matched too, but the shared materialiser extracts only nested profile files.
//
//go:embed all:*
var FS embed.FS
