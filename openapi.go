// Package scrutineer embeds repository-root assets that ship inside the
// binary. It holds no logic; //go:embed cannot reach a parent directory, so
// the OpenAPI document at the repo root needs a package alongside it.
package scrutineer

import _ "embed"

// OpenAPISpec is openapi.yaml, served at GET /api/openapi.yaml so a skill or
// an external tool can read the API surface from a running server without a
// checkout.
//
//go:embed openapi.yaml
var OpenAPISpec []byte
