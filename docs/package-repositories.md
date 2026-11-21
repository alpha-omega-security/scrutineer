# Package repositories

`package_repositories` points the package managers inside scan containers at an
existing package repository or caching proxy (Artifactory, Nexus or
[git-pkgs/proxy](https://github.com/git-pkgs/proxy)). Scrutineer sets each
package manager's native environment variables, so no files are written into
the scanned workspace.

```yaml
package_repositories:
  git_pkgs_proxy: https://pkgs.example.com
  # Optional per-ecosystem override.
  npm: https://artifactory.example.com/api/npm/npm/
```

## Environment set per ecosystem

| Key | Environment variables | git-pkgs/proxy path |
| --- | --- | --- |
| `npm` | `npm_config_registry`, `YARN_NPM_REGISTRY_SERVER`, `BUN_CONFIG_REGISTRY` | `/npm/` |
| `pypi` | `PIP_INDEX_URL`, `UV_DEFAULT_INDEX` | `/pypi/simple/` |
| `go` | `GOPROXY` | `/go` |
| `pub` | `PUB_HOSTED_URL` | `/pub` |
| `rubygems` | `BUNDLE_MIRROR__HTTPS://RUBYGEMS__ORG/` | `/gem/` |
| `hex` | `HEX_MIRROR` | none, set `hex:` explicitly |

An explicit per-ecosystem key always beats the `git_pkgs_proxy` preset. A
trailing slash on the proxy base URL is ignored.

The preset leaves Hex alone. When git-pkgs/proxy filters a Hex release for
cooldown it re-encodes the signed payload without a signature, so `mix deps.get`
fails origin verification for any package with a release inside the cooldown
window. Set `hex:` only for a mirror that keeps releases signed.

Go gets the bare URL as `GOPROXY`, with no `,direct` suffix, so a miss never
silently falls back to the public upstream. Checksum verification through
`GOSUMDB` is unchanged.

The `rubygems` key sets Bundler's mirror for the default `https://rubygems.org`
source, so a Gemfile that points at another source is unaffected. Bundler does
not fall back to rubygems.org when the mirror fails. Plain `gem install` has no
environment variable for this and is not covered.

## Egress

Without `--hardened` the repository hosts are added to the egress allowlist
automatically. Under `--hardened` they are not. Grant `host:port` for each
repository with `egress_policies` or `scan_egress_policies` instead, using 443
when the URL has no port (see [egress-policies.md](egress-policies.md)).
Scrutineer logs the exact pairs at startup.

## Validation

Scrutineer rejects the config at startup when a URL:

- is not an absolute `https` URL
- contains credentials, a query string or a fragment
- contains `,` or `|`, which `GOPROXY` reads as list separators
- uses `localhost`, a `.localhost` name or the container host gateway
- is an IP literal that is loopback, private, link-local or unspecified

The scan egress proxy blocks private and loopback addresses, so those
repositories could never be reached. Credentials must stay out of config URLs.

## Not yet supported

- Credentials
- Custom CA certificates
- Cargo, Maven/Gradle, NuGet and Composer, which need configuration files rather
  than environment variables
- The `gem` command outside Bundler
- Internally hosted repositories on private addresses
- The `--no-container` runner (a warning is logged)
