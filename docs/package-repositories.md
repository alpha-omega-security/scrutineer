# Package repositories

`package_repositories` points the package managers inside scan containers at an
existing package repository or caching proxy (Artifactory, Nexus or
[git-pkgs/proxy](https://github.com/git-pkgs/proxy)). Scrutineer sets each
package manager's native environment variables or, where a package manager
needs it, mounts a generated config file read-only outside the workspace, so
nothing is written into the scanned workspace.

```yaml
package_repositories:
  git_pkgs_proxy: https://pkgs.example.com
  # Optional per-ecosystem override.
  npm: https://artifactory.example.com/api/npm/npm/
```

## Settings per ecosystem

| Key | Native setting | git-pkgs/proxy path |
| --- | --- | --- |
| `npm` | `npm_config_registry`, `YARN_NPM_REGISTRY_SERVER`, `BUN_CONFIG_REGISTRY` | `/npm/` |
| `pypi` | `PIP_INDEX_URL`, `UV_DEFAULT_INDEX` | `/pypi/simple/` |
| `go` | `GOPROXY` | `/go` |
| `pub` | `PUB_HOSTED_URL` | `/pub` |
| `rubygems` | `BUNDLE_USER_CONFIG` pointing at a mounted Bundler config | `/gem/` |
| `maven` | `MAVEN_ARGS=--global-settings` pointing at a mounted Maven settings file | `/maven/` |
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

For `rubygems`, Scrutineer writes a Bundler config file holding the
`mirror.https://rubygems.org/` setting to `package-repositories/bundler/config`
under the data directory. It mounts that directory read-only at
`/package-repositories` and sets `BUNDLE_USER_CONFIG` to the file. A file is
used instead of an environment variable because the mirror key contains `:` and
`/`, which dash (`/bin/sh` on Debian) drops from the environment, so Bundler
run through `sh -c`, a Makefile or a `#!/bin/sh` script would lose the mirror.

The mirror applies only to the default `https://rubygems.org` source, so a
Gemfile that points at another source is unaffected. Scrutineer does not enable
Bundler's mirror fallback, so a failed mirror is not retried against
rubygems.org. A scanned repository's own `.bundle/config` outranks the user
config, so it can override the mirror itself as well as set `fallback_timeout`.
Plain `gem install` is not covered.

For `maven`, Scrutineer writes a Maven settings file with a mirror of `central`
to `package-repositories/maven/settings.xml` under the data directory. It mounts
that directory read-only at `/package-repositories` and sets `MAVEN_ARGS` so
Maven reads the file as global settings. Global settings are used rather than
user settings so a project's own `-s` file or `~/.m2/settings.xml` still applies
on top. A mirror of `central` there wins over Scrutineer's. Repositories a
`pom.xml` declares other than `central` are not redirected.

The file replaces the image's own global settings, so a custom profile image
that configures Maven in `conf/settings.xml` loses that. The bundled java
profile sets its local repository through `MAVEN_OPTS` for this reason. Maven
older than 3.9, for example one pinned by a Maven wrapper, ignores `MAVEN_ARGS`.
Gradle is not covered.

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
- contains a quote, backslash or whitespace, which must be percent-encoded
  because the URL is written verbatim into generated config files
- uses `localhost`, a `.localhost` name or the container host gateway
- is an IP literal that is loopback, private, link-local or unspecified

The scan egress proxy blocks private and loopback addresses, so those
repositories could never be reached. Credentials must stay out of config URLs.

## Not yet supported

- Credentials
- Custom CA certificates
- Cargo, Gradle, NuGet and Composer
- The `gem` command outside Bundler
- Internally hosted repositories on private addresses
- The `--no-container` runner (a warning is logged)
