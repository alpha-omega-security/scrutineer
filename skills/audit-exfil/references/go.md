# Go Exfiltration Review Notes

## SSRF

Search for http.Get, http.Client.Do, Request construction, reverse proxies,
webhook callbacks, importers, URL previewers, and custom transports. Safe code
should map user input to fixed destinations or enforce host/IP/scheme allowlists
before the request and after redirects. Inspect url.Parse behavior, proxy use,
DialContext hooks, DNS rebinding, localhost aliases, IPv6, and cloud metadata
addresses.

Concrete defaults:

- A zero-value `http.Client` follows redirects and stops after 10 consecutive
  requests. `CheckRedirect` must reject or revalidate each destination; a
  check performed only before `Do` is insufficient.
- The standard `net/http` transport supports HTTP(S), not `file:` or
  `gopher:`. Do not claim alternate-scheme SSRF unless a custom
  `RoundTripper`, proxy, or wrapper adds it.
- `http.DefaultTransport` consults proxy environment settings. Inspect custom
  `Proxy`, `DialContext`, resolver, and transport wrappers because they can
  change both destination enforcement and DNS-rebinding analysis.

## File Reads

Search for os.Open, os.ReadFile, http.ServeFile, http.FileServer,
filepath.Join/Clean/Abs/EvalSymlinks, embed/static wrappers, archive/zip,
archive/tar, and object-store key construction. Require canonical containment
under a trusted root after normalization and symlink resolution.

Standard-library behavior and false positives:

- `http.ServeFile` rejects `..` in `r.URL.Path`, but it serves the separate
  `name` argument supplied by the application. Go's documentation explicitly
  requires sanitizing a user-derived `name`; the URL-path check does not make
  `ServeFile(w, r, userPath)` safe.
- `http.FileServer(http.Dir(fixedRoot))` prevents lexical URL traversal, but
  `http.Dir` follows symlinks outside the root and serves dotfiles such as
  `.git` and `.htpasswd`. It is not a chroot: inspect root contents, who can
  create symlinks, and whether sensitive dotfiles are reachable.
- `fs.Sub` restricts names to a subtree but inherits the underlying
  filesystem's symlink behavior. In particular, `fs.Sub(os.DirFS(root), dir)`
  can follow a symlink outside that subtree. Treat it as a containment defense
  only when the underlying filesystem cannot escape (for example, a vetted
  immutable `embed.FS`) or the application separately rejects unsafe links.
- `filepath.Clean`, `Abs`, and `IsLocal` are lexical checks. For existing
  filesystem targets that must remain under a root, account for symlinks with
  `EvalSymlinks`/opened-file verification and compare using path components,
  not a raw string prefix.
- `archive/zip` exposes slash-separated entry names; custom extraction code
  still has to join and enforce destination containment per entry. Do not
  report code that only reads archive members in memory without writing or
  disclosing a sensitive file.

## XML And Document Parsing

The standard encoding/xml package does not fetch external entities by itself,
but wrappers, custom Entity maps, template expansion, SVG/office parsers, or
cgo-backed XML libraries can. Report only when untrusted input can trigger a
file or network read or sensitive expansion.

`xml.Decoder.Entity` is an application-supplied map of replacements; it does
not turn DTD system identifiers into file/network fetches. A bare
`xml.Unmarshal`/`Decoder.Decode` is therefore a false positive for XXE
exfiltration. Focus on custom entity/resolver code and non-standard or
cgo-backed parsers.

## Response Leaks

Search for http.Error with raw internal errors, panic recovery that writes stack
traces, httputil.DumpRequest/Response, debug endpoints, pprof exposure, and log
or diagnostic APIs available to lower-privileged callers.

`http.Error(w, err.Error(), 500)` discloses the supplied text; a generic
constant is safe. `net/http/pprof` is only exposed when its handlers are
registered on a reachable mux (commonly through a blank import plus
`DefaultServeMux`). Server-side logs are not an exfiltration finding unless a
less-privileged actor can retrieve them or they cross a tenant/third-party log
boundary.
