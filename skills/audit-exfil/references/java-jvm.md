# Java/JVM Exfiltration Review Notes

## SSRF

Search for java.net.URL/URI, HttpClient, URLConnection, OkHttp, Apache
HttpClient, RestTemplate, WebClient, Feign, webhook callbacks, URL previewers,
and importers. Safe code should resolve caller input through a fixed service
map or strict allowlist and handle redirects consistently. Check localhost
aliases, IPv6, numeric IP encodings, DNS rebinding, proxy settings, and cloud
metadata addresses.

Concrete defaults:

- `java.net.http.HttpClient` uses `Redirect.NEVER` unless the builder selects a
  different redirect policy. That prevents redirect pivots but does not make
  the initial destination safe.
- `HttpURLConnection` has its own redirect settings, while Spring
  `RestTemplate`, `WebClient`, Feign, OkHttp, and Apache HttpClient behavior
  depends on request-factory/client configuration and version. Inspect the
  concrete client bean and Maven/Gradle lock or resolved dependency data.
- A `URI`/`URL` parse, regex hostname check, or allowlist applied before a
  redirect is not an IP-layer defense. Verify every resolved address and every
  followed hop, including custom DNS and proxy adapters.

## File Reads

Search for Files.read*, Path/Paths, FileInputStream, Resource loaders,
sendfile/resource controllers, ZipInputStream, TarArchiveInputStream, and
classpath or template lookup helpers. A safe path flow resolves against a
trusted root and checks canonical containment after normalization and symlink
resolution.

Specific behavior:

- `Path.normalize()` is lexical and does not check containment or resolve
  symlinks. `toRealPath()` resolves existing links; compare the resulting path
  against a trusted base with `Path.startsWith`.
- Spring `ClassPathResource` with a constant resource name is not arbitrary
  filesystem access. `FileSystemResource`, `UrlResource`, or a
  `ResourceLoader` location derived from request data can cross into `file:`
  or remote URL schemes and must be traced.
- `ZipInputStream` and `TarArchiveInputStream` expose entry names; they do not
  establish destination containment for application-written extraction loops.
  Require a normalized/canonical target check for every entry.

## XML And Document Parsing

Search for DocumentBuilderFactory, SAXParserFactory, XMLInputFactory,
TransformerFactory, SchemaFactory, JAXB, XPath, SVG, and office document
parsers. Confirm feature flags that disable DTDs, external general and
parameter entities, XInclude, and external schema/resource fetching.

JAXP defaults and required guards:

- JDK JAXP external-access properties historically default to `all`, allowing
  all protocols. For untrusted XML, set `XMLConstants.ACCESS_EXTERNAL_DTD`,
  `ACCESS_EXTERNAL_SCHEMA`, and `ACCESS_EXTERNAL_STYLESHEET` to the empty
  string on every factory that can load them.
- For DOM/SAX, disabling only one feature is incomplete. Prefer rejecting
  DOCTYPE and also disable external general entities, external parameter
  entities, external DTD loading, XInclude, and entity-reference expansion.
- For StAX, set both `XMLInputFactory.SUPPORT_DTD=false` and
  `isSupportingExternalEntities=false`. For transformers and schemas, inspect
  the matching external-access properties and any custom resolver.
- `FEATURE_SECURE_PROCESSING` imposes limits, but do not assume it alone blocks
  every external resource on every provider/JDK. Custom `EntityResolver`,
  `URIResolver`, or `LSResourceResolver` code can deliberately re-enable
  access and must be traced.

## Response Leaks

Search for Spring error attributes, whitelabel error pages, stack traces,
debug actuator endpoints, exception mappers, and logs or upstream responses
returned to tenants or unauthenticated callers.

Spring Boot's standard error response is not automatically a stack leak.
Inspect `server.error.include-stacktrace`, `include-message`, active profiles,
custom `ErrorAttributes`, and exception handlers. Jackson/JPA serialization of
an entity is only a finding when sensitive properties are included in the
actual response; DTOs, `@JsonIgnore`, views, and explicit projections are
mitigations.
