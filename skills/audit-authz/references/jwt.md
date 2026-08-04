# JWT Authorization Review Notes

Load this reference only when JWT headers or claims influence a principal,
tenant, role, permission, scope, ownership check, or protected resource. Token
parsing used solely for logging or display is not an authorization finding.

## Verification Before Authorization

Distinguish parsing from verification. Helpers named `decode`,
`ParseUnverified`, or equivalent intentionally expose attacker-controlled
header and payload data without proving a signature. Report that pattern only
when the resulting claims reach an authorization decision.

For verified tokens, establish all of the following from the actual call:

- the accepted algorithm or key family is fixed by trusted configuration, not
  selected from the token's `alg` header;
- a key ID selects from a trusted, bounded key set rather than a caller-chosen
  file, URL, embedded JWK, or tenant key without issuer binding;
- issuer, audience, subject/token purpose, expiry, and not-before checks match
  the application's trust domains;
- role, tenant, and scope claims are bound to the resource and operation they
  authorize;
- verification errors cannot fall through to an allow path.

Do not require a literal algorithm list when the pinned library and trusted key
object already enforce one safe algorithm family. Read wrappers and constants
before treating an omitted call-site option as a bypass.

## Version-Sensitive Cases

### Node `jsonwebtoken`

Versions before 9.0.0 are candidates for the 2022 verification advisories, but
package version alone is not a finding:

- CVE-2022-23540 requires `jwt.verify` with no explicit algorithms and a falsy
  verification key before an unsigned `alg: none` token can be accepted.
- CVE-2022-23539 concerns accepting invalid asymmetric key-type and algorithm
  combinations, such as a DSA key with `RS256`.
- Version 9.0.0 removed the implicit `none` fallback and validates asymmetric
  key-type/algorithm combinations. It does not automatically enforce
  application-specific issuer, audience, purpose, tenant, or scope.

Confirm the installed version from a lockfile and the complete key callback and
verify options. Sources:
https://github.com/auth0/node-jsonwebtoken/security/advisories/GHSA-qwph-4952-7xr6
and
https://github.com/auth0/node-jsonwebtoken/security/advisories/GHSA-8cf7-32gw-wr33.

### Python PyJWT

CVE-2022-29217 affects PyJWT before 2.4.0 when an application permits both
asymmetric and HMAC algorithms and supplies a public key in a format the older
blocklist did not recognize. A pinned asymmetric algorithm with an appropriate
public key is not this vulnerability. Current PyJWT documentation warns not to
derive the `algorithms` argument from attacker-controlled token data.

Confirm the package is PyJWT rather than another module imported as `jwt`.
Sources:
https://github.com/jpadilla/pyjwt/security/advisories/GHSA-ffqj-6fqr-9h24
and https://pyjwt.readthedocs.io/en/stable/api.html.

### Go `golang-jwt/jwt`

Use `WithValidMethods` when the trust context requires an explicit algorithm
allowlist; the v5 package documentation strongly recommends it. Also inspect
claim requirements: `exp` is optional unless `WithExpirationRequired` is used,
while `WithIssuer` and `WithAudience` require and validate their claims.

For v4, CVE-2024-51744 affects versions through 4.5.0 when caller error
handling accepts a token after checking only a combined non-signature error.
Version 4.5.1 changed dangerous signature failures to return immediately.
The vulnerable condition requires incorrect caller error handling; the
dependency version alone is not a finding.

Sources: https://pkg.go.dev/github.com/golang-jwt/jwt/v5 and
https://github.com/golang-jwt/jwt/security/advisories/GHSA-29wx-vh33-7x7r.

## Key Selection And Claim Binding

Treat `kid`, `jku`, `x5u`, and embedded `jwk` values as attacker-controlled
metadata until a trusted issuer configuration constrains them. A fixed JWKS
endpoint with HTTPS validation and lookup by `kid` can be safe. A callback that
fetches the token's `jku`, imports its embedded key, traverses a filesystem
path, or selects another tenant's key is a candidate.

A valid signature proves possession of an issuer's signing key; it does not by
itself prove:

- that this service is the intended audience;
- that an access token may be used as an ID or session token;
- that a role or scope applies to the selected tenant or object;
- that a token issued before a permission change remains authorized.

Report missing issuer, audience, type, or revocation binding only when the
application has multiple trust domains or a demonstrated cross-domain token
can reach a protected decision. Generic advice to validate every optional
claim is not a finding.

## False-Positive Controls

- Decoding before verification can be safe when only the untrusted `kid` is
  used to select a key from a trusted issuer's bounded key set and claims are
  consumed only after verification.
- `algorithms` may be supplied through a wrapper or trusted configuration.
- Separate verification paths with separate HMAC and asymmetric keys do not
  create key confusion merely because the application supports both families.
- Long-lived tokens without revocation are not automatically an authorization
  bypass; establish a product promise or permission-change path that requires
  invalidation.
- A missing audience is not exploitable when the issuer creates tokens for one
  service and no second token type or relying party crosses the boundary.
