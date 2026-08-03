# Java And JVM Authorization Review Notes

## Spring Security

Resolve both request-level and method-level security. A configured
`SecurityFilterChain` may protect routes globally, while `@PreAuthorize`,
`@Secured`, or `@RolesAllowed` can protect service methods. Method annotations
need method security to be enabled; annotation presence alone is not proof.

- Request matcher order matters: the first matching authorization rule is
  applied. Review broad `permitAll` matchers and path normalization.
- Authentication rules such as `authenticated()` do not enforce tenant,
  object, or operation-specific permissions.
- Proxy-based method security may not intercept self-invocation within the
  same object. Confirm the actual call path and proxy mode before reporting.
- Custom permission evaluators and repository methods can supply object-level
  checks. Read their implementation.

For JAX-RS or servlet applications, resolve filters, interceptors, security
constraints, `@RolesAllowed`, and deployment configuration. Confirm that the
annotation mechanism is enabled and attached to the runtime path.

## Data Access And Binding

JPA/Hibernate lookups by global ID need a later policy check or a query that
also binds tenant, owner, membership, or an allowed resource set. Hibernate
filters and multi-tenancy support can provide implicit scoping; verify they are
enabled for the relevant session and cannot be bypassed by native queries.

Spring/Jackson request binding validates shape only. Trace DTO-to-entity
mappers, BeanUtils/property-copy helpers, patch documents, and repository
updates for writable roles, tenant IDs, owners, security flags, prices, or
workflow state.

## JWT And Delegated Authorization

Read `jwt.md` for shared token-verification and claim-binding checks. Spring
resource-server validation can verify signatures while application code still
misuses claims. Confirm expected issuer and audience, token type/purpose,
scope-to-operation mapping, and tenant/resource binding. Do not report a claim
unless it drives an actual protected decision.
