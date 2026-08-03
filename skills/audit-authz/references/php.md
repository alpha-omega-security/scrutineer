# PHP Authorization Review Notes

## Laravel

Resolve route middleware, controller middleware, policies, gates, resource
authorization, and service-layer queries. `auth` establishes a principal; it
does not prove that principal may access an Eloquent model.

- Route `can` middleware and `$this->authorize()` can enforce a policy.
- `authorizeResource` maps resource controller actions to policy methods;
  confirm parameter names and custom actions.
- `Gate::before` and policy `before` methods can override later checks. Read
  their allow/deny behavior and role handling.
- Implicit route-model binding loads by identifier. Ownership still needs a
  scoped binding or policy decision.

Eloquent `$fillable` and `$guarded` restrict mass assignment only on APIs that
honor those settings. Direct property assignment, query-builder updates, and
unguarded modes need separate review. Report only sensitive writable fields
that cross a real privilege boundary.

## Symfony

Resolve firewall configuration, access-control rules, controller attributes,
voters, and service-layer decisions. Symfony `access_control` uses the first
matching rule, so ordering and `PUBLIC_ACCESS` entries matter. An
`IsGranted`/security expression can protect a controller or object, but custom
voters must be read to establish semantics.

Doctrine queries by global ID need an ownership/tenant predicate or a policy
check over the loaded entity. Serializer groups and validation rules constrain
shape, not authorization.

## Tokens And Sessions

Read `jwt.md` and determine the JWT/OAuth library and pinned version before
interpreting verification options. Session authentication does not replace
object authorization.
