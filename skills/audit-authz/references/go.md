# Go Authorization Review Notes

## HTTP And RPC Guard Attachment

`net/http` has no authorization default. Trace the concrete handler registered
with `Handle`, `HandleFunc`, or a router and every wrapper around it. A
middleware function that exists but is not used in the final registration
does nothing.

For chi, Gin, Echo, Fiber, and other routers, resolve group nesting, mounts,
middleware order, route-specific overrides, and recovery/error behavior. A
group-level authentication middleware does not automatically prove object or
tenant authorization.

For gRPC, check unary and stream interceptors, service registration, method
allowlists, and in-method policy calls. A unary interceptor does not protect
stream methods. Health/reflection services are usually intentionally public.

## Resource Queries

Trace path/query/body IDs through repository and database helpers. A query such
as `WHERE id = ?` on a tenant resource needs either:

- a principal-derived owner/tenant predicate in the same query;
- a membership/policy decision over the loaded object; or
- a verified repository abstraction that always supplies the scope.

Do not report global lookup helpers used only for public objects or trusted
internal jobs. Confirm the reachable caller and principal boundary.

## Struct Binding And Updates

JSON/form binding into a struct is not itself mass assignment. Establish that
the bound struct, map, patch, or reflection-based copier reaches persistence or
a privileged operation with attacker-controlled role, owner, tenant,
permission, security, billing, or workflow fields.

Prefer checking whether the handler builds an explicit update map or overwrites
server-owned fields after decoding. Validation tags constrain value shape, not
field-level authority.

## JWT And Context Principals

Read `jwt.md` and determine the JWT package and version from go.mod/go.sum
before evaluating parser options or error handling. Context values are trusted
only if every reachable registration path installs the middleware that creates
them and rejects invalid input.
