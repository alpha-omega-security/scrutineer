# GraphQL Authorization Review Notes

GraphQL authorization must cover every resolver path that reaches protected
data or an operation. Schema visibility, disabled introspection, opaque/global
IDs, and the absence of a field in the UI are not access controls.

## Resolver Coverage

Trace:

- root query and mutation resolvers;
- field resolvers that can reveal nested protected objects;
- node/global-ID lookups and type resolvers;
- list, search, connection, export, batch, and data-loader paths;
- subscriptions at both subscribe time and event-delivery time;
- federation entity resolvers and cross-service identity propagation.

A parent resolver's check does not automatically protect a child field if that
field can also be reached through another root or entity resolver. Conversely,
a framework plugin or resolver wrapper may apply a global policy; resolve it
before reporting a missing local check.

## Directives And Middleware

An authorization directive in the schema has no effect unless runtime code
implements and installs it. Inspect schema transforms, plugins, resolver
wrappers, and directive-name aliases. Fail closed when a directive, role,
resource, or policy lookup is unknown.

For NestJS GraphQL guards, verify that the guard converts the execution context
with the GraphQL adapter and reads the actual request principal. HTTP-only
extraction can yield an empty principal or bypass branch.

For graphql-ruby, inspect class ancestry, `authorized?`, field/type
authorization hooks, visibility profiles, and resolver policies. Visibility
can hide schema elements but is not a substitute for object authorization.

## Object And Tenant Binding

Relay/global IDs are identifiers, not authorization tokens. Decode paths must
still bind the loaded object to the actor's owner, tenant, membership, or
permission set. Data loaders and caches must include authorization-relevant
tenant/principal context in their key or ensure they cannot return a row loaded
for another actor. A loader instantiated separately for each request is a
common safe design because its cache cannot cross principals; confirm its
lifetime before requiring principal data in every key.

List/connection resolvers need scoped querysets; checking each item only on a
detail resolver does not protect a list. Mutations must authorize the exact
object later changed, including nested relation IDs supplied in input.

Aliases, fragments, batching, and persisted queries normally reuse the same
resolver authorization. Do not report them without a concrete bypass of the
effective guard.
