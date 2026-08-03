# Node Authorization Review Notes

## Middleware Frameworks

Express, Koa, Fastify, Hono, and Elysia are allow-by-default unless middleware
or hooks cover a route. Resolve the actual mount path and registration order.

- Express middleware applies in registration order. `app.use(auth)` added
  after a route does not protect that earlier route. Path-scoped middleware
  protects only matching mounts.
- Fastify guards commonly use `onRequest`, `preValidation`, or `preHandler`
  hooks. Plugin encapsulation means a hook in one registration scope may not
  protect a sibling plugin.
- Hono/Elysia guard and middleware builders are path- and order-sensitive.
  Read the composed application, not only the route file.
- Koa middleware must reject or stop the chain on failure. Exception branches
  that set an empty principal and still call the next handler are fail-open.

An upstream reverse proxy can be the effective guard. Confirm deployment
reachability and whether the application replaces or verifies identity headers
before treating `x-user-id`, `x-roles`, or similar headers as trusted.

## NestJS, Next.js, And tRPC

NestJS guards can be global (`APP_GUARD`), controller-level, or route-level.
Resolve `@UseGuards`, custom `@Public` metadata, reflector logic, and guard
ordering. A roles decorator has no effect unless a guard reads it. For GraphQL
controllers, confirm the guard extracts the GraphQL context rather than an HTTP
request shape that is absent at runtime.

Next.js middleware or Proxy can provide a coarse gate, but Route Handlers and
Server Actions that read or mutate protected data should make their own
authorization decision. A page or layout check does not prove a directly
invoked Server Action is authorized. Inspect middleware matchers and the
installed Next.js version before making a version-sensitive bypass claim.

tRPC distinguishes public and protected procedures through builders and
middleware. Follow aliases and router merges until the final procedure
builder is known; a security-sounding variable name is not evidence.

## Data Access And Assignment

For Prisma, Sequelize, Mongoose, TypeORM, and repository wrappers, trace whether
request-derived IDs are combined with the principal's owner/tenant predicate.
`findUnique({where:{id}})` on a tenant resource is a candidate, not a finding,
until all service-layer policy checks are read.

Spreading `req.body`, input objects, or DTO instances into `create`/`update`
can expose role, tenant, owner, status, or permission fields. Zod/Joi/class
validator schemas are effective only when they omit or reject those fields and
the parsed result, rather than the original body, reaches persistence.

## JWT Claims

Read `jwt.md` for algorithm, key-selection, claim-validation, and version
checks. Distinguish `decode` from cryptographic verification and identify the
actual package (`jsonwebtoken`, `jose`, framework wrappers, or another
implementation). JavaScript truthiness checks on arrays or strings can also
turn malformed claims into allow decisions; trace the exact predicate.
