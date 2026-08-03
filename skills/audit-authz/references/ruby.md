# Ruby Authorization Review Notes

## Rails Controllers And Policies

Resolve Rails `before_action` inheritance, `skip_before_action`, concerns,
controller base classes, route constraints, and service-layer policies. A
controller with no local guard may inherit one. `authenticate_user!` proves
identity, not ownership or permission.

Pundit checks are explicit:

- `authorize(record)` applies a policy to one record.
- `policy_scope(Model)` limits collections.
- `verify_authorized` and `verify_policy_scoped` detect missing calls but do
  not authorize by themselves.

CanCanCan commonly uses `load_and_authorize_resource`; verify controller
aliases, nested resources, skipped actions, and custom loads. Do not infer
coverage from an `Ability` rule unless the handler invokes the mechanism that
enforces it.

Active Record `find(params[:id])` is globally scoped. It can still be safe if a
policy authorizes the loaded record. Queries through a principal or tenant
association, such as `current_user.orders.find`, supply stronger object
scoping.

## Strong Parameters And Assignment

Strong Parameters are the field allowlist only when the permitted hash is what
reaches `new`, `create`, `assign_attributes`, or `update`. Inspect privileged
fields such as role, admin flags, tenant/organization IDs, ownership, billing,
and workflow state. A server-side assignment can still be overwritten if
caller data is merged afterward.

Do not report `permit!` or a broad permit on a read-only path. Establish the
write operation and a sensitive field a lower-privileged actor can control.

## Tokens And Sessions

Read `jwt.md` when JWT claims drive authorization and determine which JWT gem
is used before interpreting decode options. Rails signed or encrypted cookies
provide integrity/confidentiality for cookie contents but do not prove that a
referenced object belongs to the current actor.
