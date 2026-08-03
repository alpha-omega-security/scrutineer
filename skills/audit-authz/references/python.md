# Python Authorization Review Notes

## Django And Django REST Framework

Django authentication middleware establishes `request.user`; it does not
authorize that user to arbitrary models. Trace URL registration, decorators,
class mixins, middleware, and the object query.

- Django 5.1 introduced `LoginRequiredMiddleware`. It can supply a global
  authentication requirement, but it does not add ownership, tenant, or role
  checks. Views marked with `login_not_required` are deliberate exceptions.
- Django REST Framework views opt out of Django 5.1+
  `LoginRequiredMiddleware`. For DRF, inspect
  `DEFAULT_AUTHENTICATION_CLASSES`, `DEFAULT_PERMISSION_CLASSES`, and
  per-view overrides instead of assuming the Django middleware protects the
  API. See https://www.django-rest-framework.org/api-guide/authentication/#django-51-loginrequiredmiddleware.
- `LoginRequiredMixin` and `@login_required` prove authentication only.
  `PermissionRequiredMixin`, `UserPassesTestMixin`, model permissions, or an
  application policy may add function-level authorization.
- DRF calls `has_permission` before the handler. Object permission checks occur
  when code calls `check_object_permissions`, including the normal
  `get_object` path. Custom lookups and list querysets need their own object or
  tenant scoping.
- DRF does not automatically apply object permissions to every row in a list.
  Inspect `get_queryset`, filter backends, and repository helpers.
- Read inherited viewsets and mixins before reporting an unscoped concrete
  class. A base class may supply `get_queryset` or permission classes.

Mass-assignment candidates include writable `ModelSerializer` fields,
`fields = "__all__"`, `serializer.save(**request.data)`, model constructors,
and `QuerySet.update(**payload)`. Confirm the HTTP method and writable-field
configuration. A read-only serializer is not an assignment path.

## FastAPI And Flask

FastAPI dependencies can attach globally, to an `APIRouter`, or to an
individual operation. Follow `include_router` nesting and dependency lists.
`Depends(require_user)` proves only what that dependency actually checks.
Pydantic request validation constrains shape; it does not prove that the actor
owns a selected row.

Flask is allow-by-default unless application or blueprint hooks establish a
guard. Resolve `before_request`, blueprint registration, route decorators,
Flask-Login, and custom policy calls. `@login_required` is authentication, not
object authorization.

For SQLAlchemy and similar ORMs, compare:

    query.filter(Model.id == request_id)

with a query that also binds the actor's tenant, owner, membership, or allowed
resource set. A later policy call can make a globally loaded row safe; inspect
it rather than judging the query alone.

## JWT And Session Claims

Read `jwt.md` for algorithm, key-selection, claim-validation, and version
checks. Determine the imported Python module before interpreting a
`jwt.decode` call because PyJWT and python-jose expose different contracts.
Do not report a decoded claim unless it actually grants a role, tenant, scope,
ownership decision, or privileged operation.
