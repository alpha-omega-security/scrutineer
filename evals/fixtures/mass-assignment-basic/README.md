# Mass-assignment fixture

The member-only `/account` route validates only the JSON shape, then passes
the full request body to `account.update(body)`. A member can therefore set
server-owned fields such as `role` or `owner_id`.

The `/profile` route is the paired negative case. It copies only an explicit
allow-list of editable fields and overwrites `owner_id` from the authenticated
principal, so it must not produce a mass-assignment finding.
