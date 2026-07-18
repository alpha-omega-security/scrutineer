# Fail-closed missing session fixture

Tiny Flask app with one profile endpoint that requires a `user_id` session
value. When the session is absent the handler returns 401 before any authorised
branch runs. The eval expects the skill to recognise the fail-closed behaviour
and not file a missing-input authentication bypass.
