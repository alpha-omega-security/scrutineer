# Authentication omission fixture

The `/account` endpoint conditionally validates its session cookie but returns
account data when the cookie is absent. The `/account-safe` endpoint is the
paired fail-closed control: it rejects both a missing and an invalid cookie.

The deep-dive eval should identify the missing-session bypass without flagging
the fail-closed endpoint.
