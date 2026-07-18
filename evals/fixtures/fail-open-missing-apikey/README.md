# Fail-open missing API key fixture

Tiny Flask app with one admin endpoint whose credential check runs only when an
`X-API-Key` header is present. A request that omits the header skips the
comparison and reaches the authorised branch. The eval expects the skill to
treat the missing credential as a fail-open authentication bypass, not as a
harmless missing optional input.
