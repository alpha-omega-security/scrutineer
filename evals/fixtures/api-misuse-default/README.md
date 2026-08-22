# API misuse fixture

`fetch` in `client.py` defaults `verify` to `False`, so a caller who passes
nothing gets no certificate or hostname checking. `fetch_pinned` in
`pinned_client.py` is the paired control: the same body, the safe default, an
opt-out the caller has to ask for by name.

The two bodies are identical on purpose. The only difference is the default, so
a run that flags both is reacting to the presence of an opt-out rather than to
which way the API points a caller who says nothing.

Each helper gets its own file so the assertions key on `path` rather than on
wording. A correct write-up is free to name `fetch_pinned` while contrasting the
two. A run that files the safe helper is caught whatever title it picks.

The deep-dive eval should file the unsafe default as an API misuse finding
without flagging the helper whose default is safe.
