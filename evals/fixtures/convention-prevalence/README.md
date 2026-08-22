# Convention prevalence fixture

Every module builds SQL by interpolating into a string then handing it to
`store.query`. Eight of the nine call sites live in `reports.py` and interpolate
module constants, so nothing external reaches them. The ninth, in `search.py`,
interpolates a request parameter.

The idiom is the same everywhere, which is the point: the count is what tells a
reviewer that string-built SQL is this project's house style rather than a slip,
while the trace is what singles out the one site an attacker can reach.

The deep-dive eval should file the `search.py` site and leave the `reports.py`
sites in the ruled-out list rather than filing eight more findings for the
convention.
