# Egress proxy sidecar — operator validation (rootless podman)

scrutineer makes `--hardened` work under **rootless podman** by running its
egress allowlist proxy as a **per-scan sidecar container** instead of a host
process. This page is the checklist for validating it on a real rootless podman
host — the parts that can't be unit-tested because they depend on the kernel and
the rootless network backend.

> **TL;DR of what to verify:** (1) your rootless backend forwards `host-gateway`
> to the host **loopback**; (2) a real `--hardened` scan runs and its egress is
> enforced; (3) teardown leaves no `scrutineer-proxy-*` containers or
> `scrutineer-hardened-*` networks behind. If (1) fails, scrutineer refuses
> hardened scans (fail closed) — that's correct, not a bug.

## How it works (one paragraph)

Under rootless podman `--hardened`, the scan container is attached to a per-scan
`--internal` network with no route out. scrutineer starts a sidecar
(`scrutineer proxy`, run from the **runner image**) on the default bridge network,
then connects it to the `--internal` network too. That `--internal` network is
created with `--disable-dns` — its embedded resolver can't forward external lookups
and would shadow the sidecar's working one — so the scan resolves no names and
points `HTTPS_PROXY` at the sidecar's **IP** on the network (`<ip>:3128`), dialing
it directly. The sidecar enforces the allowlist and forwards out its bridge leg,
reaching the host skill API via the `host.docker.internal` → host-gateway alias.
The scan never needs to reach the host directly.

### What about UDP / DNS?

The egress proxy is **TCP-only** (HTTP `CONNECT` for HTTPS, absolute-URI
forwarding for HTTP), and that is sufficient — the scan needs no outbound UDP,
just as it didn't under the host-proxy path:

- **App traffic** to Anthropic, the forges, and registries is HTTPS/HTTP over
  TCP, carried through the proxy.
- **DNS for upstreams** (e.g. `api.anthropic.com`) is resolved by the **sidecar**
  on its egress leg, not by the scan: with `HTTPS_PROXY` set the scan sends the
  *hostname* to the proxy in the `CONNECT`, so it never resolves upstreams
  itself.
- **The scan resolves no names at all**: the `--internal` network is created with
  `--disable-dns` and the scan reaches the sidecar by its `--internal` IP, so it
  needs no resolver — which also keeps that non-forwarding resolver from shadowing
  the sidecar's own upstream lookups.

So `--internal` correctly blocks **all** external egress including UDP (QUIC/
HTTP3, stray DNS), and nothing legitimate breaks. This matches the existing
docker `--hardened` behaviour; the sidecar does not change it. If you ever add a
skill that genuinely needs outbound UDP, it would need a different transport than
this proxy — not in scope here.

One thing the sidecar *does* shift: upstream DNS is resolved by the **sidecar
container**, not the host (the host proxy resolved on the host). The sidecar uses
the default bridge's resolver (the pasta forwarder, which forwards to the host's
real upstream) — not the `--internal` resolver, which is disabled precisely because
it can't forward externally. A host whose resolver isn't propagated into the
rootless netns (split-horizon, VPN, or a `127.0.0.53` stub that isn't forwarded)
could still resolve on the host yet fail in the sidecar. The sidecar guards this:
before it serves, it confirms it can **actually resolve** an allowlisted upstream
— a resolver that only answers NXDOMAIN counts as failure — and **refuses to start
(fail closed)** otherwise, so a broken netns resolver surfaces as a clear scan
refusal rather than a mid-scan model-call failure.

## Version requirements

| Component | Minimum | Why |
|---|---|---|
| **podman** | **4.7** | `--add-host host.docker.internal:host-gateway`, which the egress path needs (already required for any podman egress). |
| **podman** (recommended) | **5.0** | Default rootless backend becomes **pasta**, which maps the host with `--map-host-loopback` so the sidecar can reach the loopback-bound skill API. |
| **pasta (passt)** | a build with `--map-host-loopback` | The host-API leg: the skill API listens on `127.0.0.1`, reachable from the sidecar only if the backend forwards host-gateway to host loopback. |
| **slirp4netns** | host-loopback enabled | Alternative backend; podman enables host-loopback for `host.containers.internal`. |
| **netavark** | podman ≥ 4.0 (covered by 4.7) | Manages the default bridge and per-scan `--internal` networks the sidecar is dual-homed on. The scan reaches the sidecar by its `--internal` IP (that network is `--disable-dns`), so no embedded name resolution is needed. |

Check what you have:

```sh
podman info --format '{{.Version.Version}} | rootless={{.Host.Security.Rootless}} | net={{.Host.NetworkBackend}}'
pasta --version 2>/dev/null || slirp4netns --version
```

## Step 1 — the make-or-break precondition: host-gateway → host loopback

The whole feature rests on the sidecar reaching the host's **loopback-bound**
skill API over `host-gateway`. Most modern rootless backends forward this; some
don't. Prove it directly before anything else.

```sh
# A throwaway "host API" on loopback only:
python3 -m http.server 18080 --bind 127.0.0.1 &
HOST_API=$!

# Resolve the default-network host-gateway IPv4 the way scrutineer does:
GW=$(podman run --rm --add-host hgw:host-gateway alpine \
       sh -c "getent hosts hgw | awk '{print \$1; exit}'")
echo "host-gateway = $GW"

# Can a normal container reach the LOOPBACK-bound server through it?
podman run --rm --add-host host.docker.internal:host-gateway alpine \
  sh -c "wget -qO- -T5 http://host.docker.internal:18080/ >/dev/null && echo REACHABLE || echo BLOCKED"

kill $HOST_API
```

- `REACHABLE` → your backend forwards host-gateway to host loopback. The sidecar
  will work. Continue.
- `BLOCKED` → it does **not**. scrutineer will **refuse** hardened scans here
  (fail closed). If you are already on podman ≥ 5.0 with pasta, it is most likely
  suppressing the host-loopback mapping — re-enable it (next section). Otherwise
  switch the backend, or use `--hardened-runtime-only` (cooperative egress) /
  rootful podman / docker.

### Re-enabling host-loopback under pasta

podman ≥ 5.0 uses pasta, which *can* forward host-gateway to the host loopback,
but podman commonly starts it with that mapping **disabled** — so a modern host
can still read `BLOCKED`. Confirm what podman passes to pasta (look for
`--map-host-loopback none`, or its absence) while a container runs:

```sh
podman run -d --rm --name nettest alpine sleep 10 >/dev/null
pgrep -a pasta
podman rm -f nettest >/dev/null
```

Re-enable it in your rootless `containers.conf` (per-user; no restart — the next
`podman run` reads it). Derive the gateway address rather than hardcoding it:

```sh
GW=$(podman run --rm --add-host hgw:host-gateway alpine \
       cat /etc/hosts | awk '$2=="hgw"{print $1; exit}')
mkdir -p ~/.config/containers
# creates/overwrites containers.conf; if you already have one, add these keys by hand
cat > ~/.config/containers/containers.conf <<EOF
[network]
default_rootless_network_cmd = "pasta"
pasta_options = ["--map-host-loopback", "$GW"]
EOF
```

This is a **one-time** host setup: `containers.conf` persists and every rootless
`podman run` (scrutineer's sidecar included) reads it — no need to re-apply per
scan or per scrutineer start. Re-derive only if pasta's gateway later changes
(e.g. a podman/pasta upgrade), which the Step 1 probe will surface as `BLOCKED`
again. Note it also makes the host loopback reachable from any rootless container
on the default network, not just the sidecar — fine on a dedicated scrutineer
host, weigh it on a shared one. Re-run the Step 1 probe; it should print
`REACHABLE`.

## Step 2 — build the runner image (it now carries the `scrutineer` binary)

The sidecar runs `scrutineer proxy` from the runner image, so the image must be
built from the updated `docker/runner/Dockerfile.runner` (which bakes in the
static `scrutineer` binary). Building needs network access for `go mod download`,
so do it in CI or a network-enabled environment:

```sh
podman build -t scrutineer-runner:dev -f docker/runner/Dockerfile.runner .
podman run --rm scrutineer-runner:dev scrutineer proxy -h   # smoke test: exits 0
```

> **Upgrade coupling.** Under rootless `--hardened`, the host `scrutineer`
> binary and the runner-image `scrutineer` binary are now coupled: an upgraded
> host running an **old cached runner image** (no `scrutineer` inside) can't run
> the sidecar. scrutineer guards this — under rootless `--hardened` it smoke-tests
> the runner image at **startup** and refuses to boot with a clear "rebuild from
> docker/runner/Dockerfile.runner" message rather than failing every scan
> cryptically. So when you upgrade, rebuild/pull the runner image too. A
> **custom** `--runner-image` must therefore include the `scrutineer` binary
> (and `curl`); build it FROM the stock runner image or replicate the
> `docker/runner/Dockerfile.runner` build stage.

## Step 3 — run a real hardened scan under rootless podman

```sh
scrutineer --runtime podman --hardened --runner-image scrutineer-runner:dev ...
```

Watch for, at startup:

```
container runtime detected ... hardened=true egress_sidecar=true
```

`egress_sidecar=true` confirms the sidecar path is active (rootless + hardened +
a resolved host-gateway). If you instead see a startup warning that host-gateway
did not resolve, fix that first (Step 1 / podman ≥ 4.7).

While a scan runs, in another shell:

```sh
podman ps --filter name=scrutineer-proxy-      # the sidecar for the active scan
podman network inspect scrutineer-hardened-<scan_id>   # the per-scan --internal net
podman logs scrutineer-proxy-<scan_id>         # "egress proxy listening ..." once ready
```

What to confirm:

- **The sidecar starts and serves.** Its log shows `egress proxy: waiting for
  host skill API` then `egress proxy listening`. If it logs `refusing to start:
  host skill API ... unreachable` and exits, Step 1 failed on this host.
- **The scan's skill-API calls succeed** (the skill fetches context / posts
  findings) — proves scan → sidecar → host API end to end.
- **Enforced egress.** A workload that ignores `HTTPS_PROXY` has no route out:
  the per-scan verification already proves this at scan start (it refuses the
  scan otherwise), but you can re-confirm with the probe in Step 4.
- **Allowlist enforcement.** Egress to anything outside `*.anthropic.com` + the
  host skill API gets a `403` from the sidecar. These `egress denied` lines are
  captured into the **scan record** at teardown (prefixed `egress-proxy:`), so
  you don't need `podman logs` to audit them after the fact — though they're
  there live too.

## Step 4 — the automated integration test

A build-tagged integration test drives the whole flow against real podman.
Point it at your locally-built runner image:

```sh
SCRUTINEER_TEST_RUNNER_IMAGE=scrutineer-runner:dev \
  go test -tags podman -run TestIntegration_ProxySidecar -count=1 -v ./internal/worker/
```

It **skips** (not fails) when podman is absent, isn't rootless, the runner image
isn't present, or the backend doesn't forward host-gateway to host loopback (the
Step 1 precondition) — so a clean skip with that message is itself the signal
that this host can't run the sidecar. A pass proves: the sidecar comes up on both
network legs, the scan reaches the host API only through it, a non-allowlisted
host is refused (403), and teardown removes the sidecar and its network.

The pre-existing podman tests are worth running too:

```sh
go test -tags podman -run TestIntegration -count=1 -v ./internal/worker/
```

## Step 5 — teardown and crash recovery

- **Normal teardown:** after each scan, the sidecar is force-removed *before* its
  network (a network with an attached container won't delete). Confirm nothing
  lingers:

  ```sh
  podman ps -a --filter name=scrutineer-proxy-      # empty between scans
  podman network ls --filter name=scrutineer-hardened-   # empty between scans
  ```

- **Crash recovery:** a hard kill of scrutineer mid-scan leaves a detached
  sidecar (and its network). On the next startup scrutineer sweeps them —
  `removed orphan egress proxy sidecars` / `removed orphan hardened networks` in
  the log. To simulate: start a scan, `kill -9` scrutineer, confirm a
  `scrutineer-proxy-*` container remains, restart scrutineer, confirm it's gone.

## Failure modes and what they mean

| Symptom | Meaning | Action |
|---|---|---|
| Startup warning: host-gateway did not resolve under rootless podman | podman < 4.7 or no host-gateway wiring | Upgrade to podman ≥ 4.7; check the rootless network backend. |
| Sidecar log: `refusing to start: host skill API ... unreachable`; scan refused with `sidecar ... exited before becoming reachable` | Backend doesn't forward host-gateway to host loopback (Step 1) | Upgrade to podman ≥ 5.0 / pasta with `--map-host-loopback`; or use `--hardened-runtime-only` / rootful / docker. |
| Sidecar log: `refusing to start: ... cannot reach a DNS resolver ...` or `... returned NXDOMAIN for every allowlisted upstream ...`; scan refused | The sidecar can't resolve upstreams — resolver unreachable, or it answers but can't forward externally (e.g. a `127.0.0.53` stub not reachable from the rootless netns) | Check the bridge resolver / pasta forwarder and `/etc/resolv.conf` propagation. |
| Startup fails: `runner image ... is missing the scrutineer binary ... rebuild it from docker/runner/Dockerfile.runner` | The deployed runner image predates the sidecar (no `scrutineer` baked in), or a custom image lacks it | Rebuild/pull the runner image from the current `docker/runner/Dockerfile.runner`. |
| Verification: `internal network ... cannot reach the egress proxy sidecar` | Sidecar didn't come up in time, or it couldn't be reached at its `--internal` IP | Check `podman logs scrutineer-proxy-<id>`; confirm the sidecar attached to the per-scan network. |
| Verification: `did not block external egress` | `--internal` isn't isolating egress on this backend | Backend/version issue; do not run hardened here. |
| `runner image ... lacks curl` | Custom runner image missing curl (hardened verification needs it) | Use an image built from `docker/runner/Dockerfile.runner`. |

## See also

- [podman.md](podman.md) — full rootless security model; the `--hardened` under
  rootless podman section.
- [../threatmodel.md](../threatmodel.md) — T13 (runner egress).
