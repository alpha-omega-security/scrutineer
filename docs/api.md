# HTTP API

Scrutineer's HTTP endpoints are split by caller and trust boundary. They are not one uniformly authenticated public API: running skills use short-lived scan tokens, the browser UI and host-side operator tools use the operator token, and federation peers reach a separately deployed claim-check endpoint.

The complete method, path, parameter, request, and response definitions are in the [OpenAPI document](../openapi.yaml). See the [threat model](../threatmodel.md) for the DNS-rebinding, CSRF, runner, and federation threats these controls address. Developers adding a route should also read the [development guide](development.md#skill-http-api) and add the route to `openapi.yaml`; route coverage tests reject undocumented API handlers. This page explains how callers reach those routes and which authentication rule applies.

## Surfaces

| Surface | Intended caller | Access rule |
|---|---|---|
| `/api/*` | A skill running inside an active scan | Per-scan bearer token |
| Browser UI, `/api/v1/*` | The operator, through a browser or host-side scripts | Operator token as a cookie or bearer, plus the loopback Host check |
| `/claim-check` | A federation peer through an operator-configured reverse proxy | No bearer token; disabled by default and loopback-only without a proxy |
| `/api/openapi.yaml` | Host-side discovery or a running skill | Loopback access without a token, otherwise a per-scan bearer token |

Scrutineer normally listens on loopback. The Host checks described below are a defence against DNS rebinding, not a replacement for authentication: any non-browser client can send `Host: 127.0.0.1`, so the operator token is what keeps the browser UI and `/api/v1/*` closed to other callers. Do not publish them directly.

## Skill API: `/api/*`

Every skill scan receives a random bearer token when it is enqueued. The worker places it in `context.json` together with the API base URL, scan ID, and repository ID:

```json
{
  "scrutineer": {
    "api_base": "http://host.docker.internal:8080/api",
    "token": "<per-scan token>",
    "scan_id": 42,
    "repository_id": 7
  }
}
```

Requests send the token as an HTTP bearer credential:

```text
Authorization: Bearer <token>
```

The token is accepted only while its originating scan has status `running`. Repository-, scan-, and finding-scoped handlers also verify that the requested resource belongs to the token's repository. A token from one repository cannot read or modify another repository. Request bodies on this surface are capped at 1 MiB.

The skill API lets an active skill read repository context and prior scan data, validate a report, enqueue repository- or finding-scoped skills, and update finding records. The exact routes and schemas are in [`openapi.yaml`](../openapi.yaml). See [Writing skills](skills.md#calling-scrutineer-from-a-skill) for the workspace-facing contract and examples of bundled skills that use it.

## Operator API: `/api/v1/*`

The `/api/v1` surface is for commands running on the Scrutineer host. It passes through the same security middleware as the browser UI: it rejects a request whose `Host` is not `127.0.0.1`, `localhost`, or `::1` (with or without a port), and it requires the operator token. A scan bearer token is not accepted here. Browser POST requests through this middleware also check `Sec-Fetch-Site`; non-browser clients such as `curl` do not send that header.

On first run Scrutineer generates the operator token, writes it to `<data>/operator-token` (mode `0600`), and logs a `/login?token=...` link. Every later start logs the same link along with the absolute path of the file, so a browser that has lost its cookie can sign in again from the latest log line, and scripts can read the file. Opening the link sets an `HttpOnly`, `SameSite=Strict` cookie for the browser UI, named `operator-` plus a short hash of the token, so two instances on `127.0.0.1` with different ports do not overwrite each other's cookie. Cookies set on `127.0.0.1` are not sent to `localhost`, so use the same hostname the link uses. Deleting the file and restarting rotates the token and signs every browser out.

Send the token as a bearer credential from the host:

```sh
curl -H "Authorization: Bearer $(cat data/operator-token)" http://127.0.0.1:8080/api/v1/repositories
curl -H "Authorization: Bearer $(cat data/operator-token)" http://127.0.0.1:8080/api/v1/findings
curl -H "Authorization: Bearer $(cat data/operator-token)" http://127.0.0.1:8080/api/v1/scans
```

`GET /api/v1/findings` accepts `severity`, `status`, `sub_path`, `scope=findings`, `repository_id`, `since` (creation time) and `updated_since` (modification time) filters, combined with AND. See `openapi.yaml` for the exact semantics.

`GET /api/v1/repositories/{id}` and `GET /api/v1/findings/{id}` return a single row as JSON, with the same shape as a line of the matching JSONL export. A malformed ID returns `400` and an unknown one `404`. They reject `encrypt`, `scope`, `include` and any `format` other than `jsonl` with `400` rather than returning plaintext, as do the repositories and scans exports. `scope=findings` is accepted only by the findings exports, `/api/v1/findings` and `/api/v1/repositories/{id}/findings`.

This surface includes JSONL exports, repository finding bundles, report imports, operator delete operations, and instance-wide audit exports. Because these routes can read or modify data across the whole instance, they are kept outside the repository-scoped skill API.

Detailed workflows:

- [Importing findings](import.md) covers `POST /api/v1/import`, accepted formats, repository resolution, and revalidation, plus `POST /api/v1/import/oss-crs` and the retained OSS-CRS evidence.
- [Encrypted findings sharing](encrypted-sharing.md) covers repository bundles, archival exports, age encryption, and round trips through the import route.
- [Exporting findings as SARIF](sarif-export.md) covers `format=sarif` on the repository findings export and handing the log to OSS-CRS as bug candidates.
- The [OpenAPI document](../openapi.yaml) defines the JSONL exports, filters, delete operations, and audit endpoints.

## Federation claim check: `/claim-check`

`POST /claim-check` is registered at the server root, not below `/api`. It is disabled unless `federation_salt` is configured. Disabled instances and unsupported methods return `404`, so the endpoint does not advertise whether federation is enabled.

On its normal loopback listener, claim-check has the same Host restriction as the browser UI and `/api/v1`, but it does not require the operator token or a scan bearer token. Making it available to federation peers is an explicit deployment decision. The recommended reverse proxy should expose only `POST /claim-check` and rewrite the upstream `Host` to the Scrutineer loopback address. Do not proxy the rest of the UI or operator API with it.

See [Federation interchange](interchange.md#claim-check-endpoint) for the hash contract, responses, configuration, and reverse-proxy guidance.

## OpenAPI discovery: `/api/openapi.yaml`

The repository copy of [`openapi.yaml`](../openapi.yaml) is authoritative and is also embedded in the binary. A running server exposes that copy at `GET /api/openapi.yaml` under two access rules:

- A host-side caller using a loopback Host may fetch it without credentials.
- A skill whose container-facing API hostname is not loopback must send its active scan bearer token.

This hybrid rule applies only to OpenAPI discovery. It does not make the rest of `/api/*` available without a token or the rest of `/api/v1/*` available to a container token.
