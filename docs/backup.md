# Backup and restore

Scrutineer stores repositories, scans, findings, advisories, maintainer records,
chat messages, and edited skills in its database. The default is SQLite at
`data/scrutineer.db`; installations configured for PostgreSQL must back up that
database instead. Resumable agent sessions also need files outside the database.

## What to back up

- Back up the configured database using one of the methods below.
- To preserve container-backed scan and chat sessions, also save
  `data/harness-state/` and the existing `data/scan-*/` and `data/chat-*/`
  workspaces. Host-run Claude sessions use the host's Claude configuration
  directory instead of `harness-state/`; include that session store if needed.
- Preserve `scrutineer.yaml` and any separately configured credential files in
  protected storage, or keep a way to recreate them. They can contain API keys,
  OAuth tokens, and database credentials; exclude them from shared archives.

Use your configured data directory in place of `data/`. Stop Scrutineer while
taking a matching database and session-file backup, and restore both before
restarting it. A database-only restore preserves application records and chat
messages, but cannot restore native agent sessions. Repository clones in
`data/repo-cache/` can be rebuilt from their remotes.

## Sensitivity

A backup holds the same operator-sensitive data as the live database:
pre-disclosure security findings, maintainer contact records, per-scan API
bearer tokens, and model usage figures. Session stores can also contain
credentials and repository content. Protect backups as you would the source data:

- keep it off shared paths,
- encrypt it at rest whenever it is stored off-host (an S3 bucket, an SFTP
  target, an external disk),
- prefer destinations you already trust with vulnerability data over generic
  cloud storage.

## PostgreSQL

For `database.driver: postgres`, use operator-managed database backups, such as
a provider snapshot or [`pg_dump`](https://www.postgresql.org/docs/current/app-pgdump.html).
Custom-format dumps can be restored with
[`pg_restore`](https://www.postgresql.org/docs/current/app-pgrestore.html).
Provision the required database roles separately; `pg_dump` covers one database
and does not include cluster-wide roles. Stop Scrutineer before restoring, then
set `database.dsn` to the restored database before restarting.

The built-in `scrutineer backup` and `scrutineer restore` commands are SQLite-only
and reject PostgreSQL configurations. PostgreSQL backups still need the session
files described above if you want to preserve scan and chat resume state.

## SQLite

SQLite runs in [WAL mode](database.md), so a plain `cp` while a scan runs can
capture an inconsistent copy: committed transactions may still sit in the
`-wal` sidecar. The methods below handle that. The stop-and-copy method includes
the `-wal` and `-shm` sidecars; the other methods produce a consistent database
without copying those files separately. None includes the session files or
configuration.

### 1. Built-in command (recommended)

`scrutineer backup` writes a consistent snapshot via SQLite's `VACUUM INTO`. It
cooperates with WAL, so it is safe to run while scrutineer is serving, it needs
no external `sqlite3` binary (scrutineer ships a pure-Go SQLite driver), and the
snapshot is written owner-only (`0600`).

```sh
# Explicit destination.
scrutineer backup --to /backups/scrutineer-2026-06-05.db

# No --to: writes ./scrutineer-backup-<timestamp>.db in the working directory.
scrutineer backup
```

`backup` locates the database the same way the server does, so pass the same
`-data` / `-config` you start scrutineer with if they are not the defaults.

A daily cron entry is enough for most single-operator setups (the recovery
point is the cron cadence). Note the escaped `%` in crontab:

```cron
0 3 * * * cd /srv/scrutineer && /usr/local/bin/scrutineer backup --to /backups/scrutineer-$(date +\%F).db
```

To restore, **stop the server first**, then:

```sh
scrutineer restore --from /backups/scrutineer-2026-06-05.db
```

`restore` checks that `--from` is a SQLite database, removes any stale
`-wal`/`-shm` next to the live file, and swaps the snapshot in atomically. It
refuses to run while a server answers on the configured address, but that is
only a backstop: stopping the server yourself is the real precondition.

### 2. `sqlite3 .backup`

If you prefer the SQLite CLI, `.backup` is also WAL-safe and runs while
scrutineer is up. Scrutineer does not bundle the `sqlite3` binary, so install it
from your package manager first.

```sh
sqlite3 data/scrutineer.db ".backup '/backups/scrutineer-$(date +%F).db'"
```

To restore, stop the server, then either run `scrutineer restore --from <file>`
or replace the file by hand: copy the snapshot over `data/scrutineer.db`, delete
`data/scrutineer.db-wal` and `data/scrutineer.db-shm`, and restart.

### 3. Litestream (continuous replication)

[Litestream](https://litestream.io) streams WAL frames to S3, GCS, SFTP, or a
sibling disk, pulling the recovery point down to seconds. It runs as one extra
sidecar process and needs infrastructure you may not want to stand up.

```yaml
# litestream.yml
dbs:
  - path: /srv/scrutineer/data/scrutineer.db
    replicas:
      - url: s3://my-trusted-bucket/scrutineer
```

To restore, stop the server, then:

```sh
litestream restore -o data/scrutineer.db s3://my-trusted-bucket/scrutineer
```

### 4. Stop-and-copy

The fallback when you want a snapshot with no tooling at all: stop the server so
nothing writes, copy the database, restart. Safe but disruptive, so it suits
occasional manual archives only.

Copy the main file with its `-wal`/`-shm` sidecars: scrutineer holds the database
open, so the `-wal` can carry committed transactions not yet folded into the
`.db`, which alone would be an inconsistent copy. The glob takes whichever exist;
copy the session stores (`harness-state/`), the saved partial reports
(`resume-report/`) and the workspaces separately if preserving resume state:

```sh
# With the server stopped:
mkdir -p /backups/scrutineer-2026-06-05
cp data/scrutineer.db* /backups/scrutineer-2026-06-05/
```

To restore, stop the server, clear any stale sidecars next to the live file, and
copy the set back:

```sh
rm -f data/scrutineer.db data/scrutineer.db-wal data/scrutineer.db-shm
cp /backups/scrutineer-2026-06-05/scrutineer.db* data/
```

## Verify the first restore

Restore once and confirm the data survived. These commands are for SQLite;
run the same SQL through `psql` for PostgreSQL:

- **Record counts per table** look right:

  ```sh
  sqlite3 data/scrutineer.db "SELECT 'repositories', count(*) FROM repositories \
    UNION ALL SELECT 'scans', count(*) FROM scans \
    UNION ALL SELECT 'findings', count(*) FROM findings;"
  ```

- **The most recent scan id** is present:

  ```sh
  sqlite3 data/scrutineer.db "SELECT max(id) FROM scans;"
  ```

- **A known finding loads** in the UI: open it and confirm its notes and
  communications render.
- If you backed up session files, resume a saved scan and continue a chat to
  check that their native sessions are available.

See [database.md](database.md) for the full schema these checks run against.
