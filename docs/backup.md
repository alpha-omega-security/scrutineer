# Backup and restore

All of scrutineer's unique state lives in one SQLite file, `data/scrutineer.db`:
every repository, scan, finding, advisory, maintainer record, and edited skill.
Lose it and the only rebuild path is to rescan everything, paying the wall-clock
time and Anthropic spend again.

Because the database runs in [WAL mode](database.md), a plain `cp` of it while a
scan runs can capture an inconsistent, unrestorable copy: committed transactions
may still sit in the `-wal` sidecar. Every method below handles that; do not
substitute a bare file copy.

## What to back up

- **`data/scrutineer.db`** is the only state worth backing up.
- **Do not back up `scrutineer.yaml`.** It carries credentials (the Anthropic API
  key or OAuth token) that should not be copied into a backup destination.
- The `data/scrutineer.db-wal` and `data/scrutineer.db-shm` sidecars only matter
  for the stop-and-copy method below. The built-in command, `sqlite3 .backup`,
  and Litestream all fold the WAL into a single consistent file for you.

## Sensitivity

A backup holds the same operator-sensitive data as the live database:
pre-disclosure security findings, maintainer contact records, per-scan API
bearer tokens, and Anthropic usage figures. Give a backup file the same trust
handling as the live database:

- keep it off shared paths,
- encrypt it at rest whenever it is stored off-host (an S3 bucket, an SFTP
  target, an external disk),
- prefer destinations you already trust with vulnerability data over generic
  cloud storage.

## Strategies

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
`.db`, which alone would be an inconsistent copy. The glob takes whichever exist
and skips the disposable `data/work/` workspaces:

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

Before you trust a backup path, restore once and confirm the data survived:

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

See [database.md](database.md) for the full schema these checks run against.
