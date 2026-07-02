-- PostgreSQL counterpart to schema_sqlite.sql, made idempotent so it can
-- run on every startup like the SQLite version does. goqite's own bundled
-- schema_postgres.sql is not re-runnable (bare create table / trigger /
-- function), so we guard each object here instead.
create extension if not exists pgcrypto;

create or replace function goqite_update_timestamp()
returns trigger as $$
begin
   new.updated = now();
   return new;
end;
$$ language plpgsql;

create table if not exists goqite (
  id text primary key default ('m_' || encode(gen_random_bytes(16), 'hex')),
  created timestamptz not null default now(),
  updated timestamptz not null default now(),
  queue text not null,
  body bytea not null,
  timeout timestamptz not null default now(),
  received integer not null default 0,
  priority integer not null default 0
);

drop trigger if exists goqite_updated_timestamp on goqite;
create trigger goqite_updated_timestamp
before update on goqite
for each row execute procedure goqite_update_timestamp();

create index if not exists goqite_queue_priority_created_idx on goqite (queue, priority desc, created);
