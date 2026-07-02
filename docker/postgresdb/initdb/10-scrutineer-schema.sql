-- scrutineer PostgreSQL schema — PRE-PROVISIONING INIT SCRIPT
--
-- Loaded once by the postgres entrypoint (/docker-entrypoint-initdb.d) on
-- first container start, against $POSTGRES_DB as $POSTGRES_USER.
--
-- GENERATED, do not hand-edit. It is scrutineer's own GORM AutoMigrate output
-- captured via pg_dump --schema-only. scrutineer re-runs AutoMigrate on every
-- boot, so this file is a head start, not the source of truth: any drift from
-- the Go models is reconciled automatically at startup.
--
-- Regenerate (from repo root, with a throwaway postgres on :55432):
--   SCRUTINEER_TEST_PG_DSN=postgres://scrutineer:secret@localhost:55432/scrutineer?sslmode=disable \
--     go test ./internal/db/ ./internal/queue/ -run 'TestPostgresBackend|TestPostgresQueue' -count=1
--   pg_dump -U scrutineer -d scrutineer --schema-only --no-owner --no-privileges > docker/postgresdb/initdb/10-scrutineer-schema.sql

--
-- PostgreSQL database dump
--

\restrict 8PJRx7K6xAKDVk0U4YNXkMnn5e3i5YlMyHGkH113mXL54AA7TKcgBDYeLhLGRbZ

-- Dumped from database version 16.14
-- Dumped by pg_dump version 16.14

SET statement_timeout = 0;
SET lock_timeout = 0;
SET idle_in_transaction_session_timeout = 0;
SET client_encoding = 'UTF8';
SET standard_conforming_strings = on;
SELECT pg_catalog.set_config('search_path', '', false);
SET check_function_bodies = false;
SET xmloption = content;
SET client_min_messages = warning;
SET row_security = off;

--
-- Name: public; Type: SCHEMA; Schema: -; Owner: -
--

-- *not* creating schema, since initdb creates it


--
-- Name: SCHEMA public; Type: COMMENT; Schema: -; Owner: -
--

COMMENT ON SCHEMA public IS '';


--
-- Name: pgcrypto; Type: EXTENSION; Schema: -; Owner: -
--

CREATE EXTENSION IF NOT EXISTS pgcrypto WITH SCHEMA public;


--
-- Name: EXTENSION pgcrypto; Type: COMMENT; Schema: -; Owner: -
--

COMMENT ON EXTENSION pgcrypto IS 'cryptographic functions';


--
-- Name: goqite_update_timestamp(); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.goqite_update_timestamp() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
begin
   new.updated = now();
   return new;
end;
$$;


SET default_tablespace = '';

SET default_table_access_method = heap;

--
-- Name: advisories; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.advisories (
    id bigint NOT NULL,
    repository_id bigint NOT NULL,
    uuid text,
    url text,
    title text,
    description text,
    severity text,
    cvss_score numeric,
    classification text,
    packages text,
    published_at timestamp with time zone,
    withdrawn_at timestamp with time zone,
    created_at timestamp with time zone
);


--
-- Name: advisories_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.advisories_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: advisories_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.advisories_id_seq OWNED BY public.advisories.id;


--
-- Name: cnas; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.cnas (
    id bigint NOT NULL,
    short_name text NOT NULL,
    cna_id text,
    organization text,
    scope text,
    email text,
    contact_url text,
    policy_url text,
    advisory_url text,
    root text,
    types text,
    country text,
    metadata text,
    fetched_at timestamp with time zone,
    created_at timestamp with time zone,
    updated_at timestamp with time zone
);


--
-- Name: cnas_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.cnas_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: cnas_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.cnas_id_seq OWNED BY public.cnas.id;


--
-- Name: dependencies; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.dependencies (
    id bigint NOT NULL,
    repository_id bigint NOT NULL,
    name text,
    ecosystem text,
    p_url text,
    requirement text,
    requirement_unresolved boolean,
    requirement_resolution text,
    dependency_type text,
    manifest_path text,
    manifest_kind text,
    created_at timestamp with time zone
);


--
-- Name: dependencies_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.dependencies_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: dependencies_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.dependencies_id_seq OWNED BY public.dependencies.id;


--
-- Name: dependents; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.dependents (
    id bigint NOT NULL,
    repository_id bigint NOT NULL,
    name text,
    ecosystem text,
    p_url text,
    repository_url text,
    downloads bigint,
    dependent_repos bigint,
    registry_url text,
    latest_version text,
    created_at timestamp with time zone
);


--
-- Name: dependents_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.dependents_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: dependents_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.dependents_id_seq OWNED BY public.dependents.id;


--
-- Name: finding_communications; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.finding_communications (
    id bigint NOT NULL,
    finding_id bigint NOT NULL,
    channel text,
    direction text,
    actor text,
    body text,
    offered_help text,
    at timestamp with time zone,
    created_at timestamp with time zone
);


--
-- Name: finding_communications_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.finding_communications_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: finding_communications_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.finding_communications_id_seq OWNED BY public.finding_communications.id;


--
-- Name: finding_dependents; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.finding_dependents (
    id bigint NOT NULL,
    finding_id bigint NOT NULL,
    dependent_id bigint NOT NULL,
    status text,
    justification text,
    rationale text,
    scan_id bigint,
    scan_commit text,
    created_at timestamp with time zone,
    updated_at timestamp with time zone
);


--
-- Name: finding_dependents_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.finding_dependents_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: finding_dependents_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.finding_dependents_id_seq OWNED BY public.finding_dependents.id;


--
-- Name: finding_histories; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.finding_histories (
    id bigint NOT NULL,
    finding_id bigint NOT NULL,
    field text,
    old_value text,
    new_value text,
    source text,
    by text,
    created_at timestamp with time zone
);


--
-- Name: finding_histories_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.finding_histories_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: finding_histories_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.finding_histories_id_seq OWNED BY public.finding_histories.id;


--
-- Name: finding_labels; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.finding_labels (
    id bigint NOT NULL,
    name text NOT NULL,
    color text,
    created_at timestamp with time zone
);


--
-- Name: finding_labels_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.finding_labels_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: finding_labels_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.finding_labels_id_seq OWNED BY public.finding_labels.id;


--
-- Name: finding_labels_join; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.finding_labels_join (
    finding_id bigint NOT NULL,
    finding_label_id bigint NOT NULL
);


--
-- Name: finding_notes; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.finding_notes (
    id bigint NOT NULL,
    finding_id bigint NOT NULL,
    body text,
    by text,
    created_at timestamp with time zone
);


--
-- Name: finding_notes_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.finding_notes_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: finding_notes_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.finding_notes_id_seq OWNED BY public.finding_notes.id;


--
-- Name: finding_references; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.finding_references (
    id bigint NOT NULL,
    finding_id bigint NOT NULL,
    url text,
    tags text,
    summary text,
    created_at timestamp with time zone
);


--
-- Name: finding_references_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.finding_references_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: finding_references_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.finding_references_id_seq OWNED BY public.finding_references.id;


--
-- Name: finding_reviews; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.finding_reviews (
    id bigint NOT NULL,
    finding_id bigint NOT NULL,
    verdict text,
    reason text,
    automated_outcome text,
    reviewer text,
    created_at timestamp with time zone
);


--
-- Name: finding_reviews_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.finding_reviews_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: finding_reviews_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.finding_reviews_id_seq OWNED BY public.finding_reviews.id;


--
-- Name: findings; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.findings (
    id bigint NOT NULL,
    scan_id bigint NOT NULL,
    repository_id bigint,
    commit text,
    sub_path text,
    fingerprint text,
    last_seen_scan_id bigint,
    last_seen_commit text,
    seen_count bigint,
    missed_count bigint,
    last_missed_scan_id bigint,
    vid text,
    finding_id text,
    sinks text,
    title text,
    severity text,
    confidence text,
    status text DEFAULT 'new'::text,
    cwe text,
    location text,
    locations text,
    snippet text,
    affected text,
    reachability text,
    quality_tier text,
    imported_from text,
    cve_id text,
    ghsa_id text,
    cvss_vector text,
    cvss_score numeric,
    cvss_v4_vector text,
    cvss_v4_score numeric,
    fix_version text,
    fix_commit text,
    released_at timestamp with time zone,
    release_tag text,
    release_url text,
    resolution text,
    disclosure_draft text,
    assignee text,
    last_revalidate_verdict text,
    suggested_fix text,
    suggested_fix_commit text,
    breaking_change text,
    breaking_change_rationale text,
    exploited_in_wild text,
    exploited_in_wild_evidence text,
    mitigation text,
    mitigation_semgrep text,
    trace text,
    boundary text,
    validation text,
    prior_art text,
    reach text,
    rating text,
    created_at timestamp with time zone,
    updated_at timestamp with time zone
);


--
-- Name: findings_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.findings_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: findings_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.findings_id_seq OWNED BY public.findings.id;


--
-- Name: goqite; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.goqite (
    id text DEFAULT ('m_'::text || encode(public.gen_random_bytes(16), 'hex'::text)) NOT NULL,
    created timestamp with time zone DEFAULT now() NOT NULL,
    updated timestamp with time zone DEFAULT now() NOT NULL,
    queue text NOT NULL,
    body bytea NOT NULL,
    timeout timestamp with time zone DEFAULT now() NOT NULL,
    received integer DEFAULT 0 NOT NULL,
    priority integer DEFAULT 0 NOT NULL
);


--
-- Name: maintainers; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.maintainers (
    id bigint NOT NULL,
    login text NOT NULL,
    name text,
    email text,
    company text,
    avatar_url text,
    status text DEFAULT 'unknown'::text,
    notes text,
    do_not_contact boolean,
    created_at timestamp with time zone,
    updated_at timestamp with time zone
);


--
-- Name: maintainers_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.maintainers_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: maintainers_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.maintainers_id_seq OWNED BY public.maintainers.id;


--
-- Name: packages; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.packages (
    id bigint NOT NULL,
    repository_id bigint NOT NULL,
    name text,
    ecosystem text,
    p_url text,
    licenses text,
    latest_version text,
    versions_count bigint,
    downloads bigint,
    dependent_packages bigint,
    dependent_repos bigint,
    registry_url text,
    latest_release_at timestamp with time zone,
    dependent_packages_url text,
    metadata text,
    created_at timestamp with time zone
);


--
-- Name: packages_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.packages_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: packages_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.packages_id_seq OWNED BY public.packages.id;


--
-- Name: repositories; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.repositories (
    id bigint NOT NULL,
    url text NOT NULL,
    name text NOT NULL,
    full_name text,
    owner text,
    description text,
    default_branch text,
    languages text,
    license text,
    stars bigint,
    forks bigint,
    archived boolean,
    pushed_at timestamp with time zone,
    html_url text,
    icon_url text,
    metadata text,
    fetched_at timestamp with time zone,
    ecosystems_repo_data text,
    ecosystems_repo_fetched_at timestamp with time zone,
    ecosystems_packages_data text,
    ecosystems_packages_fetched_at timestamp with time zone,
    ecosystems_advisories_data text,
    ecosystems_advisories_fetched_at timestamp with time zone,
    ecosystems_commits_data text,
    ecosystems_commits_fetched_at timestamp with time zone,
    ecosystems_issues_data text,
    ecosystems_issues_fetched_at timestamp with time zone,
    ecosystems_dependents_data text,
    ecosystems_dependents_fetched_at timestamp with time zone,
    disclosure_channel text,
    posture text,
    posture_summary text,
    fork text,
    clone_error text,
    disk_bytes bigint,
    threat_model text,
    created_at timestamp with time zone,
    updated_at timestamp with time zone
);


--
-- Name: repositories_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.repositories_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: repositories_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.repositories_id_seq OWNED BY public.repositories.id;


--
-- Name: repository_maintainers; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.repository_maintainers (
    maintainer_id bigint NOT NULL,
    repository_id bigint NOT NULL
);


--
-- Name: sbom_packages; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.sbom_packages (
    id bigint NOT NULL,
    sbom_upload_id bigint NOT NULL,
    name text,
    version text,
    p_url text,
    ecosystem text,
    license text,
    scope text,
    repository_id bigint,
    resolve_error text,
    created_at timestamp with time zone
);


--
-- Name: sbom_packages_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.sbom_packages_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: sbom_packages_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.sbom_packages_id_seq OWNED BY public.sbom_packages.id;


--
-- Name: sbom_uploads; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.sbom_uploads (
    id bigint NOT NULL,
    name text,
    filename text,
    format text,
    spec_version text,
    raw bytea,
    package_count bigint,
    created_at timestamp with time zone,
    updated_at timestamp with time zone
);


--
-- Name: sbom_uploads_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.sbom_uploads_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: sbom_uploads_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.sbom_uploads_id_seq OWNED BY public.sbom_uploads.id;


--
-- Name: scans; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.scans (
    id bigint NOT NULL,
    repository_id bigint NOT NULL,
    kind text NOT NULL,
    status text NOT NULL,
    model text,
    effort text,
    skill_id bigint,
    skill_version bigint,
    skill_name text,
    finding_id bigint,
    dependent_id bigint,
    baseline_scan_id bigint,
    api_token text,
    status_priority bigint,
    ref text,
    skills_repo_sha text,
    sub_path text,
    profile text,
    session_id text,
    max_turns_hit boolean DEFAULT false NOT NULL,
    resumed_from_scan_id bigint,
    commit text,
    started_at timestamp with time zone,
    finished_at timestamp with time zone,
    cost_usd numeric,
    turns bigint,
    input_tokens bigint,
    output_tokens bigint,
    cache_read_tokens bigint,
    cache_write_tokens bigint,
    prompt text,
    report text,
    log text,
    error text,
    import_payload bytea,
    findings_count bigint,
    created_at timestamp with time zone,
    updated_at timestamp with time zone
);


--
-- Name: scans_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.scans_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: scans_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.scans_id_seq OWNED BY public.scans.id;


--
-- Name: settings; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.settings (
    key text NOT NULL,
    value text
);


--
-- Name: skills; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.skills (
    id bigint NOT NULL,
    name text NOT NULL,
    description text,
    license text,
    compatibility text,
    allowed_tools text,
    metadata text,
    body text,
    schema_json text,
    output_file text,
    output_kind text,
    max_turns bigint,
    model text,
    min_confidence text,
    report_on text,
    fail_on text,
    version bigint DEFAULT 1 NOT NULL,
    active boolean DEFAULT true NOT NULL,
    requires_remote boolean,
    requires_profile text,
    paths text,
    ignore_paths text,
    requires text,
    source text,
    source_path text,
    source_hash text,
    created_at timestamp with time zone,
    updated_at timestamp with time zone
);


--
-- Name: skills_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.skills_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: skills_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.skills_id_seq OWNED BY public.skills.id;


--
-- Name: subprojects; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.subprojects (
    id bigint NOT NULL,
    repository_id bigint NOT NULL,
    path text NOT NULL,
    name text,
    kind text,
    description text,
    created_at timestamp with time zone,
    updated_at timestamp with time zone
);


--
-- Name: subprojects_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.subprojects_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: subprojects_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.subprojects_id_seq OWNED BY public.subprojects.id;


--
-- Name: advisories id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.advisories ALTER COLUMN id SET DEFAULT nextval('public.advisories_id_seq'::regclass);


--
-- Name: cnas id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.cnas ALTER COLUMN id SET DEFAULT nextval('public.cnas_id_seq'::regclass);


--
-- Name: dependencies id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.dependencies ALTER COLUMN id SET DEFAULT nextval('public.dependencies_id_seq'::regclass);


--
-- Name: dependents id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.dependents ALTER COLUMN id SET DEFAULT nextval('public.dependents_id_seq'::regclass);


--
-- Name: finding_communications id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.finding_communications ALTER COLUMN id SET DEFAULT nextval('public.finding_communications_id_seq'::regclass);


--
-- Name: finding_dependents id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.finding_dependents ALTER COLUMN id SET DEFAULT nextval('public.finding_dependents_id_seq'::regclass);


--
-- Name: finding_histories id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.finding_histories ALTER COLUMN id SET DEFAULT nextval('public.finding_histories_id_seq'::regclass);


--
-- Name: finding_labels id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.finding_labels ALTER COLUMN id SET DEFAULT nextval('public.finding_labels_id_seq'::regclass);


--
-- Name: finding_notes id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.finding_notes ALTER COLUMN id SET DEFAULT nextval('public.finding_notes_id_seq'::regclass);


--
-- Name: finding_references id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.finding_references ALTER COLUMN id SET DEFAULT nextval('public.finding_references_id_seq'::regclass);


--
-- Name: finding_reviews id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.finding_reviews ALTER COLUMN id SET DEFAULT nextval('public.finding_reviews_id_seq'::regclass);


--
-- Name: findings id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.findings ALTER COLUMN id SET DEFAULT nextval('public.findings_id_seq'::regclass);


--
-- Name: maintainers id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.maintainers ALTER COLUMN id SET DEFAULT nextval('public.maintainers_id_seq'::regclass);


--
-- Name: packages id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.packages ALTER COLUMN id SET DEFAULT nextval('public.packages_id_seq'::regclass);


--
-- Name: repositories id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.repositories ALTER COLUMN id SET DEFAULT nextval('public.repositories_id_seq'::regclass);


--
-- Name: sbom_packages id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.sbom_packages ALTER COLUMN id SET DEFAULT nextval('public.sbom_packages_id_seq'::regclass);


--
-- Name: sbom_uploads id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.sbom_uploads ALTER COLUMN id SET DEFAULT nextval('public.sbom_uploads_id_seq'::regclass);


--
-- Name: scans id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.scans ALTER COLUMN id SET DEFAULT nextval('public.scans_id_seq'::regclass);


--
-- Name: skills id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.skills ALTER COLUMN id SET DEFAULT nextval('public.skills_id_seq'::regclass);


--
-- Name: subprojects id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.subprojects ALTER COLUMN id SET DEFAULT nextval('public.subprojects_id_seq'::regclass);


--
-- Name: advisories advisories_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.advisories
    ADD CONSTRAINT advisories_pkey PRIMARY KEY (id);


--
-- Name: cnas cnas_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.cnas
    ADD CONSTRAINT cnas_pkey PRIMARY KEY (id);


--
-- Name: dependencies dependencies_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.dependencies
    ADD CONSTRAINT dependencies_pkey PRIMARY KEY (id);


--
-- Name: dependents dependents_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.dependents
    ADD CONSTRAINT dependents_pkey PRIMARY KEY (id);


--
-- Name: finding_communications finding_communications_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.finding_communications
    ADD CONSTRAINT finding_communications_pkey PRIMARY KEY (id);


--
-- Name: finding_dependents finding_dependents_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.finding_dependents
    ADD CONSTRAINT finding_dependents_pkey PRIMARY KEY (id);


--
-- Name: finding_histories finding_histories_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.finding_histories
    ADD CONSTRAINT finding_histories_pkey PRIMARY KEY (id);


--
-- Name: finding_labels_join finding_labels_join_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.finding_labels_join
    ADD CONSTRAINT finding_labels_join_pkey PRIMARY KEY (finding_id, finding_label_id);


--
-- Name: finding_labels finding_labels_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.finding_labels
    ADD CONSTRAINT finding_labels_pkey PRIMARY KEY (id);


--
-- Name: finding_notes finding_notes_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.finding_notes
    ADD CONSTRAINT finding_notes_pkey PRIMARY KEY (id);


--
-- Name: finding_references finding_references_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.finding_references
    ADD CONSTRAINT finding_references_pkey PRIMARY KEY (id);


--
-- Name: finding_reviews finding_reviews_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.finding_reviews
    ADD CONSTRAINT finding_reviews_pkey PRIMARY KEY (id);


--
-- Name: findings findings_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.findings
    ADD CONSTRAINT findings_pkey PRIMARY KEY (id);


--
-- Name: goqite goqite_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.goqite
    ADD CONSTRAINT goqite_pkey PRIMARY KEY (id);


--
-- Name: maintainers maintainers_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.maintainers
    ADD CONSTRAINT maintainers_pkey PRIMARY KEY (id);


--
-- Name: packages packages_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.packages
    ADD CONSTRAINT packages_pkey PRIMARY KEY (id);


--
-- Name: repositories repositories_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.repositories
    ADD CONSTRAINT repositories_pkey PRIMARY KEY (id);


--
-- Name: repository_maintainers repository_maintainers_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.repository_maintainers
    ADD CONSTRAINT repository_maintainers_pkey PRIMARY KEY (maintainer_id, repository_id);


--
-- Name: sbom_packages sbom_packages_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.sbom_packages
    ADD CONSTRAINT sbom_packages_pkey PRIMARY KEY (id);


--
-- Name: sbom_uploads sbom_uploads_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.sbom_uploads
    ADD CONSTRAINT sbom_uploads_pkey PRIMARY KEY (id);


--
-- Name: scans scans_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.scans
    ADD CONSTRAINT scans_pkey PRIMARY KEY (id);


--
-- Name: settings settings_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.settings
    ADD CONSTRAINT settings_pkey PRIMARY KEY (key);


--
-- Name: skills skills_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.skills
    ADD CONSTRAINT skills_pkey PRIMARY KEY (id);


--
-- Name: subprojects subprojects_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.subprojects
    ADD CONSTRAINT subprojects_pkey PRIMARY KEY (id);


--
-- Name: goqite_queue_priority_created_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX goqite_queue_priority_created_idx ON public.goqite USING btree (queue, priority DESC, created);


--
-- Name: idx_advisories_published_at; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_advisories_published_at ON public.advisories USING btree (published_at);


--
-- Name: idx_advisories_repository_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_advisories_repository_id ON public.advisories USING btree (repository_id);


--
-- Name: idx_advisories_severity; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_advisories_severity ON public.advisories USING btree (severity);


--
-- Name: idx_cnas_cna_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_cnas_cna_id ON public.cnas USING btree (cna_id);


--
-- Name: idx_cnas_short_name; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX idx_cnas_short_name ON public.cnas USING btree (short_name);


--
-- Name: idx_dependencies_ecosystem; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_dependencies_ecosystem ON public.dependencies USING btree (ecosystem);


--
-- Name: idx_dependencies_repository_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_dependencies_repository_id ON public.dependencies USING btree (repository_id);


--
-- Name: idx_dependents_dependent_repos; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_dependents_dependent_repos ON public.dependents USING btree (dependent_repos);


--
-- Name: idx_dependents_downloads; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_dependents_downloads ON public.dependents USING btree (downloads);


--
-- Name: idx_dependents_repository_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_dependents_repository_id ON public.dependents USING btree (repository_id);


--
-- Name: idx_finding_communications_finding_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_finding_communications_finding_id ON public.finding_communications USING btree (finding_id);


--
-- Name: idx_finding_dependent; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX idx_finding_dependent ON public.finding_dependents USING btree (finding_id, dependent_id);


--
-- Name: idx_finding_dependents_dependent_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_finding_dependents_dependent_id ON public.finding_dependents USING btree (dependent_id);


--
-- Name: idx_finding_dependents_finding_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_finding_dependents_finding_id ON public.finding_dependents USING btree (finding_id);


--
-- Name: idx_finding_dependents_status; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_finding_dependents_status ON public.finding_dependents USING btree (status);


--
-- Name: idx_finding_histories_field; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_finding_histories_field ON public.finding_histories USING btree (field);


--
-- Name: idx_finding_histories_finding_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_finding_histories_finding_id ON public.finding_histories USING btree (finding_id);


--
-- Name: idx_finding_histories_source; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_finding_histories_source ON public.finding_histories USING btree (source);


--
-- Name: idx_finding_labels_name; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX idx_finding_labels_name ON public.finding_labels USING btree (name);


--
-- Name: idx_finding_notes_finding_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_finding_notes_finding_id ON public.finding_notes USING btree (finding_id);


--
-- Name: idx_finding_references_finding_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_finding_references_finding_id ON public.finding_references USING btree (finding_id);


--
-- Name: idx_finding_reviews_automated_outcome; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_finding_reviews_automated_outcome ON public.finding_reviews USING btree (automated_outcome);


--
-- Name: idx_finding_reviews_finding_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_finding_reviews_finding_id ON public.finding_reviews USING btree (finding_id);


--
-- Name: idx_finding_reviews_verdict; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_finding_reviews_verdict ON public.finding_reviews USING btree (verdict);


--
-- Name: idx_findings_assignee; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_findings_assignee ON public.findings USING btree (assignee);


--
-- Name: idx_findings_breaking_change; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_findings_breaking_change ON public.findings USING btree (breaking_change);


--
-- Name: idx_findings_confidence; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_findings_confidence ON public.findings USING btree (confidence);


--
-- Name: idx_findings_exploited_in_wild; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_findings_exploited_in_wild ON public.findings USING btree (exploited_in_wild);


--
-- Name: idx_findings_imported_from; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_findings_imported_from ON public.findings USING btree (imported_from);


--
-- Name: idx_findings_last_revalidate_verdict; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_findings_last_revalidate_verdict ON public.findings USING btree (last_revalidate_verdict);


--
-- Name: idx_findings_quality_tier; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_findings_quality_tier ON public.findings USING btree (quality_tier);


--
-- Name: idx_findings_reachability; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_findings_reachability ON public.findings USING btree (reachability);


--
-- Name: idx_findings_repo_fp; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_findings_repo_fp ON public.findings USING btree (repository_id, fingerprint);


--
-- Name: idx_findings_repository_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_findings_repository_id ON public.findings USING btree (repository_id);


--
-- Name: idx_findings_resolution; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_findings_resolution ON public.findings USING btree (resolution);


--
-- Name: idx_findings_scan_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_findings_scan_id ON public.findings USING btree (scan_id);


--
-- Name: idx_findings_severity; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_findings_severity ON public.findings USING btree (severity);


--
-- Name: idx_findings_status; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_findings_status ON public.findings USING btree (status);


--
-- Name: idx_findings_sub_path; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_findings_sub_path ON public.findings USING btree (sub_path);


--
-- Name: idx_findings_v_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_findings_v_id ON public.findings USING btree (vid);


--
-- Name: idx_maintainers_do_not_contact; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_maintainers_do_not_contact ON public.maintainers USING btree (do_not_contact);


--
-- Name: idx_maintainers_login; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX idx_maintainers_login ON public.maintainers USING btree (login);


--
-- Name: idx_maintainers_status; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_maintainers_status ON public.maintainers USING btree (status);


--
-- Name: idx_packages_dependent_repos; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_packages_dependent_repos ON public.packages USING btree (dependent_repos);


--
-- Name: idx_packages_downloads; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_packages_downloads ON public.packages USING btree (downloads);


--
-- Name: idx_packages_ecosystem; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_packages_ecosystem ON public.packages USING btree (ecosystem);


--
-- Name: idx_packages_repository_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_packages_repository_id ON public.packages USING btree (repository_id);


--
-- Name: idx_repositories_name; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_repositories_name ON public.repositories USING btree (name);


--
-- Name: idx_repositories_posture; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_repositories_posture ON public.repositories USING btree (posture);


--
-- Name: idx_repositories_stars; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_repositories_stars ON public.repositories USING btree (stars);


--
-- Name: idx_repositories_url; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX idx_repositories_url ON public.repositories USING btree (url);


--
-- Name: idx_sbom_packages_p_url; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_sbom_packages_p_url ON public.sbom_packages USING btree (p_url);


--
-- Name: idx_sbom_packages_repository_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_sbom_packages_repository_id ON public.sbom_packages USING btree (repository_id);


--
-- Name: idx_sbom_packages_sbom_upload_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_sbom_packages_sbom_upload_id ON public.sbom_packages USING btree (sbom_upload_id);


--
-- Name: idx_sbom_packages_scope; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_sbom_packages_scope ON public.sbom_packages USING btree (scope);


--
-- Name: idx_scans_api_token; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_scans_api_token ON public.scans USING btree (api_token);


--
-- Name: idx_scans_baseline_scan_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_scans_baseline_scan_id ON public.scans USING btree (baseline_scan_id);


--
-- Name: idx_scans_dependent_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_scans_dependent_id ON public.scans USING btree (dependent_id);


--
-- Name: idx_scans_finding_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_scans_finding_id ON public.scans USING btree (finding_id);


--
-- Name: idx_scans_kind; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_scans_kind ON public.scans USING btree (kind);


--
-- Name: idx_scans_priority_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_scans_priority_id ON public.scans USING btree (status_priority, id DESC);


--
-- Name: idx_scans_profile; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_scans_profile ON public.scans USING btree (profile);


--
-- Name: idx_scans_repository_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_scans_repository_id ON public.scans USING btree (repository_id);


--
-- Name: idx_scans_resumed_from_scan_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_scans_resumed_from_scan_id ON public.scans USING btree (resumed_from_scan_id);


--
-- Name: idx_scans_skill_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_scans_skill_id ON public.scans USING btree (skill_id);


--
-- Name: idx_scans_skill_name; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_scans_skill_name ON public.scans USING btree (skill_name);


--
-- Name: idx_scans_status; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_scans_status ON public.scans USING btree (status);


--
-- Name: idx_scans_sub_path; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_scans_sub_path ON public.scans USING btree (sub_path);


--
-- Name: idx_skills_name; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX idx_skills_name ON public.skills USING btree (name);


--
-- Name: idx_skills_output_kind; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_skills_output_kind ON public.skills USING btree (output_kind);


--
-- Name: idx_subprojects_kind; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_subprojects_kind ON public.subprojects USING btree (kind);


--
-- Name: idx_subprojects_repository_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_subprojects_repository_id ON public.subprojects USING btree (repository_id);


--
-- Name: goqite goqite_updated_timestamp; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER goqite_updated_timestamp BEFORE UPDATE ON public.goqite FOR EACH ROW EXECUTE FUNCTION public.goqite_update_timestamp();


--
-- Name: finding_labels_join fk_finding_labels_join_finding; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.finding_labels_join
    ADD CONSTRAINT fk_finding_labels_join_finding FOREIGN KEY (finding_id) REFERENCES public.findings(id);


--
-- Name: finding_labels_join fk_finding_labels_join_finding_label; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.finding_labels_join
    ADD CONSTRAINT fk_finding_labels_join_finding_label FOREIGN KEY (finding_label_id) REFERENCES public.finding_labels(id);


--
-- Name: finding_communications fk_findings_communications; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.finding_communications
    ADD CONSTRAINT fk_findings_communications FOREIGN KEY (finding_id) REFERENCES public.findings(id) ON DELETE CASCADE;


--
-- Name: finding_histories fk_findings_history; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.finding_histories
    ADD CONSTRAINT fk_findings_history FOREIGN KEY (finding_id) REFERENCES public.findings(id) ON DELETE CASCADE;


--
-- Name: finding_notes fk_findings_notes; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.finding_notes
    ADD CONSTRAINT fk_findings_notes FOREIGN KEY (finding_id) REFERENCES public.findings(id) ON DELETE CASCADE;


--
-- Name: finding_references fk_findings_references; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.finding_references
    ADD CONSTRAINT fk_findings_references FOREIGN KEY (finding_id) REFERENCES public.findings(id) ON DELETE CASCADE;


--
-- Name: scans fk_findings_scan; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.scans
    ADD CONSTRAINT fk_findings_scan FOREIGN KEY (finding_id) REFERENCES public.findings(id);


--
-- Name: packages fk_packages_repository; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.packages
    ADD CONSTRAINT fk_packages_repository FOREIGN KEY (repository_id) REFERENCES public.repositories(id);


--
-- Name: scans fk_repositories_scans; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.scans
    ADD CONSTRAINT fk_repositories_scans FOREIGN KEY (repository_id) REFERENCES public.repositories(id) ON DELETE CASCADE;


--
-- Name: repository_maintainers fk_repository_maintainers_maintainer; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.repository_maintainers
    ADD CONSTRAINT fk_repository_maintainers_maintainer FOREIGN KEY (maintainer_id) REFERENCES public.maintainers(id);


--
-- Name: repository_maintainers fk_repository_maintainers_repository; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.repository_maintainers
    ADD CONSTRAINT fk_repository_maintainers_repository FOREIGN KEY (repository_id) REFERENCES public.repositories(id);


--
-- Name: sbom_packages fk_sbom_packages_repository; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.sbom_packages
    ADD CONSTRAINT fk_sbom_packages_repository FOREIGN KEY (repository_id) REFERENCES public.repositories(id);


--
-- Name: sbom_packages fk_sbom_uploads_packages; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.sbom_packages
    ADD CONSTRAINT fk_sbom_uploads_packages FOREIGN KEY (sbom_upload_id) REFERENCES public.sbom_uploads(id) ON DELETE CASCADE;


--
-- Name: findings fk_scans_findings; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.findings
    ADD CONSTRAINT fk_scans_findings FOREIGN KEY (scan_id) REFERENCES public.scans(id) ON DELETE CASCADE;


--
-- PostgreSQL database dump complete
--

\unrestrict 8PJRx7K6xAKDVk0U4YNXkMnn5e3i5YlMyHGkH113mXL54AA7TKcgBDYeLhLGRbZ

