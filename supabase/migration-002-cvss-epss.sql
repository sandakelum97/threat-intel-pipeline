-- Migration 002 – CVSS/EPSS enrichment and CVE Watch
-- Run once in the Supabase SQL editor (safe to re-run).

-- 1. Enrichment columns on KEV
alter table public.kev_entries
  add column if not exists cvss_score     numeric(3,1),
  add column if not exists cvss_severity  text,          -- CRITICAL | HIGH | MEDIUM | LOW
  add column if not exists cvss_vector    text,
  add column if not exists cvss_version   text,          -- 4.0 | 3.1 | 3.0 | 2.0
  add column if not exists epss_score     numeric(6,5),  -- 0..1 probability of exploitation in 30 days
  add column if not exists epss_percentile numeric(6,5),
  add column if not exists enriched_at    timestamptz;

create index if not exists kev_enriched_idx on public.kev_entries (enriched_at) where enriched_at is null;

-- 2. CVE Watch: high-severity CVEs in our stack from NVD, before/without KEV listing
create table if not exists public.cve_watch (
  cve_id          text primary key,
  published_at    timestamptz,
  last_modified   timestamptz,
  description     text,
  cvss_score      numeric(3,1),
  cvss_severity   text,
  cvss_vector     text,
  cvss_version    text,
  epss_score      numeric(6,5),
  epss_percentile numeric(6,5),
  matched_vendor  text,
  cpe_vendors     text[] default '{}',
  cpe_products    text[] default '{}',
  references_count int default 0,
  created_at      timestamptz not null default now()
);

create index if not exists cve_watch_published_idx on public.cve_watch (published_at desc);
create index if not exists cve_watch_cvss_idx      on public.cve_watch (cvss_score desc);

alter table public.cve_watch enable row level security;
drop policy if exists "anon read cve_watch" on public.cve_watch;
create policy "anon read cve_watch" on public.cve_watch for select to anon using (true);

-- 3. digest_log doubles as the run log (kind = 'kev' | 'news' | 'news-collect' | 'cve-watch' | 'kev-enrich')
create index if not exists digest_log_kind_idx on public.digest_log (kind, sent_at desc);
