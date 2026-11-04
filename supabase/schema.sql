-- Threat Intel Pipeline – Supabase schema
-- Run once in the Supabase SQL editor. n8n writes with the service-role key (bypasses RLS);
-- the dashboard reads with the anon key under the read-only policies below.

create table if not exists public.kev_entries (
  cve_id          text primary key,
  vendor          text,
  product         text,
  vuln_name       text,
  description     text,
  required_action text,
  date_added      date,
  due_date        date,
  ransomware      text,            -- 'Known' | 'Unknown'
  matched_vendor  text,            -- allowlist term that matched
  catalog_version text,
  created_at      timestamptz not null default now()
);

create table if not exists public.articles (
  link          text primary key,
  title         text,
  source        text,
  published_at  timestamptz,
  summary       text,
  score         int not null default 0,
  matched_terms text[] default '{}',
  relevant      boolean not null default false,
  ai_verdict    boolean,           -- filled by the optional Claude step
  ai_reason     text,
  created_at    timestamptz not null default now()
);

create table if not exists public.digest_log (
  id          bigserial primary key,
  sent_at     timestamptz not null default now(),
  kind        text,                -- 'kev' | 'news'
  item_count  int,
  payload     jsonb
);

create index if not exists articles_published_idx on public.articles (published_at desc);
create index if not exists articles_relevant_idx  on public.articles (relevant, published_at desc);
create index if not exists kev_date_added_idx     on public.kev_entries (date_added desc);

-- Row-level security: anon (dashboard) can read, nobody but service role can write.
alter table public.kev_entries enable row level security;
alter table public.articles    enable row level security;
alter table public.digest_log  enable row level security;

drop policy if exists "anon read kev"     on public.kev_entries;
drop policy if exists "anon read articles" on public.articles;
drop policy if exists "anon read digests"  on public.digest_log;

create policy "anon read kev"      on public.kev_entries for select to anon using (true);
create policy "anon read articles" on public.articles    for select to anon using (true);
create policy "anon read digests"  on public.digest_log  for select to anon using (true);

-- Optional housekeeping: keep 90 days of articles (run via pg_cron or manually)
-- delete from public.articles where published_at < now() - interval '90 days';
