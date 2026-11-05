-- Migration 004 – product groups + Claude summaries
alter table public.kev_entries add column if not exists product_group text, add column if not exists ai_summary text, add column if not exists ai_reason text;
alter table public.cve_watch   add column if not exists product_group text, add column if not exists ai_summary text, add column if not exists ai_reason text;
alter table public.articles    add column if not exists product_group text, add column if not exists ai_summary text;
create index if not exists kev_group_idx   on public.kev_entries (product_group);
create index if not exists watch_group_idx on public.cve_watch (product_group);
create index if not exists art_group_idx   on public.articles (product_group);
-- let TI 05 re-visit existing KEV rows to add product_group + summaries
update public.kev_entries set enriched_at = null where ai_summary is null;
