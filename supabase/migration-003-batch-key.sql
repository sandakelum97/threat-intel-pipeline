-- Migration 003 – browser release batches (Chrome/Firefox/Edge) collapse to one line in email + dashboard
alter table public.cve_watch add column if not exists batch_key text;
create index if not exists cve_watch_batch_idx on public.cve_watch (batch_key) where batch_key is not null;
