-- Migration 006: remediation facts from NVD / CISA
-- product_name   : the actual software from the CPE (e.g. "Google Brotli"), finer than product_group
-- fixed_versions : [{product, fixed, through}] from NVD version ranges (fixed = first non-vulnerable version)
-- advisory_url   : NVD reference tagged Patch / Vendor Advisory
-- remediation    : plain sentence built from the above (+ CISA required_action for KEV)
alter table public.cve_watch
  add column if not exists product_name   text,
  add column if not exists fixed_versions jsonb default '[]'::jsonb,
  add column if not exists advisory_url   text,
  add column if not exists remediation    text;
alter table public.kev_entries
  add column if not exists product_name   text,
  add column if not exists fixed_versions jsonb default '[]'::jsonb,
  add column if not exists advisory_url   text,
  add column if not exists remediation    text;
-- let TI 05 revisit rows so the new fields get filled (it processes 60 per run, oldest first)
update public.kev_entries set enriched_at = null where remediation is null;
