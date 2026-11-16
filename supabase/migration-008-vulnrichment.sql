-- Migration 008: CISA Vulnrichment SSVC inputs on kev_entries and cve_watch
--
-- Vulnrichment = CISA's public "ADP" (Authorized Data Publisher) enrichment of CVE records.
-- For each CVE it assesses three SSVC inputs:
--   Exploitation      none | poc | active
--   Automatable       no | yes
--   Technical Impact  partial | total
-- These are the two public inputs of the SSVC deployer tree (System Exposure and Human Impact
-- come from the client's own environment; see migration 009).
--
-- Not every CVE has been assessed. ssvc_status says which:
--   assessed      CISA published an SSVC block for this CVE
--   not_assessed  no Vulnrichment record (or no SSVC block in it) when last checked
-- For not_assessed CVEs the decision layer uses CERT/CC's defaults (Exploitation none,
-- Automatable yes) and flags them as "default used" (research finding A11 / A48).
--
-- Note (research finding A28/A29): Vulnrichment overwrites Exploitation when a CVE enters KEV.
-- Fine for live triage; never use these current values to back-test past decisions.

alter table public.kev_entries
  add column if not exists ssvc_exploitation     text check (ssvc_exploitation in ('none','poc','active')),
  add column if not exists ssvc_automatable      text check (ssvc_automatable in ('no','yes')),
  add column if not exists ssvc_technical_impact text check (ssvc_technical_impact in ('partial','total')),
  add column if not exists ssvc_status           text check (ssvc_status in ('assessed','not_assessed')),
  add column if not exists ssvc_assessed_at      timestamptz,   -- CISA's own timestamp on the assessment
  add column if not exists ssvc_checked_at       timestamptz;   -- when TI 08 last looked

alter table public.cve_watch
  add column if not exists ssvc_exploitation     text check (ssvc_exploitation in ('none','poc','active')),
  add column if not exists ssvc_automatable      text check (ssvc_automatable in ('no','yes')),
  add column if not exists ssvc_technical_impact text check (ssvc_technical_impact in ('partial','total')),
  add column if not exists ssvc_status           text check (ssvc_status in ('assessed','not_assessed')),
  add column if not exists ssvc_assessed_at      timestamptz,
  add column if not exists ssvc_checked_at       timestamptz;

create index if not exists kev_entries_ssvc_checked_idx on public.kev_entries (ssvc_checked_at nulls first);
create index if not exists cve_watch_ssvc_checked_idx   on public.cve_watch   (ssvc_checked_at nulls first);

-- Called by TI 08 with the service key: one call writes a whole batch to both tables.
-- rows = [{cve_id, exploitation, automatable, technical_impact, status, assessed_at}, ...]
create or replace function public.ssvc_apply(rows jsonb)
returns integer language plpgsql as $$
declare n integer := 0; k integer;
begin
  with r as (
    select x->>'cve_id' as cve_id,
           nullif(x->>'exploitation','') as e, nullif(x->>'automatable','') as a,
           nullif(x->>'technical_impact','') as t, x->>'status' as s,
           nullif(x->>'assessed_at','')::timestamptz as at
    from jsonb_array_elements(rows) x
    where x->>'cve_id' ~* '^CVE-[0-9]{4}-[0-9]{4,}$'
  )
  update public.kev_entries k set ssvc_exploitation = r.e, ssvc_automatable = r.a, ssvc_technical_impact = r.t,
         ssvc_status = r.s, ssvc_assessed_at = r.at, ssvc_checked_at = now()
  from r where k.cve_id = r.cve_id;
  get diagnostics k = row_count; n := n + k;

  with r as (
    select x->>'cve_id' as cve_id,
           nullif(x->>'exploitation','') as e, nullif(x->>'automatable','') as a,
           nullif(x->>'technical_impact','') as t, x->>'status' as s,
           nullif(x->>'assessed_at','')::timestamptz as at
    from jsonb_array_elements(rows) x
    where x->>'cve_id' ~* '^CVE-[0-9]{4}-[0-9]{4,}$'
  )
  update public.cve_watch w set ssvc_exploitation = r.e, ssvc_automatable = r.a, ssvc_technical_impact = r.t,
         ssvc_status = r.s, ssvc_assessed_at = r.at, ssvc_checked_at = now()
  from r where w.cve_id = r.cve_id;
  get diagnostics k = row_count; n := n + k;
  return n;
end $$;

-- Writes must not be callable with the public (anon) key that the dashboard uses.
revoke all on function public.ssvc_apply(jsonb) from public;
do $$ begin
  if exists (select 1 from pg_roles where rolname = 'anon')          then revoke all on function public.ssvc_apply(jsonb) from anon; end if;
  if exists (select 1 from pg_roles where rolname = 'authenticated') then revoke all on function public.ssvc_apply(jsonb) from authenticated; end if;
  if exists (select 1 from pg_roles where rolname = 'service_role')  then grant execute on function public.ssvc_apply(jsonb) to service_role; end if;
end $$;
