-- Migration 007: SSVC deployer decision layer (thesis Phase 5, step 1)
--
-- SSVC = Stakeholder-Specific Vulnerability Categorization (CERT/CC).
-- Four inputs decide one of four actions:
--   Exploitation    none | public poc | active          (public: CISA Vulnrichment)
--   System Exposure small | controlled | open            (environment: derived from asset data)
--   Automatable     no | yes                             (public: CISA Vulnrichment)
--   Human Impact    low | medium | high | very high       (environment: from Mission + Safety Impact)
--   -> action       defer < scheduled < out-of-cycle < immediate
--
-- Source: CERT/CC decision table DT_DP 1.0.0
--   (CERTCC/SSVC data/csv/ssvc/deployer_patch_application_priority_1_0_0.csv),
--   checked row by row against it: 72/72 identical.
-- Read-only reference data; no client data in this file.

create table if not exists public.ssvc_deployer_decision (
  exploitation    text not null check (exploitation in ('none','public poc','active')),
  system_exposure text not null check (system_exposure in ('small','controlled','open')),
  automatable     text not null check (automatable in ('no','yes')),
  human_impact    text not null check (human_impact in ('low','medium','high','very high')),
  outcome         text not null check (outcome in ('defer','scheduled','out-of-cycle','immediate')),
  primary key (exploitation, system_exposure, automatable, human_impact)
);

insert into public.ssvc_deployer_decision (exploitation, system_exposure, automatable, human_impact, outcome) values
  ('none','small','no','low','defer'),
  ('none','small','no','medium','defer'),
  ('none','small','no','high','scheduled'),
  ('none','small','no','very high','scheduled'),
  ('none','small','yes','low','defer'),
  ('none','small','yes','medium','scheduled'),
  ('none','small','yes','high','scheduled'),
  ('none','small','yes','very high','scheduled'),
  ('none','controlled','no','low','defer'),
  ('none','controlled','no','medium','scheduled'),
  ('none','controlled','no','high','scheduled'),
  ('none','controlled','no','very high','scheduled'),
  ('none','controlled','yes','low','scheduled'),
  ('none','controlled','yes','medium','scheduled'),
  ('none','controlled','yes','high','scheduled'),
  ('none','controlled','yes','very high','scheduled'),
  ('none','open','no','low','defer'),
  ('none','open','no','medium','scheduled'),
  ('none','open','no','high','scheduled'),
  ('none','open','no','very high','scheduled'),
  ('none','open','yes','low','scheduled'),
  ('none','open','yes','medium','scheduled'),
  ('none','open','yes','high','scheduled'),
  ('none','open','yes','very high','out-of-cycle'),
  ('public poc','small','no','low','defer'),
  ('public poc','small','no','medium','scheduled'),
  ('public poc','small','no','high','scheduled'),
  ('public poc','small','no','very high','scheduled'),
  ('public poc','small','yes','low','scheduled'),
  ('public poc','small','yes','medium','scheduled'),
  ('public poc','small','yes','high','scheduled'),
  ('public poc','small','yes','very high','scheduled'),
  ('public poc','controlled','no','low','defer'),
  ('public poc','controlled','no','medium','scheduled'),
  ('public poc','controlled','no','high','scheduled'),
  ('public poc','controlled','no','very high','scheduled'),
  ('public poc','controlled','yes','low','scheduled'),
  ('public poc','controlled','yes','medium','scheduled'),
  ('public poc','controlled','yes','high','scheduled'),
  ('public poc','controlled','yes','very high','out-of-cycle'),
  ('public poc','open','no','low','scheduled'),
  ('public poc','open','no','medium','scheduled'),
  ('public poc','open','no','high','scheduled'),
  ('public poc','open','no','very high','out-of-cycle'),
  ('public poc','open','yes','low','scheduled'),
  ('public poc','open','yes','medium','scheduled'),
  ('public poc','open','yes','high','out-of-cycle'),
  ('public poc','open','yes','very high','out-of-cycle'),
  ('active','small','no','low','scheduled'),
  ('active','small','no','medium','scheduled'),
  ('active','small','no','high','out-of-cycle'),
  ('active','small','no','very high','out-of-cycle'),
  ('active','small','yes','low','scheduled'),
  ('active','small','yes','medium','out-of-cycle'),
  ('active','small','yes','high','out-of-cycle'),
  ('active','small','yes','very high','out-of-cycle'),
  ('active','controlled','no','low','scheduled'),
  ('active','controlled','no','medium','scheduled'),
  ('active','controlled','no','high','out-of-cycle'),
  ('active','controlled','no','very high','out-of-cycle'),
  ('active','controlled','yes','low','out-of-cycle'),
  ('active','controlled','yes','medium','out-of-cycle'),
  ('active','controlled','yes','high','out-of-cycle'),
  ('active','controlled','yes','very high','out-of-cycle'),
  ('active','open','no','low','scheduled'),
  ('active','open','no','medium','out-of-cycle'),
  ('active','open','no','high','out-of-cycle'),
  ('active','open','no','very high','immediate'),
  ('active','open','yes','low','out-of-cycle'),
  ('active','open','yes','medium','out-of-cycle'),
  ('active','open','yes','high','immediate'),
  ('active','open','yes','very high','immediate')
on conflict (exploitation, system_exposure, automatable, human_impact) do update set outcome = excluded.outcome;

alter table public.ssvc_deployer_decision enable row level security;
drop policy if exists "public read ssvc_deployer_decision" on public.ssvc_deployer_decision;
create policy "public read ssvc_deployer_decision" on public.ssvc_deployer_decision for select using (true);

-- Human Impact from Mission Impact and Safety Impact (CERT/CC DT_HI 1.0.0), first match wins.
-- mission: degraded | mef_support_crippled | mef_failure | mission_failure
-- safety : negligible | marginal | critical | catastrophic
create or replace function public.ssvc_human_impact(mission text, safety text)
returns text language sql immutable as $$
  select case
    when lower(safety)  = 'catastrophic'                                      then 'very high'
    when lower(mission) = 'mission_failure'                                   then 'very high'
    when lower(safety)  = 'critical' and lower(mission) in ('mef_support_crippled','mef_failure') then 'high'
    when lower(safety)  = 'critical' and lower(mission) = 'degraded'          then 'medium'
    when lower(mission) = 'mef_failure'                                       then 'medium'
    else 'low'
  end
$$;

-- The action for four inputs. Accepts Vulnrichment's 'poc' spelling.
-- Missing Exploitation / Automatable fall back to CERT/CC defaults (none / yes);
-- missing System Exposure falls back to 'open' (rule R1, the safe side).
-- Returns the action plus which inputs were defaulted, so the dashboard can show
-- "default used" and keep those decisions in a separate, lower-confidence queue.
create or replace function public.ssvc_decide(
  p_exploitation text, p_system_exposure text, p_automatable text, p_human_impact text)
returns table (outcome text, exploitation text, system_exposure text, automatable text,
               human_impact text, defaults_used text[])
language sql stable as $$
  with norm as (
    select
      case when p_exploitation is null or p_exploitation = '' then 'none'
           when lower(p_exploitation) in ('poc','public poc','public_poc') then 'public poc'
           else lower(p_exploitation) end as e,
      coalesce(nullif(lower(p_system_exposure), ''), 'open') as x,
      coalesce(nullif(lower(p_automatable), ''), 'yes')      as a,
      lower(p_human_impact) as h,
      array_remove(array[
        case when p_exploitation    is null or p_exploitation    = '' then 'exploitation' end,
        case when p_system_exposure is null or p_system_exposure = '' then 'system_exposure' end,
        case when p_automatable     is null or p_automatable     = '' then 'automatable' end
      ], null) as d
  )
  select t.outcome, n.e, n.x, n.a, n.h, n.d
  from norm n
  join public.ssvc_deployer_decision t
    on t.exploitation = n.e and t.system_exposure = n.x
   and t.automatable = n.a and t.human_impact = n.h
$$;
