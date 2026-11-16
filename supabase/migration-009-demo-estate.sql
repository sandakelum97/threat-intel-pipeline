-- Migration 009: SSVC demo estate + decision view (thesis Phase 5, step 3)
--
-- WHAT THIS IS
--   A small, made-up client estate (3 tenants, 15 devices, their software) so the team can
--   see what an SSVC decision looks like next to a CVSS score, on real KEV / CVE Watch rows.
--
-- WHAT THIS IS NOT
--   * Not client data. Every tenant, device and version below is invented (tenant_01..03).
--   * Not thesis evidence. The thesis runs on its own, separate database; nothing here is
--     read by, or written to, the research database.
--
-- WHERE THE RULES COME FROM
--   The four environmental rules are transcribed from the thesis repo's executable views
--   (ssvc-environmental-automation, db/views/01..04, estate-v5), kept with the same rule IDs:
--     System Exposure  ssvc:EXP:1.0.1   R1..R9  (01_system_exposure_derivation.sql)
--     Mission Impact   ssvc:MI:2.0.0    M1..M5  (02_mission_impact_derivation.sql)
--     Safety Impact    ssvc:SI:2.0.1    S1..S4  (03_safety_impact_derivation.sql)
--     Human Impact     ssvc:DT_HI:1.0.0         (04 -> public.ssvc_human_impact, migration 007)
--   The final action comes from public.ssvc_decide (CERT/CC DT_DP 1.0.0, migration 007).
--   If a rule changes in the thesis repo, change it here too; the thesis repo wins.
--
-- MATCHING (demo simplification)
--   A device "has" a CVE when one of its software match_terms appears in the CVE's product
--   text. Versions are NOT compared, so this over-matches on purpose: treat every row as
--   "check this device", not "this device is vulnerable".
--
-- Needs migrations 002, 004, 006, 007 and 008 first. Safe to run twice.

-- ---------------------------------------------------------------------------
-- 1. Demo estate tables (column names kept identical to the thesis schema)
-- ---------------------------------------------------------------------------
create table if not exists public.demo_tenants (
  tenant_id            text primary key check (tenant_id ~ '^tenant_[0-9]{2}$'),
  sector               text not null,
  security_posture     text not null check (security_posture in ('basic','developing','established','advanced')),
  network_segmentation text not null check (network_segmentation in ('flat','partial','strict')),
  note                 text
);

create table if not exists public.demo_devices (
  device_id                 text primary key,
  tenant_id                 text not null references public.demo_tenants(tenant_id) on delete cascade,
  asset_class               text not null,   -- server | workstation | byod_endpoint | network_device | appliance
  business_function         text,            -- NULL = unknown (drives M5 / S4 defaults)
  network_zone              text,            -- dmz | cloud_public | perimeter | internal | ot
  seen_in_external_scan     boolean,         -- NULL = no scan data
  has_public_ip             boolean,         -- NULL = unknown
  managed_by_mssp           boolean not null default true,
  reachable_from_user_vlan  boolean,
  reachable_from_guest_vlan boolean,
  requires_auth             boolean,
  behind_vpn_only           boolean,
  behind_sase               boolean
);

create table if not exists public.demo_software (
  device_id      text not null references public.demo_devices(device_id) on delete cascade,
  match_term     text not null,   -- lower-case text looked for in the CVE's product fields
  display_name   text not null,
  version        text,
  end_of_support date,            -- vendor end of support; NULL = unknown / still supported
  primary key (device_id, match_term)
);

-- ---------------------------------------------------------------------------
-- 2. Synthetic data. Re-running replaces it.
-- ---------------------------------------------------------------------------
delete from public.demo_tenants where tenant_id in ('tenant_01','tenant_02','tenant_03');

insert into public.demo_tenants values
  ('tenant_01','healthcare',           'developing', 'partial', 'Made-up clinic group'),
  ('tenant_02','manufacturing',        'basic',      'flat',    'Made-up factory'),
  ('tenant_03','professional_services','advanced',   'strict',  'Made-up accounting firm');

insert into public.demo_devices
 (device_id, tenant_id, asset_class, business_function, network_zone, seen_in_external_scan, has_public_ip,
  managed_by_mssp, reachable_from_user_vlan, reachable_from_guest_vlan, requires_auth, behind_vpn_only, behind_sase) values
  -- tenant_01 healthcare
  ('t01-fw01',  'tenant_01','network_device','perimeter_firewall',     'perimeter', true,  true,  true, false,false,true, false,false),
  ('t01-vpn01', 'tenant_01','appliance',     'vpn_concentrator',       'dmz',       true,  true,  true, false,false,true, false,false),
  ('t01-ehr01', 'tenant_01','server',        'clinical_use',           'internal',  false, false, true, true, false,true, false,false),
  ('t01-dc01',  'tenant_01','server',        'directory_services',     'internal',  false, false, true, true, false,true, false,false),
  ('t01-ws014', 'tenant_01','workstation',   'reception',              'internal',  false, false, false,true, false,true, false,false),
  ('t01-bms01', 'tenant_01','server',        'building_management',    'internal',  false, false, true, false,false,false,false,false),
  -- tenant_02 manufacturing
  ('t02-ws003', 'tenant_02','workstation',   'engineering_workstation','internal',  false, false, false,true, true, false,false,false),
  ('t02-plc01', 'tenant_02','server',        'production_line_control','ot',        false, false, true, false,false,false,false,false),
  ('t02-file01','tenant_02','server',        'file_and_print',         'internal',  false, false, true, true, false,true, false,false),
  ('t02-mail01','tenant_02','server',        'email_gateway',          'dmz',       true,  true,  true, false,false,true, false,false),
  ('t02-old01', 'tenant_02','server',        null,                     'internal',  null,  null,  true, true, false,null, null, null),
  -- tenant_03 professional services
  ('t03-vh01',  'tenant_03','server',        'virtualisation_platform','internal',  false, false, true, false,false,true, false,false),
  ('t03-app01', 'tenant_03','server',        'internal_web_application','internal', false, false, true, false,false,true, true, false),
  ('t03-ws021', 'tenant_03','workstation',   'general_office',         'internal',  false, false, true, true, false,true, false,true),
  ('t03-dev01', 'tenant_03','server',        'development_test',       'internal',  false, false, true, false,false,false,false,false);

insert into public.demo_software (device_id, match_term, display_name, version, end_of_support) values
  ('t01-fw01',  'fortios',        'Fortinet FortiOS',           '7.2.8',        null),
  ('t01-vpn01', 'connect secure', 'Ivanti Connect Secure',      '22.7R2.3',     null),
  ('t01-ehr01', 'windows',        'Microsoft Windows Server',   '2019',         '2029-01-09'),
  ('t01-ehr01', 'sql server',     'Microsoft SQL Server',       '2016',         '2026-07-14'),
  ('t01-dc01',  'windows',        'Microsoft Windows Server',   '2016',         '2027-01-12'),
  ('t01-ws014', 'windows',        'Microsoft Windows 10',       '22H2',         '2025-10-14'),
  ('t01-ws014', 'chrome',         'Google Chrome',              '141',          null),
  ('t01-bms01', 'windows',        'Microsoft Windows Server',   '2012 R2',      '2023-10-10'),
  ('t02-ws003', 'windows',        'Microsoft Windows 11',       '23H2',         null),
  ('t02-ws003', 'firefox',        'Mozilla Firefox',            '140 ESR',      null),
  ('t02-ws003', '7-zip',          '7-Zip',                      '24.08',        null),
  ('t02-plc01', 'windows',        'Microsoft Windows 10 LTSC',  '2019',         '2029-01-09'),
  ('t02-file01','windows',        'Microsoft Windows Server',   '2022',         '2031-10-14'),
  ('t02-mail01','exchange',       'Microsoft Exchange Server',  '2019 CU14',    '2025-10-14'),
  ('t02-old01', 'windows',        'Microsoft Windows Server',   '2012',         '2023-10-10'),
  ('t03-vh01',  'vmware',         'VMware ESXi',                '8.0 U3',       null),
  ('t03-app01', 'sharepoint',     'Microsoft SharePoint Server','Subscription', null),
  ('t03-app01', 'windows',        'Microsoft Windows Server',   '2022',         '2031-10-14'),
  ('t03-ws021', 'windows',        'Microsoft Windows 11',       '24H2',         null),
  ('t03-ws021', 'chrome',         'Google Chrome',              '141',          null),
  ('t03-ws021', 'adobe',          'Adobe Acrobat Reader',       '2025',         null),
  ('t03-dev01', 'gitlab',         'GitLab CE',                  '17.x',         null);

-- ---------------------------------------------------------------------------
-- 3. Environmental decision points per device (rules transcribed from the thesis views)
-- ---------------------------------------------------------------------------
create or replace view public.demo_device_context as
with m as (
  select d.*, t.sector, t.security_posture, t.network_segmentation,
    case
      when d.business_function in ('core_switching','virtualisation_platform') then 'mission_failure'
      when (t.sector = 'healthcare' and d.business_function in ('clinical_use','core_transaction_processing'))
        or (t.sector = 'financial_services' and d.business_function in ('core_transaction_processing'))
        or (t.sector = 'manufacturing' and d.business_function in ('production_line_control'))
        or (t.sector = 'utilities' and d.business_function in ('production_line_control','environmental_control'))
        or (t.sector = 'education' and d.business_function in ('student_lab'))
        or (t.sector = 'ecommerce_retail' and d.business_function in ('core_transaction_processing','internal_web_application'))
        or (t.sector = 'professional_services' and d.business_function in ('file_and_print','internal_web_application')) then 'mef_failure'
      when d.business_function in ('directory_services','edge_routing','distribution_switching','email_gateway','backup',
             'reporting_and_analytics','perimeter_firewall','vpn_concentrator','web_proxy','wireless_access',
             'building_management','engineering_workstation','internal_web_application','file_and_print',
             'environmental_control','core_transaction_processing') then 'mef_support_crippled'
      when d.business_function in ('general_office','reception','finance_operations','shared_office_printing',
             'secure_document_printing','physical_security_monitoring','development_test','personal_device',
             'student_device','contractor_device') then 'degraded'
      else 'mef_support_crippled'
    end as mission_impact,
    case
      when d.business_function in ('core_switching','virtualisation_platform') then 'M1-organisation-wide'
      when (t.sector = 'healthcare' and d.business_function in ('clinical_use','core_transaction_processing'))
        or (t.sector = 'financial_services' and d.business_function in ('core_transaction_processing'))
        or (t.sector = 'manufacturing' and d.business_function in ('production_line_control'))
        or (t.sector = 'utilities' and d.business_function in ('production_line_control','environmental_control'))
        or (t.sector = 'education' and d.business_function in ('student_lab'))
        or (t.sector = 'ecommerce_retail' and d.business_function in ('core_transaction_processing','internal_web_application'))
        or (t.sector = 'professional_services' and d.business_function in ('file_and_print','internal_web_application')) then 'M2-sector-mef'
      when d.business_function in ('directory_services','edge_routing','distribution_switching','email_gateway','backup',
             'reporting_and_analytics','perimeter_firewall','vpn_concentrator','web_proxy','wireless_access',
             'building_management','engineering_workstation','internal_web_application','file_and_print',
             'environmental_control','core_transaction_processing') then 'M3-supports-mef'
      when d.business_function in ('general_office','reception','finance_operations','shared_office_printing',
             'secure_document_printing','physical_security_monitoring','development_test','personal_device',
             'student_device','contractor_device') then 'M4-non-essential'
      else 'M5-default'
    end as mission_rule_id,
    case
      when (t.sector = 'healthcare' and d.business_function in ('clinical_use','environmental_control','building_management'))
        or (t.sector = 'manufacturing' and d.business_function in ('production_line_control'))
        or (t.sector = 'utilities' and d.business_function in ('production_line_control','environmental_control'))
        or (t.sector = 'financial_services' and d.business_function in ('core_transaction_processing')) then 'critical'
      when (t.sector = 'manufacturing' and d.business_function in ('environmental_control','building_management'))
        or (t.sector = 'utilities' and d.business_function in ('building_management'))
        or (t.sector = 'healthcare' and d.business_function in ('secure_document_printing'))
        or (t.sector = 'ecommerce_retail' and d.business_function in ('core_transaction_processing'))
        or (t.sector = 'education' and d.business_function in ('student_lab','student_device'))
        or (t.sector in ('manufacturing','utilities') and d.business_function = 'engineering_workstation')
        or (d.business_function = 'building_management') then 'marginal'
      when d.business_function is null then 'marginal'
      else 'negligible'
    end as safety_impact,
    case
      when (t.sector = 'healthcare' and d.business_function in ('clinical_use','environmental_control','building_management'))
        or (t.sector = 'manufacturing' and d.business_function in ('production_line_control'))
        or (t.sector = 'utilities' and d.business_function in ('production_line_control','environmental_control'))
        or (t.sector = 'financial_services' and d.business_function in ('core_transaction_processing')) then 'S1-critical'
      when (t.sector = 'manufacturing' and d.business_function in ('environmental_control','building_management'))
        or (t.sector = 'utilities' and d.business_function in ('building_management'))
        or (t.sector = 'healthcare' and d.business_function in ('secure_document_printing'))
        or (t.sector = 'ecommerce_retail' and d.business_function in ('core_transaction_processing'))
        or (t.sector = 'education' and d.business_function in ('student_lab','student_device'))
        or (t.sector in ('manufacturing','utilities') and d.business_function = 'engineering_workstation')
        or (d.business_function = 'building_management') then 'S2-marginal'
      when d.business_function is null then 'S4-default'
      else 'S3-negligible'
    end as safety_rule_id
  from public.demo_devices d
  join public.demo_tenants t on t.tenant_id = d.tenant_id
)
select m.*, public.ssvc_human_impact(m.mission_impact, m.safety_impact) as human_impact
from m;

-- ---------------------------------------------------------------------------
-- 4. One row per (device, CVE): SSVC action next to CVSS and EPSS
-- ---------------------------------------------------------------------------
create or replace view public.demo_ssvc_decisions as
with vulns as (
  select 'KEV'::text as source, k.cve_id, k.product_group,
         coalesce(k.product_name, concat_ws(' ', k.vendor, k.product)) as product_label,
         lower(concat_ws(' ', k.vendor, k.product, k.product_name)) as product_text,
         k.cvss_score, k.cvss_severity, k.epss_score, k.date_added::timestamptz as seen_at,
         k.ssvc_exploitation, k.ssvc_automatable, k.ssvc_status, k.fixed_versions, k.remediation
  from public.kev_entries k
  union all
  select 'CVE Watch', w.cve_id, w.product_group,
         coalesce(w.product_name, w.matched_vendor),
         lower(concat_ws(' ', w.matched_vendor, w.product_name, array_to_string(w.cpe_products, ' '))),
         w.cvss_score, w.cvss_severity, w.epss_score, w.published_at,
         w.ssvc_exploitation, w.ssvc_automatable, w.ssvc_status, w.fixed_versions, w.remediation
  from public.cve_watch w
  where not exists (select 1 from public.kev_entries k2 where k2.cve_id = w.cve_id)  -- KEV row wins
),
pairs as (
  select c.tenant_id, c.sector, c.device_id, c.asset_class, c.business_function,
         s.display_name as software, s.version as software_version, s.end_of_support,
         (s.end_of_support is not null and s.end_of_support < current_date) as out_of_support,
         v.*,
         c.mission_impact, c.mission_rule_id, c.safety_impact, c.safety_rule_id, c.human_impact,
         case
           when c.seen_in_external_scan is null and c.has_public_ip is null then 'open'
           when c.seen_in_external_scan = true then 'open'
           when c.network_zone in ('dmz','cloud_public','perimeter') then 'open'
           when c.asset_class in ('workstation','byod_endpoint')
                and c.security_posture in ('basic','developing')
                and c.managed_by_mssp = false then 'open'
           when v.ssvc_automatable = 'yes' then 'controlled'
           when c.reachable_from_user_vlan = true or c.reachable_from_guest_vlan = true then 'controlled'
           when c.requires_auth = true or c.behind_vpn_only = true or c.behind_sase = true then 'controlled'
           when c.network_segmentation = 'strict'
                and c.reachable_from_user_vlan = false and c.reachable_from_guest_vlan = false
                and c.has_public_ip = false then 'small'
           else 'controlled'
         end as system_exposure,
         case
           when c.seen_in_external_scan is null and c.has_public_ip is null then 'R1-null-default'
           when c.seen_in_external_scan = true then 'R2-ext-scan'
           when c.network_zone in ('dmz','cloud_public','perimeter') then 'R3-internet-zone'
           when c.asset_class in ('workstation','byod_endpoint')
                and c.security_posture in ('basic','developing')
                and c.managed_by_mssp = false then 'R4-unprotected-endpoint'
           when v.ssvc_automatable = 'yes' then 'R5-automatable'
           when c.reachable_from_user_vlan = true or c.reachable_from_guest_vlan = true then 'R6-user-network'
           when c.requires_auth = true or c.behind_vpn_only = true or c.behind_sase = true then 'R7-access-restricted'
           when c.network_segmentation = 'strict'
                and c.reachable_from_user_vlan = false and c.reachable_from_guest_vlan = false
                and c.has_public_ip = false then 'R8-strict-segment'
           else 'R9-fallback'
         end as exposure_rule_id
  from public.demo_device_context c
  join public.demo_software s on s.device_id = c.device_id
  join vulns v on v.product_text like '%' || s.match_term || '%'
)
select p.*,
       d.outcome as ssvc_action,
       d.exploitation as ssvc_exploitation_used,
       d.automatable  as ssvc_automatable_used,
       d.defaults_used,
       case when p.cvss_score >= 9 then 'critical' when p.cvss_score >= 7 then 'high'
            when p.cvss_score >= 4 then 'medium' when p.cvss_score > 0 then 'low' else 'none' end as cvss_band
from pairs p
cross join lateral public.ssvc_decide(p.ssvc_exploitation, p.system_exposure,
                                      p.ssvc_automatable, p.human_impact) d;

-- Views run with the caller's rights, so the anon key sees only what RLS allows.
alter view public.demo_device_context  set (security_invoker = on);
alter view public.demo_ssvc_decisions  set (security_invoker = on);

-- ---------------------------------------------------------------------------
-- 5. Read-only for the dashboard (anon key). Writes only via the service key / SQL editor.
-- ---------------------------------------------------------------------------
alter table public.demo_tenants  enable row level security;
alter table public.demo_devices  enable row level security;
alter table public.demo_software enable row level security;
drop policy if exists "public read demo_tenants"  on public.demo_tenants;
drop policy if exists "public read demo_devices"  on public.demo_devices;
drop policy if exists "public read demo_software" on public.demo_software;
create policy "public read demo_tenants"  on public.demo_tenants  for select using (true);
create policy "public read demo_devices"  on public.demo_devices  for select using (true);
create policy "public read demo_software" on public.demo_software for select using (true);

-- Supabase normally grants these by default; stated here so the dashboard works either way.
do $$ begin
  if exists (select 1 from pg_roles where rolname = 'anon') then
    grant select on public.demo_tenants, public.demo_devices, public.demo_software,
                    public.demo_device_context, public.demo_ssvc_decisions,
                    public.ssvc_deployer_decision to anon;
  end if;
end $$;
