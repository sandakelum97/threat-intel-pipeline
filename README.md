# Threat Intel Pipeline (n8n + Supabase + Teams)

Replaces the daily "open eight websites" routine with three n8n workflows that collect, filter and post
only what is relevant to our client environments. Keyword/vendor filtering only in this version; an
AI relevancy step is wired in but disabled.

![architecture](docs/architecture.png)

## What it does

| Workflow | Schedule | What happens |
|---|---|---|
| **TI 01 – KEV Monitor** | daily 06:00 | Pulls the CISA KEV JSON, keeps entries whose vendor/product is in our allowlist, inserts new ones into `kev_entries`, emails the new ones (Teams optional). Supabase returns only rows it inserted, so there's no "seen list" to maintain. |
| **TI 02 – News Collector** | hourly | Reads 8 RSS feeds, dedupes by link, scores each article against the vendor allowlist and high-signal terms (zero-day, actively exploited, ransomware, Australia, MSP…), upserts into `articles` with the score and matched terms. |
| **TI 03 – Daily Digest** | weekdays 06:45 | Reads relevant articles from the last 24 h, groups by source, sends one HTML email (Teams optional). |
| **TI 04 – CVE Watch** | every 6 h | Pulls CVEs published in the last 48 h from NVD, keeps those matching the vendor allowlist with CVSS ≥ 7, adds EPSS, stores in `cve_watch`, emails the new ones. "Patch before it's exploited." |
| **TI 05 – KEV Enrich** | every 2 h | Back-fills CVSS (NVD) and EPSS (FIRST) onto `kev_entries`, 60 rows per run, within NVD rate limits. |

The dashboard (`dashboard/index.html`) reads both tables with the anon key and shows KEV hits,
kept/dropped articles and *why* each was kept.

## Setup (about 20 minutes)

### 1. Supabase
1. Open the SQL editor in your Supabase project and run `supabase/schema.sql`.
2. Note the **Project URL**, the **service_role** key (for n8n) and the **anon** key (for the dashboard).

Also run `supabase/migration-002-cvss-epss.sql` (CVSS/EPSS columns, `cve_watch` table).

### 1b. NVD API key (TI 04 / TI 05)
Request a free key at https://nvd.nist.gov/developers/request-an-api-key and put it in `NVD_API_KEY` in the Config node of TI 04 and TI 05.
Without a key NVD allows 5 requests per 30 s; TI 05 is tuned for the keyed limit (50 per 30 s).

### 2. Email (default output)
The workflows email the KEV alert and the daily digest. In n8n create an **SMTP** credential:
- Gmail: host `smtp.gmail.com`, port `465`, SSL on, user = your Gmail address, password = a
  [Google app password](https://myaccount.google.com/apppasswords) (needs 2-step verification on).
- Microsoft 365: host `smtp.office365.com`, port `587`, STARTTLS, if SMTP AUTH is enabled on the mailbox.

Then set `EMAIL_FROM` and `EMAIL_TO` in each Config node and pick that credential on the **Send email** nodes.

**Teams instead?** Each workflow also has a *Post to Teams (disabled)* node. Create a channel
webhook (**… → Workflows → "Send webhook alerts to a channel"**), put the URL in `TEAMS_WEBHOOK`,
enable that node and disable *Send email*. Needs a work/school tenant; personal Teams can't do it.

### 3. n8n
1. **Workflows → Import from file** for each of `n8n/01-kev-monitor.json`, `02-news-collector.json`, `03-daily-digest.json`.
2. In each workflow open the **Config** node and fill in `SUPABASE_URL`, `SUPABASE_SERVICE_KEY`,
   `EMAIL_FROM`, `EMAIL_TO`, `DASHBOARD_URL`, then select your SMTP credential on the **Send email** node. Adjust `VENDOR_ALLOWLIST` / `SIGNAL_TERMS` / `MIN_SCORE` to taste.
   (For the demo the config lives in a Code node so there's nothing else to click. Before production,
   move the keys into n8n Credentials or Variables.)
3. Run **TI 01** once manually. The first run stores the whole in-scope backlog but only posts entries
   added in the last `KEV_LOOKBACK_DAYS` (14) to Teams.
4. Run **TI 02** once manually, then **TI 03** to see the first digest.
5. Activate all three.

### 4. Dashboard
Open `dashboard/index.html`, set `SUPABASE_URL` and `SUPABASE_ANON_KEY` at the top of the script.
Host it anywhere static (SharePoint site asset, GitHub Pages, S3, an internal web server) or just open it
from a file share. Without keys it shows built-in sample data, which is handy for the demo.

## Demo script (10 minutes)

1. Show the current manual process (the list of sites).
2. Open **TI 01**, click *Execute workflow*, show the Filter node output (`total_in_catalog` vs `in_scope`),
   then the email that arrives.
3. Open **TI 02**, execute, show the Score node output (score, matched terms, relevant flag), point out
   the dropped items.
4. Open the dashboard: tiles → KEV table → articles with "why it was kept".
5. Show the disabled Claude node and explain the optional AI step (Max plan includes US$100/month API credit).
6. Ask for feedback on the allowlist and score threshold.

## Tuning

- **Too noisy?** raise `MIN_SCORE` (default 3) or remove broad allowlist terms like `"Google"`, `"Linux"`.
- **Missing things?** add the product names your clients run to `VENDOR_ALLOWLIST`; add feeds to the
  `Feed list` node in TI 02 (any RSS/Atom URL works; source label comes from the hostname).
- **CVE Watch threshold**: `CVSS_MIN` (7.0) and `CVE_LOOKBACK_HOURS` (48) in the TI 04 Config node.
- **Enable AI**: set `AI_ENABLED: true` in the TI 02 Config node, put the API key in the
  *Claude relevancy check* node, enable the node. Then add a small Code node after it to write
  `ai_verdict` / `ai_reason` back to `articles` (left out so the demo stays keyword-only).

## Next step after the demo

Cross-match new KEV CVEs against NinjaOne vulnerability data per client organisation so the Teams
card says "CVE-2026-xxxx – 14 devices across 3 clients" instead of just listing the CVE.

## Files

```
n8n/01-kev-monitor.json      n8n/02-news-collector.json      n8n/03-daily-digest.json
supabase/schema.sql          dashboard/index.html            docs/architecture.mmd / .png
```

## Feed URLs used

| Source | URL |
|---|---|
| CISA KEV | https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json |
| CISA advisories | https://www.cisa.gov/cybersecurity-advisories/cybersecurity-advisories.xml |
| ASD ACSC alerts | https://www.cyber.gov.au/rss/alerts |
| ASD ACSC advisories | https://www.cyber.gov.au/rss/advisories |
| MSRC Security Update Guide | https://api.msrc.microsoft.com/update-guide/rss |
| Fortinet PSIRT | https://filestore.fortinet.com/fortiguard/rss/ir.xml |
| BleepingComputer | https://www.bleepingcomputer.com/feed/ |
| The Hacker News | https://feeds.feedburner.com/TheHackersNews |
| AskWoody | https://www.askwoody.com/feed/ |
