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
| **TI 05 – KEV Enrich** | every 2 h | Back-fills CVSS (NVD), EPSS (FIRST), product group and a Claude summary onto `kev_entries`, 60 rows per run. |
| **TI 06 – AI Summaries** | hourly | Writes a 2-sentence Claude summary + "why it matters / action" for relevant articles that don't have one yet (25 per run), plus a relevance verdict (`ai_verdict`). Articles Claude judges not relevant are hidden from the digest, ticket note and dashboard "Relevant only" view. |
| **TI 07 – Daily Ticket Note** | weekdays 07:00 | Builds a plain-text note of the last 24 h (new KEV entries, new high-severity CVEs in our stack, relevant news) – ready to paste into a ticket note – emails it and stores it in `ticket_notes` (dashboard → *Ticket note* tab → *Copy note*). |
| **TI 00 – Verify Data** | manual | Cross-checks what we stored against the live sources: KEV rows vs the CISA catalog (missing/mismatched fields), a sample of CVSS scores vs NVD, EPSS vs FIRST, article links (HTTP 200), and whether each AI summary mentions the product. Emails a pass/fail report. Run it before a demo. |

Every KEV entry, CVE Watch item and relevant article is tagged with a **product group** (`PRODUCT_GROUPS` in Config: Microsoft, Fortinet, ConnectWise, …). Emails and the dashboard group by it.

The dashboard (`dashboard/index.html`) reads both tables with the anon key and shows KEV hits,
kept/dropped articles and *why* each was kept.

## Setup (about 20 minutes)

### 1. Supabase
1. Open the SQL editor in your Supabase project and run `supabase/schema.sql`.
2. Note the **Project URL**, the **service_role** key (for n8n) and the **anon** key (for the dashboard).

Also run `supabase/migration-002-cvss-epss.sql` (CVSS/EPSS columns, `cve_watch` table), `supabase/migration-003-batch-key.sql` (browser release batching), `supabase/migration-004-groups-ai.sql` (product groups + AI summary columns) `supabase/migration-005-ticket-notes.sql` (`ticket_notes` table for TI 07) and `supabase/migration-006-remediation.sql` (fix versions, advisory link, software name).

### 1c. Claude API key (summaries)
In n8n: **Credentials → Create → Anthropic** → paste your API key, name it **`Anthropic account`**. The Claude nodes in TI 01/04/05/06 reference it by that name. Cost: Haiku, roughly US$0.001 per item; the Max plan's monthly API credit covers it. Set `AI_ENABLED: false` in Config to switch summaries off (emails still send).

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

Before the meeting: run **TI 00 – Verify Data** (manual) and keep the "all checks passed" email; open
n8n, the dashboard and Gmail in separate tabs; do **not** open any Config node on screen (it holds keys).

1. The problem: the list of sites we check by hand every morning.
2. n8n overview page: seven workflows, their schedules, last-run status (green ticks).
3. **TI 01 – KEV Monitor**: open, *Execute workflow*, click the Filter node → `total_in_catalog` vs
   `in_scope`. "1,700 exploited CVEs in the world; these are the ones for products we run."
4. **TI 04 – CVE Watch**: same idea for CVEs that are *not yet* exploited (NVD, CVSS ≥ 7, EPSS).
   Show one Claude summary in the node output.
5. Gmail: the KEV email, the CVE Watch email, the daily digest – grouped by product, with the
   Claude summary and "what we should do" line.
6. Dashboard: Overview tiles and top stories → KEV tab (filters: severity, product, ransomware) →
   Articles (kept / dropped / AI: skip, and *why*) → **Ticket note** tab → *Copy note*, paste into a
   ticket as normal text.
7. TI 00 verification email: the data is checked against CISA, NVD and FIRST, not just trusted.
8. Ask: which products are missing from the allowlist, which feeds to add, who should receive the emails.

### Presenting from a personal laptop

Everything runs locally (n8n on `localhost:5678`) with a cloud database (Supabase). In Teams, share the
*browser window*, not the whole screen, so nothing else is visible. n8n only needs to be reachable from
your own machine. If you want the team to click around the dashboard themselves after the demo, publish
`dashboard/index.html` (with the anon key only – it is read-only through RLS) to a static host such as
Vercel or Netlify, or keep it local and share the window. Set n8n's timezone to Australia/Adelaide
(Settings → Personal / workflow settings) so "07:00" means Adelaide time.

## Tuning

- **Too noisy?** raise `MIN_SCORE` (default 3) or remove broad allowlist terms like `"Google"`, `"Linux"`.
- **Missing things?** add the product names your clients run to `VENDOR_ALLOWLIST`; add feeds to the
  `Feed list` node in TI 02 (any RSS/Atom URL works; source label comes from the hostname).
- **Product groups**: edit `PRODUCT_GROUPS` in the Config node (same block in every workflow — keep them identical). Terms are matched case-insensitively; the group name is what emails and the dashboard show.
- **AI**: `AI_MODEL`, `AI_MAX_PER_RUN`, `AI_CONTEXT` (the one-paragraph description of our stack that Claude is given) in Config.
- **CVE Watch threshold**: `CVSS_MIN` (7.0) and `CVE_LOOKBACK_HOURS` (48) in the TI 04 Config node.
- **Enable AI**: set `AI_ENABLED: true` in the TI 02 Config node, put the API key in the
  *Claude relevancy check* node, enable the node. Then add a small Code node after it to write
  `ai_verdict` / `ai_reason` back to `articles` (left out so the demo stays keyword-only).

## Run now buttons (dashboard → n8n)

Each pipeline tile on the dashboard has a **Run now** button that calls an n8n Webhook trigger
(`POST /webhook/ti-run/<kind>`, header `x-run-token`). Set `N8N_RUN_BASE` and `RUN_TOKEN` at the top of
`dashboard/index.html`; the token is the value of the n8n Header Auth credential **TI run token**. Leave both
empty to hide the buttons. A 10-minute cooldown per workflow stops accidental double runs. With
`N8N_RUN_BASE = http://localhost:5678` the buttons work when the dashboard is viewed on the laptop that runs n8n;
to let the team use them, expose n8n through a Cloudflare Tunnel and put Cloudflare Access (login) in front of it,
then set `N8N_RUN_BASE` to the tunnel URL. Wrong or missing token → n8n answers 403 and nothing runs.

## Security notes

- Emails, the ticket note and the dashboard treat every value from feeds, NVD and CISA as untrusted:
  HTML is escaped (including quotes), CVE ids must match `CVE-\d{4}-\d{4,}` and links must be
  `http(s)` before they become anchors; anything else renders as `#`.
- Claude prompts wrap feed text in a `<data>…</data>` block and instruct the model to summarise only,
  never follow instructions inside the text, and never emit URLs or credentials from it
  (prompt-injection guard). Model output is parsed as JSON and truncated before storage.
- The dashboard uses the **anon** key only; every table has row-level security with read-only
  policies. The **service_role** key lives only in the n8n Config nodes on the laptop.
- Chart.js is loaded from cdnjs with Subresource Integrity (SRI) so a tampered CDN copy will not run.
- Workflow JSON exports contain the Config node. The repo copies hold placeholders; **never commit a
  filled-in Config**, and move the keys to n8n *Credentials* before this leaves the laptop.
- n8n listens on all interfaces by default. On a laptop that is fine behind the Windows firewall; to
  be strict, start it with `N8N_LISTEN_ADDRESS=127.0.0.1`.
- Deleting is never automated: workflows only insert/update rows.

## Next step after the demo

Cross-match new KEV CVEs against NinjaOne vulnerability data per client organisation so the Teams
card says "CVE-2026-xxxx – 14 devices across 3 clients" instead of just listing the CVE.

## Files

```
n8n/00-verify-data.json      n8n/01-kev-monitor.json      n8n/02-news-collector.json   n8n/03-daily-digest.json
n8n/04-cve-watch.json        n8n/05-kev-enrich.json       n8n/06-ai-summaries.json     n8n/07-ticket-note.json
supabase/schema.sql + migration-002..006.sql              dashboard/index.html         docs/architecture.mmd / .png
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
