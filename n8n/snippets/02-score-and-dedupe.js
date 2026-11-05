const cfg = $('Config').first().json;
const allow = cfg.VENDOR_ALLOWLIST.map(s => s.toLowerCase());
const signals = Object.entries(cfg.SIGNAL_TERMS);

// NOTE: the Code node sandbox has no URL class, so parse the host with a regex.
const sourceFromLink = (link) => {
  try {
    const m = String(link).match(/^https?:\/\/([^\/?#]+)/i);
    if (!m) return 'unknown';
    const h = m[1].toLowerCase().replace(/^www\./, '');
    if (h.includes('bleepingcomputer')) return 'BleepingComputer';
    if (h.includes('thehackernews')) return 'The Hacker News';
    if (h.includes('askwoody')) return 'AskWoody';
    if (h.includes('cyber.gov.au')) return 'ASD ACSC';
    if (h.includes('cisa.gov')) return 'CISA';
    if (h.includes('msrc') || h.includes('microsoft.com')) return 'MSRC';
    if (h.includes('fortiguard') || h.includes('fortinet')) return 'Fortinet PSIRT';
    return h;
  } catch { return 'unknown'; }
};

const strip = (s) => (s || '').replace(/<[^>]+>/g, ' ').replace(/\s+/g, ' ').trim();
const seen = new Set();
const rows = [];

for (const item of $input.all()) {
  const j = item.json || {};
  let link = j.link || j.guid || j.id;
  if (!link || seen.has(link)) continue;
  seen.add(link);
  // MSRC items sometimes carry a bare CVE id instead of a URL
  if (!/^https?:\/\//i.test(link) && /^CVE-\d{4}-\d+$/i.test(link)) link = `https://msrc.microsoft.com/update-guide/vulnerability/${link.toUpperCase()}`;
  const source = sourceFromLink(link);

  // Age filter: some feeds (MSRC) return their entire history; keep only recent items
  const publishedRaw = j.isoDate || j.pubDate || null;
  const publishedMs = publishedRaw ? Date.parse(publishedRaw) : NaN;
  if (!isNaN(publishedMs) && publishedMs < Date.now() - (cfg.NEWS_MAX_AGE_DAYS || 7) * 86400000) continue;

  const title = strip(j.title);
  const summary = strip(j.contentSnippet || j.content || j.description || j['content:encoded']).slice(0, 600);
  const hay = `${title} ${summary}`.toLowerCase();

  const matched = [];
  let score = 0;
  for (const a of allow) if (hay.includes(a)) { matched.push(a); score += 2; }
  for (const [term, w] of signals) if (hay.includes(term)) { matched.push(term); score += w; }
  // a vendor hit in the TITLE is a strong signal
  const t = title.toLowerCase();
  if (allow.some(a => t.includes(a))) score += 2;

  // Noise rule: MSRC republishes every Chromium CVE (Edge inherits them). Action is always "update Edge",
  // so keep them stored but out of the digest.
  const noise = source === 'MSRC' && /^Chromium\b/i.test(title);
  if (noise) { score = 0; matched.push('chromium-edge-batch'); }

  rows.push({
    link, title,
    source,
    published_at: !isNaN(publishedMs) ? new Date(publishedMs).toISOString() : new Date().toISOString(),
    summary,
    score,
    matched_terms: [...new Set(matched)],
    relevant: score >= cfg.MIN_SCORE,
  });
}
if (rows.length === 0) return [];
return [{ json: { rows, fetched: $input.all().length, unique: rows.length,
                  relevant: rows.filter(r => r.relevant).length } }];
