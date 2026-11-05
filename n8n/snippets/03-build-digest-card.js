const cfg = $('Config').first().json;
const arts = $input.all().map(i => i.json).filter(a => a && a.link);
if (arts.length === 0) return [];

const bySource = {};
for (const a of arts) (bySource[a.source] ||= []).push(a);

const body = [
  { type: 'TextBlock', size: 'Large', weight: 'Bolder', text: `Threat intel digest – ${arts.length} relevant items (last 24h)` },
  { type: 'TextBlock', isSubtle: true, spacing: 'None', wrap: true,
    text: 'Keyword-scored against our client stack. Score and matched terms shown; full list on the dashboard.' },
];
for (const [src, list] of Object.entries(bySource)) {
  body.push({ type: 'TextBlock', weight: 'Bolder', spacing: 'Medium', text: `${src} (${list.length})` });
  for (const a of list.slice(0, 6)) {
    body.push({ type: 'TextBlock', wrap: true, spacing: 'Small',
      text: `• [${a.title}](${a.link})  _score ${a.score}: ${(a.matched_terms || []).slice(0, 5).join(', ')}_` });
  }
  if (list.length > 6) body.push({ type: 'TextBlock', isSubtle: true, spacing: 'None', text: `…${list.length - 6} more` });
}
body.push({ type: 'TextBlock', spacing: 'Medium', text: `[Open dashboard](${cfg.DASHBOARD_URL})` });
const esc = (t) => String(t ?? '').replace(/[&<>]/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;'}[c]));
let html = `<div style="font-family:Segoe UI,Arial,sans-serif;font-size:14px;color:#1b1f1c;max-width:720px">
<h2 style="margin:0 0 4px">Threat intel digest – ${arts.length} relevant items (last 24h)</h2>
<p style="color:#666;margin:0 0 16px">Keyword-scored against our client stack. Score and matched terms shown; full list on the dashboard.</p>`;
const PER_SOURCE = 8;
for (const [src, list] of Object.entries(bySource)) {
  html += `<h3 style="margin:16px 0 6px;font-size:14px">${esc(src)} (${list.length})</h3><ul style="margin:0;padding-left:18px">`;
  for (const a of list.slice(0, PER_SOURCE)) {
    html += `<li style="margin:4px 0"><a href="${a.link}">${esc(a.title)}</a> <span style="color:#666;font-size:12px">score ${a.score}: ${esc((a.matched_terms || []).slice(0, 5).join(', '))}</span></li>`;
  }
  if (list.length > PER_SOURCE) html += `<li style="color:#666">…${list.length - PER_SOURCE} more on the dashboard</li>`;
  html += `</ul>`;
}
html += `<p style="margin-top:16px"><a href="${cfg.DASHBOARD_URL}">Open dashboard</a></p></div>`;
const subject = `[Threat Intel] Daily digest – ${arts.length} relevant items`;
return [{ json: { card: body, html, subject, count: arts.length, links: arts.map(a => a.link) } }];
