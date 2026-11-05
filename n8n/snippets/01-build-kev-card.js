// Supabase returned ONLY the rows it inserted (Prefer: resolution=ignore-duplicates,return=representation)
const cfg = $('Config').first().json;
const inserted = $input.all().map(i => i.json).filter(r => r && r.cve_id);
const cutoff = new Date(Date.now() - cfg.KEV_LOOKBACK_DAYS * 86400000);
const fresh = inserted.filter(r => new Date(r.date_added) >= cutoff)
                      .sort((a, b) => (a.date_added < b.date_added ? 1 : -1));
if (fresh.length === 0) return [];

const body = [
  { type: 'TextBlock', size: 'Large', weight: 'Bolder',
    text: `CISA KEV – ${fresh.length} new in-scope ${fresh.length === 1 ? 'entry' : 'entries'}` },
  { type: 'TextBlock', isSubtle: true, spacing: 'None',
    text: `Filtered to vendors in our client environments · ${inserted.length} stored this run` },
];
for (const r of fresh.slice(0, 15)) {
  const flag = r.ransomware === 'Known' ? ' ⚠ **Ransomware use known**' : '';
  body.push({ type: 'TextBlock', weight: 'Bolder', spacing: 'Medium', wrap: true,
    text: `[${r.cve_id}](https://nvd.nist.gov/vuln/detail/${r.cve_id}) – ${r.vendor} ${r.product}${flag}` });
  body.push({ type: 'TextBlock', wrap: true, spacing: 'None', text: r.vuln_name });
  body.push({ type: 'TextBlock', wrap: true, spacing: 'None', isSubtle: true,
    text: `Added ${r.date_added} · Federal due ${r.due_date} · ${r.required_action}` });
}
if (fresh.length > 15) body.push({ type: 'TextBlock', isSubtle: true, text: `…and ${fresh.length - 15} more on the dashboard` });
body.push({ type: 'TextBlock', spacing: 'Medium', text: `[Open dashboard](${cfg.DASHBOARD_URL})` });

const esc = (t) => String(t ?? '').replace(/[&<>]/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;'}[c]));
let html = `<div style="font-family:Segoe UI,Arial,sans-serif;font-size:14px;color:#1b1f1c;max-width:720px">
<h2 style="margin:0 0 4px">CISA KEV – ${fresh.length} new in-scope ${fresh.length === 1 ? 'entry' : 'entries'}</h2>
<p style="color:#666;margin:0 0 16px">Filtered to vendors in our client environments · ${inserted.length} stored this run</p>`;
for (const r of fresh) {
  const flag = r.ransomware === 'Known' ? ' <span style="color:#b3261e;font-weight:600">⚠ Ransomware use known</span>' : '';
  html += `<div style="border-top:1px solid #ddd;padding:10px 0">
  <div><a href="https://nvd.nist.gov/vuln/detail/${r.cve_id}" style="font-weight:600">${r.cve_id}</a> – ${esc(r.vendor)} ${esc(r.product)}${flag}</div>
  <div>${esc(r.vuln_name)}</div>
  <div style="color:#666;font-size:12px">Added ${r.date_added} · Federal due ${r.due_date} · ${esc((r.required_action || '').slice(0, 140))}${(r.required_action || '').length > 140 ? '…' : ''}</div></div>`;
}
html += `<p style="margin-top:16px"><a href="${cfg.DASHBOARD_URL}">Open dashboard</a></p></div>`;
const subject = `[Threat Intel] KEV: ${fresh.length} new in-scope ${fresh.length === 1 ? 'CVE' : 'CVEs'} – ${fresh.slice(0,3).map(r => r.vendor).filter((v,i,a)=>a.indexOf(v)===i).join(', ')}`;

return [{ json: { card: body, html, subject, count: fresh.length, cves: fresh.map(r => r.cve_id) } }];
