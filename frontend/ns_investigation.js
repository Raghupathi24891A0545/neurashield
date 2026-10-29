/* NeuraShield investigation UI helpers. Every value that comes from an investigation
   (which can contain attacker-controlled e-mail text) is passed through NS.esc(). */
(function () {
  const NS = (window.NS = window.NS || {});
  const esc = (NS.esc = function (v) {
    if (v === null || v === undefined) return '';
    return String(v).replace(/[&<>"'`]/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;', '`': '&#96;' }[c]));
  });
  const NA = (NS.na = (v, why) => (v === null || v === undefined || v === '' ? `<span class="muted">Not available${why ? ' — ' + esc(why) : ''}</span>` : esc(v)));
  NS.state = (s) => `<span class="state state-${esc(s)}">${esc(String(s || '').replace(/_/g, ' '))}</span>`;
  NS.sev = (s) => `<span class="sev sev-${esc(s)}">${esc(s === 'INFORMATIONAL' ? 'INFO' : s)}</span>`;
  NS.pct = (v) => (v === null || v === undefined ? '—' : `${Math.round(v)}%`);
  const LAYER_LABEL = { identity: 'Sender identity', authentication: 'Authentication', content: 'Content', links: 'Links', attachments: 'Attachments', html: 'HTML structure' };

  /* ── elevated buttons: micro ripple ── */
  document.addEventListener('click', (e) => {
    const b = e.target.closest('.btn-elev');
    if (!b || window.matchMedia('(prefers-reduced-motion: reduce)').matches) return;
    const r = b.getBoundingClientRect(), s = document.createElement('span'), d = Math.max(r.width, r.height);
    s.className = 'ripple'; s.style.width = s.style.height = d + 'px';
    s.style.left = e.clientX - r.left - d / 2 + 'px'; s.style.top = e.clientY - r.top - d / 2 + 'px';
    b.appendChild(s); setTimeout(() => s.remove(), 550);
  });

  /* ── sidebar navigation from the capability registry (no broken links) ── */
  NS.renderNav = async function (el, activeKey) {
    let caps = { modules: [] };
    try { caps = await (await fetch('/api/capabilities')).json(); } catch (e) { /* nav fallback */ }
    const byKey = Object.fromEntries((caps.modules || []).map((m) => [m.key, m]));

    const item = (m) => {
      if (!m) return '';
      const tag = m.status === 'IN_DEVELOPMENT' ? '<span class="tag dev">IN DEV</span>' : m.status === 'COMING_SOON' ? '<span class="tag">SOON</span>' : '';
      if (!m.route || m.status === 'COMING_SOON') return `<li><span class="off">${esc(m.name)} ${tag}</span></li>`;
      return `<li><a href="${esc(m.route)}" class="${m.key === activeKey ? 'active' : ''}">${esc(m.name)} ${tag}</a></li>`;
    };

    let html = '';
    // URL Intelligence is the signed-in home page; avoid a second Dashboard link.

    // INVESTIGATION
    html += '<li class="grp">Investigation</li>';
    html += item(byKey['investigation_center'] || { key: 'investigation_center', name: 'Investigation Center', route: '/investigation-center', status: 'ACTIVE' });
    html += item(byKey['investigation_history'] || { key: 'investigation_history', name: 'Investigation History', route: '/investigations', status: 'ACTIVE' });

    // INTELLIGENCE
    html += '<li class="grp">Intelligence</li>';
    const intelKeys = ['url', 'domain', 'webpage', 'email', 'qr'];
    intelKeys.forEach(k => { if (byKey[k]) html += item(byKey[k]); });
    html += item({ key: 'bulk_analysis', name: 'Bulk Analysis', route: '/upload', status: 'ACTIVE' });

    // ANALYSIS
    html += '<li class="grp">Analysis</li>';
    const analysisKeys = ['dna', 'graph', 'brand'];
    analysisKeys.forEach(k => { if (byKey[k]) html += item(byKey[k]); });

    // SECURITY OPERATIONS
    html += '<li class="grp">Security Operations</li>';
    const secOpsKeys = ['monitoring', 'threat_intel', 'incident_response', 'evidence_packages'];
    secOpsKeys.forEach(k => { if (byKey[k]) html += item(byKey[k]); });

    // MODEL & SECURITY
    html += '<li class="grp">Model & Security</li>';
    const modelKeys = ['resilience', 'self_audit', 'analytics'];
    modelKeys.forEach(k => { if (byKey[k]) html += item(byKey[k]); });

    // RESOURCES
    html += '<li class="grp">Resources</li>';
    if (byKey['news']) html += item(byKey['news']);

    el.innerHTML = html;

    // Multiple capabilities may lead to one page; show each destination once.
    const seen = new Set();
    el.querySelectorAll('a[href]').forEach((link) => {
      const url = new URL(link.href, window.location.origin);
      const destination = `${url.pathname}${url.search}${url.hash}`;
      if (seen.has(destination)) link.closest('li')?.remove();
      else seen.add(destination);
    });
    el.querySelectorAll('li.grp').forEach((group) => {
      let next = group.nextElementSibling;
      while (next && !next.classList.contains('grp')) {
        if (next.querySelector('a, .off')) return;
        next = next.nextElementSibling;
      }
      group.remove();
    });
  };

  /* Subtle pointer-driven depth on designated cards. */
  document.addEventListener('pointermove', (e) => {
    const card = e.target.closest('.interactive-tilt');
    if (!card || window.matchMedia('(prefers-reduced-motion: reduce)').matches) return;
    const r = card.getBoundingClientRect();
    const x = (e.clientX - r.left) / r.width - 0.5;
    const y = (e.clientY - r.top) / r.height - 0.5;
    card.style.setProperty('--tilt-x', `${x * 3}deg`);
    card.style.setProperty('--tilt-y', `${y * -3}deg`);
  });
  document.addEventListener('pointerout', (e) => {
    const card = e.target.closest('.interactive-tilt');
    if (card && !card.contains(e.relatedTarget)) {
      card.style.setProperty('--tilt-x', '0deg');
      card.style.setProperty('--tilt-y', '0deg');
    }
  });

  /* ── Cyber Analysis Core (canvas). Visual only; stage text comes from the backend. ── */
  NS.core = function (canvas) {
    const reduce = window.matchMedia('(prefers-reduced-motion: reduce)').matches;
    const dpr = Math.min(window.devicePixelRatio || 1, 2);
    const ctx = canvas.getContext('2d');
    let raf = null, t0 = performance.now();
    function size() { const w = canvas.clientWidth || 260; canvas.width = w * dpr; canvas.height = w * dpr; }
    size();
    const nodes = Array.from({ length: 7 }, (_, i) => ({ a: (i / 7) * Math.PI * 2, r: 0.36 + (i % 3) * 0.05, s: 0.25 + (i % 4) * 0.08 }));
    function frame(now) {
      const t = (now - t0) / 1000, W = canvas.width, c = W / 2;
      ctx.clearRect(0, 0, W, W);
      ctx.lineWidth = 1.2 * dpr;
      [0.44, 0.34, 0.24].forEach((r, i) => {
        ctx.strokeStyle = `rgba(0,200,255,${0.18 + i * 0.08})`;
        ctx.setLineDash(i === 1 ? [6 * dpr, 8 * dpr] : []);
        ctx.beginPath(); ctx.arc(c, c, W * r, t * (i % 2 ? -0.4 : 0.3), t * (i % 2 ? -0.4 : 0.3) + Math.PI * 1.6); ctx.stroke();
      });
      ctx.setLineDash([]);
      ctx.strokeStyle = 'rgba(0,200,255,0.9)'; ctx.lineWidth = 2.5 * dpr;
      ctx.beginPath(); ctx.arc(c, c, W * 0.44, t * 1.6, t * 1.6 + 0.6); ctx.stroke();
      nodes.forEach((n) => {
        const a = n.a + t * n.s, x = c + Math.cos(a) * W * n.r, y = c + Math.sin(a) * W * n.r;
        ctx.fillStyle = 'rgba(26,111,255,0.9)'; ctx.beginPath(); ctx.arc(x, y, 3 * dpr, 0, Math.PI * 2); ctx.fill();
        ctx.strokeStyle = 'rgba(0,200,255,0.12)'; ctx.lineWidth = 1 * dpr; ctx.beginPath(); ctx.moveTo(c, c); ctx.lineTo(x, y); ctx.stroke();
      });
      const pulse = 0.5 + 0.5 * Math.sin(t * 2.2);
      ctx.fillStyle = `rgba(0,200,255,${0.1 + pulse * 0.12})`; ctx.beginPath(); ctx.arc(c, c, W * 0.13, 0, Math.PI * 2); ctx.fill();
      ctx.strokeStyle = 'rgba(0,200,255,0.8)'; ctx.lineWidth = 1.5 * dpr; ctx.beginPath();
      for (let i = 0; i < 6; i++) { const a = Math.PI / 6 + (i * Math.PI) / 3; const x = c + Math.cos(a) * W * 0.09, y = c + Math.sin(a) * W * 0.09; i ? ctx.lineTo(x, y) : ctx.moveTo(x, y); }
      ctx.closePath(); ctx.stroke();
      if (!reduce) raf = requestAnimationFrame(frame);
    }
    return { start() { t0 = performance.now(); if (raf) cancelAnimationFrame(raf); raf = requestAnimationFrame(frame); }, stop() { if (raf) cancelAnimationFrame(raf); raf = null; } };
  };

  /* ── Universal quick-result pattern (§51) ── */
  NS.quickResult = function (inv) {
    const s = inv.summary || {};
    const mlCell = s.ml_probability === null || s.ml_probability === undefined
      ? `<div class="v"><small>Not available</small></div><div class="h" title="${esc(s.ml_reason || '')}">No validated e-mail model yet — rules-only score</div>`
      : `<div class="v">${Math.round(s.ml_probability * 100)}<small>%</small></div><div class="h">Text model estimate — not certainty</div>`;
    const kf = (inv.key_findings || []);
    return `
    <div class="qr-top">
      <div class="verdict v-${esc(s.verdict)}"><div style="font:10px var(--ns-mono);letter-spacing:.12em;text-transform:uppercase;color:var(--ns-text-muted);margin-bottom:8px">Verdict</div>
        <div class="lbl">${esc(s.verdict_label)}</div><p>${esc(s.explanation)}</p></div>
      <div class="metric"><div class="k">Risk score</div><div class="v">${esc(s.risk_score)}<small>/100</small></div><div class="bar"><i style="width:${Number(s.risk_score) || 0}%"></i></div><div class="h">${esc(s.risk_level)}</div></div>
      <div class="metric"><div class="k">ML probability</div>${mlCell}</div>
      <div class="metric"><div class="k">Confidence</div><div class="v">${esc(s.confidence)}<small>%</small></div><div class="h">Support for the score, not P(phishing)</div></div>
      <div class="metric"><div class="k">Evidence coverage</div><div class="v">${esc(s.evidence_coverage)}<small>%</small></div><div class="h">${esc((inv.coverage || {}).obtained)}/${esc((inv.coverage || {}).applicable)} applicable sources</div></div>
    </div>
    <div class="sec panel"><div class="sec-h"><h2>Key findings</h2><span class="n">${kf.length} with risk contribution</span></div>
      ${kf.length ? kf.map((r) => `<div class="find">${NS.sev(r.severity)}<div><div class="t">${esc(r.name)}</div><div class="w">${esc(r.evidence)}</div></div></div>`).join('')
        : '<p class="dim" style="margin:0">No rule with a risk contribution was triggered.</p>'}
    </div>
    <div class="grid-2 sec">
      <div class="panel"><div class="sec-h"><h2>What we found</h2></div><ul class="plain">${(inv.findings || []).slice(0, 8).map((f) => `<li>${esc(f.text)}</li>`).join('')}</ul></div>
      <div class="panel"><div class="sec-h"><h2>What we could not verify</h2></div><ul class="plain">${(inv.could_not_verify || []).map((f) => `<li>${esc(f.text)}</li>`).join('')}</ul></div>
    </div>
    <div class="sec panel"><div class="sec-h"><h2>What should you do?</h2></div><ul class="plain">${(inv.recommendations || []).map((r) => `<li>${esc(r)}</li>`).join('')}</ul>
      <div style="margin-top:16px;display:flex;gap:12px;flex-wrap:wrap">
        <a class="btn-elev" href="/report?id=${encodeURIComponent(inv.investigation_id)}">View full threat investigation report →</a>
      </div></div>`;
  };

  /* ── E-mail evidence blocks (shared by the e-mail page and the report) ── */
  NS.email = {};
  NS.email.identity = function (em) {
    const id = em.identity || {}, cs = id.claimed_sender || {};
    const rows = (id.comparisons || []).map((c) => `<tr><td class="k">${esc(c.field)}</td><td><span class="brk">${NA(c.value, 'header not present')}</span></td>
      <td>${c.relation === 'DIFFERENT_DOMAIN' ? '<span class="sev sev-MEDIUM">DIFFERENT DOMAIN</span>' : c.relation === 'SAME_ORGANISATIONAL_DOMAIN' ? '<span class="state state-VERIFIED">SAME ORG DOMAIN</span>' : `<span class="state">${esc((c.relation || '').replace(/_/g, ' '))}</span>`}</td></tr>`).join('');
    const brands = (id.brand_claims || []).map((b) => `<tr><td class="k">${esc(b.brand)}</td><td>${esc((b.official_domains || []).slice(0, 4).join(', '))}</td><td>${esc(b.from_domain)}</td><td><span class="state state-${b.state === 'CONSISTENT' ? 'VERIFIED' : 'UNAVAILABLE'}">${esc(b.state)}</span></td></tr>`).join('');
    return `<div class="kv" style="margin-bottom:12px">
        <div class="k">Display name</div><div class="v">${NA(cs.display_name, 'none')}</div>
        <div class="k">From address (claimed)</div><div class="v mono">${NA(cs.address, 'From header absent')} ${NS.state('OBSERVED')}</div>
        <div class="k">Organisational domain</div><div class="v mono">${NA(cs.registered_domain)}</div>
        <div class="k">Received hops</div><div class="v">${esc(id.received_hop_count)} ${id.earliest_observed_hop ? `· earliest observed: <span class="mono">${esc(id.earliest_observed_hop.from_host || '')} ${esc(id.earliest_observed_hop.from_ip || '')}</span>` : ''}</div>
      </div>
      <p class="muted small" style="margin:0 0 10px">${esc(cs.note)}</p>
      <div class="tbl-wrap"><table class="tbl"><thead><tr><th>Field</th><th>Value</th><th>Relation to From domain</th></tr></thead><tbody>${rows}</tbody></table></div>
      ${brands ? `<h4 class="small muted" style="margin:16px 0 8px;letter-spacing:.1em;text-transform:uppercase">Brand claimed in display name</h4><div class="tbl-wrap"><table class="tbl"><thead><tr><th>Brand</th><th>Official domains</th><th>From domain</th><th>State</th></tr></thead><tbody>${brands}</tbody></table></div>` : ''}`;
  };
  NS.email.auth = function (em) {
    const a = em.authentication || {}, dns = em.sender_dns || {};
    const row = (m) => { const e = a[m] || {}; return `<tr><td class="k">${m.toUpperCase()}</td><td>${e.result ? `<b style="color:${e.result === 'pass' ? 'var(--ns-green)' : ['fail', 'softfail', 'permerror'].includes(e.result) ? 'var(--ns-red)' : 'var(--ns-text)'}">${esc(e.result)}</b>` : '<span class="muted">Not available</span>'}</td>
      <td class="mono">${NA(e.domain, '')}</td><td>${NS.state(e.state)} <span class="muted small">${esc(e.source || e.reason || '')}</span></td></tr>`; };
    const av = (label, x) => x ? `<tr><td class="k">${esc(label)}</td><td>${NS.state(x.state)}</td><td class="brk">${esc(typeof x.value === 'object' && x.value !== null ? (x.value.record || JSON.stringify(x.value)) : (x.value === true ? 'Yes' : x.value === false ? 'No' : (x.value || '')))}</td><td class="muted small">${esc(x.reason || '')}</td></tr>` : '';
    return `<div class="tbl-wrap"><table class="tbl"><thead><tr><th>Mechanism</th><th>Result</th><th>Evaluated domain</th><th>Evidence state</th></tr></thead><tbody>${['spf', 'dkim', 'dmarc'].map(row).join('')}</tbody></table></div>
      <p class="muted small" style="margin:10px 0 16px">${esc(a.note)} ${a.authserv_id ? `Authserv-id: <span class="mono">${esc(a.authserv_id)}</span>.` : ''}</p>
      <h4 class="small muted" style="margin:0 0 8px;letter-spacing:.1em;text-transform:uppercase">Sender domain — live DNS (${esc(dns.domain || 'no domain')})</h4>
      <div class="tbl-wrap"><table class="tbl"><thead><tr><th>Check</th><th>State</th><th>Value</th><th>Reason</th></tr></thead><tbody>
        ${av('Domain exists', dns.domain_exists)}${av('MX records', dns.mx)}${av('SPF record', dns.spf_record)}${av('DMARC record', dns.dmarc_record)}${av('Specific mailbox', dns.mailbox)}
      </tbody></table></div>`;
  };
  NS.email.received = function (em) {
    const hops = em.received_chain || [];
    if (!hops.length) return '<p class="muted">No Received headers present.</p>';
    return `<div class="tbl-wrap"><table class="tbl"><thead><tr><th>#</th><th>From host</th><th>From IP</th><th>By</th><th>With</th><th>Timestamp</th></tr></thead><tbody>
      ${hops.map((h) => `<tr><td class="k">${esc(h.index)}</td><td class="mono brk">${NA(h.from_host, '')}</td><td class="mono">${NA(h.from_ip, '')}</td><td class="mono brk">${NA(h.by_host, '')}</td><td>${NA(h.protocol, '')}</td><td class="mono">${NA(h.timestamp, 'unparsed')}</td></tr>`).join('')}
      </tbody></table></div><p class="muted small" style="margin-top:8px">#0 is the newest hop. Hops below your own provider's servers can be written by the sender.</p>`;
  };
  NS.email.links = function (em, urlLayer) {
    const u = em.urls || {}, res = Object.fromEntries((urlLayer || []).map((r) => [r.url, r]));
    if (!u.url_count) return '<p class="muted">No links found in the message.</p>';
    const mm = (u.anchor_mismatches || []).map((m) => `<li>Shows <span class="mono">${esc(m.displayed)}</span> but opens <span class="mono brk">${esc(m.actual_url)}</span></li>`).join('');
    return `${mm ? `<div class="panel" style="border-color:rgba(255,124,0,.45);margin-bottom:12px"><b class="small">Deceptive links</b><ul class="plain">${mm}</ul></div>` : ''}
      <div class="tbl-wrap"><table class="tbl"><thead><tr><th>URL</th><th>Found in</th><th>Flags</th><th>URL Intelligence</th></tr></thead><tbody>
      ${(u.urls || []).map((x) => { const r = res[x.url]; const flags = [x.ip_host && 'IP host', x.shortener && 'shortener', x.punycode && 'punycode', !x.uses_https && 'no HTTPS', x.same_domain_as_sender && 'sender domain', x.resource_only && 'resource only'].filter(Boolean);
        return `<tr><td class="mono brk" style="min-width:220px">${esc(x.url)}</td><td>${esc((x.locations || []).join(', '))}</td><td>${flags.map((f) => `<span class="chip">${esc(f)}</span>`).join(' ') || '<span class="muted">—</span>'}</td>
        <td>${r ? (r.status === 'ANALYSIS_UNAVAILABLE' ? `<span class="muted">Unavailable (${esc(r.reason)})</span>` : `<b>${esc(r.risk_score)}</b>/100 · ${esc(r.risk_level)}<div class="muted small">${esc(r.prediction)}</div>`) : '<span class="muted">Not analysed</span>'}</td></tr>`; }).join('')}
      </tbody></table></div>`;
  };
  NS.email.attachments = function (em) {
    const a = em.attachments || {};
    if (!a.count) return '<p class="muted">No attachments.</p>';
    return `<p class="muted small" style="margin:0 0 10px">${esc(a.note)}</p>${(a.items || []).map((x) => `
      <div class="panel" style="margin-bottom:10px"><div class="kv">
        <div class="k">Filename</div><div class="v mono">${NA(x.filename, 'no filename')}</div>
        <div class="k">Declared MIME / detected</div><div class="v">${esc(x.declared_mime_type)} · ${esc(x.detected_type)}</div>
        <div class="k">Size</div><div class="v">${esc(x.size_bytes)} bytes</div>
        <div class="k">SHA-256</div><div class="v mono brk">${NA(x.sha256)}</div>
        ${x.archive ? `<div class="k">Archive listing</div><div class="v">${x.archive.readable ? `${esc(x.archive.entry_count)} entr${x.archive.entry_count === 1 ? 'y' : 'ies'}${x.archive.encrypted_entries ? ' · encrypted' : ''}: <span class="mono">${esc((x.archive.entries || []).slice(0, 8).join(', '))}</span>` : esc(x.archive.reason)}</div>` : ''}
        ${x.pdf_markers ? `<div class="k">PDF markers</div><div class="v mono">${esc(x.pdf_markers.join(' ') || 'none')}</div>` : ''}
      </div>${(x.flags || []).length ? `<ul class="plain" style="margin-top:10px">${x.flags.map((f) => `<li><b>${esc(f.flag.replace(/_/g, ' '))}</b> — ${esc(f.detail)}</li>`).join('')}</ul>` : '<p class="muted small" style="margin:10px 0 0">No static risk flags.</p>'}</div>`).join('')}`;
  };
  NS.email.content = function (em) {
    const c = em.content || {}, l = c.language || {}, h = c.html || {};
    const cats = (l.categories || []).map((k) => `<tr><td class="k">${esc(k.label)}</td><td>${esc(k.match_count)}</td><td>${(k.matches || []).slice(0, 2).map((m) => `“…${esc(m.context)}…”`).join('<br>')}</td></tr>`).join('');
    return `<div class="kv" style="margin-bottom:12px"><div class="k">Parts</div><div class="v">${c.has_text_part ? 'text/plain ' : ''}${c.has_html_part ? 'text/html' : ''}${!c.has_text_part && !c.has_html_part ? 'No readable body' : ''}</div>
      <div class="k">Words analysed</div><div class="v">${esc(l.word_count)}</div></div>
      ${cats ? `<div class="tbl-wrap"><table class="tbl"><thead><tr><th>Signal category</th><th>Matches</th><th>Context</th></tr></thead><tbody>${cats}</tbody></table></div>` : '<p class="muted">No social-engineering language categories matched.</p>'}
      <p class="muted small" style="margin:8px 0 0">${esc(l.note)}</p>
      ${h.analysed ? `<h4 class="small muted" style="margin:16px 0 8px;letter-spacing:.1em;text-transform:uppercase">HTML structure (static)</h4><div class="kv">
        <div class="k">Forms / password inputs</div><div class="v">${esc(h.form_count)} / ${esc(h.password_inputs)}</div>
        <div class="k">Scripts / on* handlers</div><div class="v">${esc(h.script_count)} / ${esc(h.event_handler_attributes)}</div>
        <div class="k">Iframes / embeds</div><div class="v">${esc(h.iframe_like_count)}</div>
        <div class="k">Remote images / tracking pixels</div><div class="v">${esc(h.remote_image_count)} / ${esc(h.tracking_pixel_count)}</div>
        <div class="k">Hidden text blocks</div><div class="v">${esc((h.hidden_text_blocks || []).length)}</div></div><p class="muted small">${esc(h.note)}</p>` : ''}
      ${c.text_excerpt ? `<h4 class="small muted" style="margin:16px 0 8px;letter-spacing:.1em;text-transform:uppercase">Text excerpt (as plain text, never rendered)</h4><pre class="raw">${esc(c.text_excerpt)}</pre>` : ''}`;
  };
  NS.email.headers = function (em) {
    const hs = em.headers || [];
    if (!hs.length) return '<p class="muted">No headers were supplied.</p>';
    return `<div class="tbl-wrap"><table class="tbl"><thead><tr><th>Header</th><th>Value</th></tr></thead><tbody>${hs.map((h) => `<tr><td class="k">${esc(h.name)}</td><td class="mono brk">${esc(h.value)}</td></tr>`).join('')}</tbody></table></div>`;
  };
  NS.coverageTable = function (cov) {
    return `<div class="tbl-wrap"><table class="tbl"><thead><tr><th>Evidence source</th><th>State</th><th>Detail</th></tr></thead><tbody>
      ${(cov.items || []).map((i) => `<tr><td class="k">${esc(i.check)}</td><td>${NS.state(i.state)}</td><td>${esc(i.reason || '')}</td></tr>`).join('')}</tbody></table></div>
      <p class="muted small" style="margin-top:8px">${esc(cov.definition)}</p>`;
  };
  NS.fusion = function (f) {
    return `${(f.layers || []).map((l) => `<div class="fbar"><span class="lbl">${esc(LAYER_LABEL[l.layer] || l.layer)}</span><span class="track"><span class="fill" style="display:block;width:${Number(l.score) || 0}%"></span></span><span class="num">${esc(l.score)}</span></div>`).join('')}
      <div class="kv" style="margin-top:14px"><div class="k">Rule risk</div><div class="v">${esc(f.rule_risk)}/100</div>
      <div class="k">ML contribution</div><div class="v">${f.ml_probability === null || f.ml_probability === undefined ? 'None — model unavailable' : `${Math.round(f.ml_probability * 100)}% × weight ${esc(f.ml_weight)}`}</div>
      <div class="k">Final formula</div><div class="v mono small">${esc(f.formula)}</div><div class="k">Method</div><div class="v small dim">${esc(f.method)}</div></div>`;
  };

  /* ── Relationship graph (SVG, evidence on every edge) ── */
  NS.graph = function (g) {
    const nodes = (g.nodes || []).slice(0, 40), ids = new Set(nodes.map((n) => n.id));
    const edges = (g.edges || []).filter((e) => ids.has(e.source) && ids.has(e.target));
    const W = 760, H = 460, cx = W / 2, cy = H / 2;
    const center = nodes.find((n) => n.id === 'email:message') || nodes[0];
    const ring1 = new Set(edges.filter((e) => e.source === (center && center.id)).map((e) => e.target));
    const pos = {}; if (center) pos[center.id] = [cx, cy];
    const r1 = nodes.filter((n) => ring1.has(n.id)), r2 = nodes.filter((n) => n !== center && !ring1.has(n.id));
    r1.forEach((n, i) => { const a = (i / Math.max(1, r1.length)) * Math.PI * 2 - Math.PI / 2; pos[n.id] = [cx + Math.cos(a) * 150, cy + Math.sin(a) * 125]; });
    r2.forEach((n, i) => { const a = (i / Math.max(1, r2.length)) * Math.PI * 2 - Math.PI / 2 + 0.3; pos[n.id] = [cx + Math.cos(a) * 285, cy + Math.sin(a) * 195]; });
    const color = (t) => /Brand/.test(t) ? '#c084fc' : /Attachment/.test(t) ? '#ffaa00' : /URL/.test(t) ? '#7dd3fc' : /IP|Nameserver/.test(t) ? '#94a3b8' : /DNA/.test(t) ? '#00d68f' : /Email/.test(t) ? '#00c8ff' : '#1a6fff';
    const svg = `<svg viewBox="0 0 ${W} ${H}" role="img" aria-label="Threat relationship graph">
      ${edges.map((e) => { const a = pos[e.source], b = pos[e.target]; if (!a || !b) return ''; return `<line x1="${a[0]}" y1="${a[1]}" x2="${b[0]}" y2="${b[1]}" stroke="rgba(0,200,255,.25)" stroke-width="1"><title>${esc(e.relation)} — ${esc(e.evidence)}</title></line>`; }).join('')}
      ${nodes.map((n) => { const p = pos[n.id]; if (!p) return ''; const lbl = n.label.length > 26 ? n.label.slice(0, 25) + '…' : n.label;
        return `<g><circle cx="${p[0]}" cy="${p[1]}" r="${n === center ? 10 : 6}" fill="${color(n.type)}"><title>${esc(n.type)}: ${esc(n.label)}</title></circle>
        <text x="${p[0]}" y="${p[1] + (n === center ? 24 : 18)}" text-anchor="middle" font-size="10.5" fill="#cbd5e1" font-family="JetBrains Mono, monospace">${esc(lbl)}</text></g>`; }).join('')}
    </svg>`;
    const lab = Object.fromEntries(nodes.map((n) => [n.id, n.label]));
    return `<div class="graph-box">${svg}</div>
      <details class="x" style="margin-top:12px"><summary>Relationship explanations (${edges.length} edges)</summary><div class="body"><div class="tbl-wrap"><table class="tbl"><thead><tr><th>From</th><th>Relation</th><th>To</th><th>Evidence</th></tr></thead><tbody>
      ${edges.map((e) => `<tr><td class="brk">${esc(lab[e.source])}</td><td class="k">${esc(e.relation)}</td><td class="brk">${esc(lab[e.target])}</td><td>${esc(e.evidence)}</td></tr>`).join('')}</tbody></table></div>
      <p class="muted small">${esc(g.note)}</p></div></details>`;
  };
})();
