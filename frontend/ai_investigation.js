/* ═══════════════════════════════════════════════════════════════════════════
   MODULE 5 — AI Investigation Agent Frontend Logic
   ═══════════════════════════════════════════════════════════════════════════ */
(function () {
  'use strict';
  const M5 = (window.M5 = {});
  const esc = (v) => {
    if (v === null || v === undefined) return '';
    return String(v).replace(/[&<>"'`]/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;', '`': '&#96;' }[c]));
  };

  let _report = null;
  let _agentAnim = null;
  let _selectedFile = null;

  // ── Tab Switching ──────────────────────────────────────────────────────
  document.querySelectorAll('.m5-tab').forEach((tab) => {
    tab.addEventListener('click', () => {
      document.querySelectorAll('.m5-tab').forEach((t) => t.classList.remove('active'));
      document.querySelectorAll('.m5-input-panel').forEach((p) => p.classList.remove('active'));
      tab.classList.add('active');
      const panel = document.getElementById('panel' + tab.dataset.tab.charAt(0).toUpperCase() + tab.dataset.tab.slice(1));
      if (panel) panel.classList.add('active');
    });
  });

  // ── QR File Handling ───────────────────────────────────────────────────
  const qrInput = document.getElementById('qrFileInput');
  const qrDrop = document.getElementById('qrDropZone');
  const qrName = document.getElementById('qrFilename');
  const qrBtn = document.getElementById('btnInvestigateQr');

  if (qrInput) {
    qrInput.addEventListener('change', (e) => {
      const file = e.target.files[0];
      if (file) {
        _selectedFile = file;
        qrName.textContent = file.name;
        qrBtn.disabled = false;
      }
    });
  }
  if (qrDrop) {
    qrDrop.addEventListener('dragover', (e) => { e.preventDefault(); qrDrop.classList.add('dragover'); });
    qrDrop.addEventListener('dragleave', () => qrDrop.classList.remove('dragover'));
    qrDrop.addEventListener('drop', (e) => {
      e.preventDefault();
      qrDrop.classList.remove('dragover');
      const file = e.dataTransfer.files[0];
      if (file) {
        _selectedFile = file;
        qrName.textContent = file.name;
        qrBtn.disabled = false;
      }
    });
  }

  // ── Investigation Starters ─────────────────────────────────────────────

  M5.startUrlInvestigation = function () {
    const url = document.getElementById('urlInput').value.trim();
    if (!url) return;
    _runInvestigation({ url: url, input_type: 'URL' });
  };

  M5.startDomainInvestigation = function () {
    const domain = document.getElementById('domainInput').value.trim();
    if (!domain) return;
    _runInvestigation({ domain: domain, input_type: 'DOMAIN' });
  };

  M5.startQrInvestigation = function () {
    if (!_selectedFile) return;
    const fd = new FormData();
    fd.append('qr_image', _selectedFile);
    _runInvestigation(fd, true);
  };

  // Enter key support
  document.getElementById('urlInput')?.addEventListener('keydown', (e) => { if (e.key === 'Enter') M5.startUrlInvestigation(); });
  document.getElementById('domainInput')?.addEventListener('keydown', (e) => { if (e.key === 'Enter') M5.startDomainInvestigation(); });

  // ── Core Investigation Runner ──────────────────────────────────────────

  async function _runInvestigation(payload, isFormData) {
    // Reset UI
    _report = null;
    _hideError();
    _showAgent('Initializing investigation…', 'Preparing analysis pipeline');
    _showTimeline([{ step: 1, title: 'Investigation Started', status: 'running', description: 'Analyzing input…' }]);
    _hideResults();
    _disableButtons(true);

    const agentCore = document.getElementById('agentCore');
    agentCore.className = 'm5-agent-core investigating';
    _startAgentAnimation();

    try {
      const endpoint = isFormData ? '/api/investigate/qr' : '/api/investigate';
      const opts = isFormData
        ? { method: 'POST', body: payload }
        : { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(payload) };

      const resp = await fetch(endpoint, opts);
      const data = await resp.json();

      if (!resp.ok) {
        const errMsg = (data.error && data.error.message) || data.error || 'Investigation failed';
        throw new Error(errMsg);
      }

      _report = data;
      _stopAgentAnimation();
      agentCore.className = 'm5-agent-core completed';
      _updateAgentStatus('Investigation Complete', `Risk: ${esc(data.risk_assessment?.risk_level || '—')} (${data.risk_assessment?.composite_score ?? '—'}/100)`);
      _renderResults(data);

    } catch (err) {
      _stopAgentAnimation();
      agentCore.className = 'm5-agent-core failed';
      _updateAgentStatus('Investigation Failed', err.message);
      _showError('Investigation Error', err.message);
    } finally {
      _disableButtons(false);
    }
  }

  // ── Agent Visual Animation ─────────────────────────────────────────────

  function _startAgentAnimation() {
    const canvas = document.getElementById('agentCanvas');
    if (!canvas) return;
    const ctx = canvas.getContext('2d');
    const dpr = Math.min(window.devicePixelRatio || 1, 2);
    const w = canvas.clientWidth || 100;
    canvas.width = w * dpr;
    canvas.height = w * dpr;
    let t0 = performance.now();
    const nodes = Array.from({ length: 6 }, (_, i) => ({ a: (i / 6) * Math.PI * 2, r: 0.32 + (i % 3) * 0.06, s: 0.3 + (i % 4) * 0.1 }));

    function frame(now) {
      const t = (now - t0) / 1000, W = canvas.width, c = W / 2;
      ctx.clearRect(0, 0, W, W);
      ctx.lineWidth = 1.2 * dpr;

      // Rings
      [0.42, 0.32, 0.22].forEach((r, i) => {
        ctx.strokeStyle = `rgba(0,200,255,${0.15 + i * 0.08})`;
        ctx.setLineDash(i === 1 ? [5 * dpr, 7 * dpr] : []);
        ctx.beginPath(); ctx.arc(c, c, W * r, t * (i % 2 ? -0.5 : 0.4), t * (i % 2 ? -0.5 : 0.4) + Math.PI * 1.6); ctx.stroke();
      });
      ctx.setLineDash([]);

      // Bright arc
      ctx.strokeStyle = 'rgba(0,200,255,0.9)'; ctx.lineWidth = 2 * dpr;
      ctx.beginPath(); ctx.arc(c, c, W * 0.42, t * 1.8, t * 1.8 + 0.5); ctx.stroke();

      // Nodes
      nodes.forEach((n) => {
        const a = n.a + t * n.s, x = c + Math.cos(a) * W * n.r, y = c + Math.sin(a) * W * n.r;
        ctx.fillStyle = 'rgba(26,111,255,0.9)'; ctx.beginPath(); ctx.arc(x, y, 2.5 * dpr, 0, Math.PI * 2); ctx.fill();
        ctx.strokeStyle = 'rgba(0,200,255,0.1)'; ctx.lineWidth = dpr; ctx.beginPath(); ctx.moveTo(c, c); ctx.lineTo(x, y); ctx.stroke();
      });

      // Center
      const pulse = 0.5 + 0.5 * Math.sin(t * 2.5);
      ctx.fillStyle = `rgba(0,200,255,${0.08 + pulse * 0.12})`; ctx.beginPath(); ctx.arc(c, c, W * 0.12, 0, Math.PI * 2); ctx.fill();
      ctx.strokeStyle = 'rgba(0,200,255,0.7)'; ctx.lineWidth = 1.5 * dpr; ctx.beginPath();
      for (let i = 0; i < 6; i++) { const a = Math.PI / 6 + (i * Math.PI) / 3; const x = c + Math.cos(a) * W * 0.08, y = c + Math.sin(a) * W * 0.08; i ? ctx.lineTo(x, y) : ctx.moveTo(x, y); }
      ctx.closePath(); ctx.stroke();

      _agentAnim = requestAnimationFrame(frame);
    }
    _agentAnim = requestAnimationFrame(frame);
  }

  function _stopAgentAnimation() {
    if (_agentAnim) { cancelAnimationFrame(_agentAnim); _agentAnim = null; }
  }

  // ── UI Helpers ─────────────────────────────────────────────────────────

  function _showAgent(stage, detail) {
    document.getElementById('agentSection').classList.add('active');
    _updateAgentStatus(stage, detail);
  }

  function _updateAgentStatus(stage, detail) {
    document.getElementById('agentStage').textContent = stage;
    document.getElementById('agentDetail').textContent = detail;
  }

  function _showTimeline(items) {
    const sec = document.getElementById('timelineSection');
    const list = document.getElementById('timelineList');
    sec.classList.add('active');
    list.innerHTML = items.map((item) => `
      <div class="m5-tl-item ${esc(item.status || 'waiting')}">
        <div class="m5-tl-title">${esc(item.title)}</div>
        <div class="m5-tl-desc">${esc(item.description || '')}</div>
      </div>
    `).join('');
  }

  function _hideResults() {
    document.getElementById('resultsSection').classList.remove('active');
  }

  function _showError(title, msg) {
    const sec = document.getElementById('errorSection');
    document.getElementById('errorTitle').textContent = title;
    document.getElementById('errorMsg').textContent = msg;
    sec.classList.add('active');
  }

  function _hideError() {
    document.getElementById('errorSection').classList.remove('active');
  }

  function _disableButtons(disabled) {
    document.querySelectorAll('.m5-btn-investigate').forEach((b) => b.disabled = disabled);
  }

  function _riskColor(score) {
    if (score >= 70) return '#ff3b3b';
    if (score >= 45) return '#ff7c00';
    if (score >= 20) return '#ffaa00';
    return '#00d68f';
  }

  // ── Render Results ─────────────────────────────────────────────────────

  function _renderResults(data) {
    const sec = document.getElementById('resultsSection');
    sec.classList.add('active');

    // Executive Summary
    document.getElementById('execSummary').textContent = data.executive_summary || '';

    // Risk Assessment
    const risk = data.risk_assessment || {};
    const score = risk.composite_score ?? 0;
    const level = risk.risk_level || 'LOW';
    document.getElementById('riskScore').innerHTML = `${score}<small>/100</small>`;
    const levelEl = document.getElementById('riskLevel');
    levelEl.textContent = level;
    levelEl.className = 'm5-risk-level ' + level;
    const barFill = document.getElementById('riskBarFill');
    barFill.style.width = score + '%';
    barFill.style.background = _riskColor(score);
    document.getElementById('riskExplanation').textContent = risk.explanation || '';

    // Risk Factors
    const factorsGrid = document.getElementById('factorsGrid');
    factorsGrid.innerHTML = (risk.factors || []).filter(f => f.status === 'EVALUATED').map((f) => {
      const color = _riskColor(f.score);
      return `<div class="m5-factor-card">
        <div class="m5-factor-name">${esc(f.dimension)}</div>
        <div class="m5-factor-score" style="color:${color}">${f.score}<small style="font-size:12px;opacity:0.5">/100</small></div>
        <div class="m5-factor-bar"><div class="m5-factor-bar-fill" style="width:${f.score}%;background:${color}"></div></div>
      </div>`;
    }).join('');

    // Timeline
    _showTimeline(data.timeline || []);

    // Module chips
    const chips = document.getElementById('moduleChips');
    chips.style.display = 'flex';
    const allMods = [...(data.modules_executed || []).map(m => ({ n: m, s: 'executed' })),
                     ...(data.modules_skipped || []).map(m => ({ n: m, s: 'skipped' })),
                     ...(data.modules_failed || []).map(m => ({ n: m, s: 'failed' }))];
    chips.innerHTML = allMods.map(m => `<span class="m5-module-chip ${m.s}">${esc(m.n.replace(/_/g, ' '))}</span>`).join('');

    // QR Analysis
    const qr = data.qr_analysis;
    const qrPanel = document.getElementById('qrPanel');
    if (qr) {
      qrPanel.style.display = '';
      const qrResults = document.getElementById('qrResults');
      let html = '';
      if (qr.qr_detected) {
        const payloads = qr.payloads || [];
        payloads.forEach((p) => {
          const cls = p.classification || {};
          html += `<div class="m5-qr-result">
            <div class="m5-qr-icon">${cls.payload_type === 'URL' ? '🔗' : cls.payload_type === 'EMAIL' ? '📧' : cls.payload_type === 'WIFI' ? '📶' : '📄'}</div>
            <div>
              <div class="m5-qr-payload-type">${esc(cls.payload_type)}</div>
              <div class="m5-qr-payload-data">${esc((cls.payload_data || '').substring(0, 200))}</div>
            </div>
          </div>`;
        });
      } else {
        html = '<p style="color:var(--ns-text-muted);font-size:13px">No QR code detected in the uploaded image.</p>';
      }
      // QR observations
      const obs = qr.observations || [];
      if (obs.length) {
        html += '<div style="margin-top:12px">';
        obs.forEach((o) => {
          html += `<div class="m5-evidence-item">
            <span class="m5-ev-badge ${esc(o.confidence || 'VERIFIED')}">${esc(o.confidence || 'VERIFIED')}</span>
            <div class="m5-ev-text">${esc(o.observation)}</div>
          </div>`;
        });
        html += '</div>';
      }
      qrResults.innerHTML = html;
    } else {
      qrPanel.style.display = 'none';
    }

    // Threat DNA
    const dna = data.threat_dna || {};
    document.getElementById('dnaFingerprint').textContent = dna.fingerprint || '—';
    const dnaInd = document.getElementById('dnaIndicators');
    dnaInd.innerHTML = (dna.indicators || []).map((ind) =>
      `<span class="m5-dna-indicator ${esc(ind.severity || 'INFO')}">${esc(ind.indicator)}</span>`
    ).join('');

    // Evidence
    const evidence = data.evidence || [];
    document.getElementById('evidenceCount').textContent = `${evidence.length} items`;
    document.getElementById('evidenceList').innerHTML = evidence.map((ev) => `
      <div class="m5-evidence-item">
        <span class="m5-ev-badge ${esc(ev.confidence)}">${esc(ev.confidence)}</span>
        <div>
          <div class="m5-ev-text">${esc(ev.observation)}</div>
          <div class="m5-ev-source">${esc(ev.source)} · ${esc(ev.category)}</div>
        </div>
      </div>
    `).join('');

    // Threat Graph
    _renderGraph(data.threat_graph || { nodes: [], edges: [] });

    // Agent Decisions
    const decisions = data.agent_decisions || [];
    document.getElementById('decisionList').innerHTML = decisions.map((d) => `
      <div class="m5-decision-item">
        <span class="m5-dec-time">${esc((d.timestamp || '').split('T')[1]?.substring(0, 8) || '')}</span>
        <span class="m5-dec-text"><strong>${esc(d.decision)}</strong> — ${esc(d.reason)}</span>
      </div>
    `).join('');

    // Recommendations
    document.getElementById('recsList').innerHTML = (data.recommendations || []).map((r) => `
      <div class="m5-rec-item">
        <span class="m5-rec-priority ${esc(r.priority)}">${esc(r.priority)}</span>
        <span class="m5-rec-action">${esc(r.action)}</span>
      </div>
    `).join('');

    // Limitations
    const lims = data.limitations || [];
    document.getElementById('limitationsList').innerHTML = lims.map((l) =>
      `<div class="m5-limitation-item">${esc(l)}</div>`
    ).join('');
  }

  // ── Threat Graph Renderer ──────────────────────────────────────────────

  function _renderGraph(graph) {
    const canvas = document.getElementById('graphCanvas');
    if (!canvas) return;
    const ctx = canvas.getContext('2d');
    const dpr = Math.min(window.devicePixelRatio || 1, 2);
    const rect = canvas.parentElement.getBoundingClientRect();
    canvas.width = rect.width * dpr;
    canvas.height = rect.height * dpr;
    ctx.scale(dpr, dpr);

    const W = rect.width, H = rect.height;
    const nodes = graph.nodes || [];
    const edges = graph.edges || [];
    if (!nodes.length) {
      ctx.fillStyle = 'rgba(107,123,141,0.4)';
      ctx.font = '13px Inter, sans-serif';
      ctx.textAlign = 'center';
      ctx.fillText('No relationship graph available', W / 2, H / 2);
      return;
    }

    // Position nodes in a force-directed-like layout
    const cx = W / 2, cy = H / 2;
    const radius = Math.min(W, H) * 0.35;
    const positions = {};
    nodes.forEach((n, i) => {
      const angle = (i / nodes.length) * Math.PI * 2 - Math.PI / 2;
      const r = i === 0 ? 0 : radius * (0.6 + (i % 3) * 0.15);
      positions[n.id] = {
        x: cx + (i === 0 ? 0 : Math.cos(angle) * r),
        y: cy + (i === 0 ? 0 : Math.sin(angle) * r),
      };
    });

    // Draw edges
    edges.forEach((e) => {
      const from = positions[e.from];
      const to = positions[e.to];
      if (!from || !to) return;
      ctx.strokeStyle = 'rgba(0,200,255,0.15)';
      ctx.lineWidth = 1;
      ctx.beginPath(); ctx.moveTo(from.x, from.y); ctx.lineTo(to.x, to.y); ctx.stroke();
      // Edge label
      const mx = (from.x + to.x) / 2, my = (from.y + to.y) / 2;
      ctx.fillStyle = 'rgba(107,123,141,0.5)';
      ctx.font = '9px JetBrains Mono, monospace';
      ctx.textAlign = 'center';
      ctx.fillText(e.label || '', mx, my - 4);
    });

    // Draw nodes
    const TYPE_COLORS = {
      url: '#00c8ff', domain: '#1a6fff', ip: '#6b7b8d', nameserver: '#6b7b8d',
      certificate: '#00d68f', webpage: '#ffaa00', indicator: '#ff7c00',
      qr: '#a855f7', form_destination: '#ff3b3b', script_source: '#6b7b8d',
      iframe_source: '#ffaa00',
    };
    nodes.forEach((n) => {
      const p = positions[n.id];
      if (!p) return;
      const color = TYPE_COLORS[n.type] || '#6b7b8d';
      const r = n.id === nodes[0]?.id ? 18 : 12;

      // Glow
      ctx.fillStyle = color.replace(')', ',0.15)').replace('rgb', 'rgba');
      ctx.beginPath(); ctx.arc(p.x, p.y, r + 4, 0, Math.PI * 2); ctx.fill();

      // Node
      ctx.fillStyle = color;
      ctx.beginPath(); ctx.arc(p.x, p.y, r, 0, Math.PI * 2); ctx.fill();

      // Label
      ctx.fillStyle = '#e0e6f0';
      ctx.font = '10px JetBrains Mono, monospace';
      ctx.textAlign = 'center';
      ctx.fillText(n.label || '', p.x, p.y + r + 14);

      // Type label
      ctx.fillStyle = 'rgba(107,123,141,0.6)';
      ctx.font = '8px JetBrains Mono, monospace';
      ctx.fillText(n.type?.toUpperCase() || '', p.x, p.y + r + 24);
    });
  }

  // ── Panel Toggle ───────────────────────────────────────────────────────

  M5.togglePanel = function (id) {
    const el = document.getElementById(id);
    if (el) el.classList.toggle('collapsed');
  };

  // ── Export JSON ────────────────────────────────────────────────────────

  M5.exportJSON = function () {
    if (!_report) return;
    const blob = new Blob([JSON.stringify(_report, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `neurashield_investigation_${_report.investigation_id || 'report'}.json`;
    a.click();
    URL.revokeObjectURL(url);
  };

  // ── New Investigation ──────────────────────────────────────────────────

  M5.newInvestigation = function () {
    _report = null;
    _selectedFile = null;
    _hideError();
    _hideResults();
    document.getElementById('agentSection').classList.remove('active');
    document.getElementById('timelineSection').classList.remove('active');
    document.getElementById('moduleChips').style.display = 'none';
    document.getElementById('urlInput').value = '';
    document.getElementById('domainInput').value = '';
    document.getElementById('qrFilename').textContent = '';
    document.getElementById('btnInvestigateQr').disabled = true;
    document.getElementById('inputSection').scrollIntoView({ behavior: 'smooth' });
  };

})();
