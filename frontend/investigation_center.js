/* ═══════════════════════════════════════════════════════════════════════════
   NEURASHIELD UNIFIED INVESTIGATION CENTER — JAVASCRIPT CONTROLLER
   Coordinates unified input, neural core visualizer, progressive timeline,
   live evidence streaming, interactive threat relationship graph, and Threat DNA.
   ═══════════════════════════════════════════════════════════════════════════ */

(function () {
  'use strict';

  const esc = (window.NS && window.NS.esc) || function (s) {
    if (s === null || s === undefined) return '';
    return String(s).replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
  };

  // ── State ────────────────────────────────────────────────────────────────
  let currentInputType = 'URL';
  let selectedQrFile = null;
  let selectedEmailFile = null;
  let activeInvestigation = null;
  let timerInterval = null;
  let timerSeconds = 0;
  let coreAnimationId = null;

  // ── DOM Elements ─────────────────────────────────────────────────────────
  const sidebarNav = document.getElementById('sidebar-nav');
  const typeTabs = document.getElementById('type-tabs');
  const fieldTextGroup = document.getElementById('field-text-group');
  const fieldQrGroup = document.getElementById('field-qr-group');
  const fieldEmailGroup = document.getElementById('field-email-group');
  const targetInput = document.getElementById('target-input');
  const btnStart = document.getElementById('btn-start');
  const btnStartQr = document.getElementById('btn-start-qr');
  const btnStartEmail = document.getElementById('btn-start-email');
  const btnPaste = document.getElementById('btn-paste');
  const qrDropzone = document.getElementById('qr-dropzone');
  const qrFileInput = document.getElementById('qr-file-input');
  const qrDropText = document.getElementById('qr-drop-text');
  const emailDropzone = document.getElementById('email-dropzone');
  const emailFileInput = document.getElementById('email-file-input');
  const emailDropText = document.getElementById('email-drop-text');
  const btnToggleRawEmail = document.getElementById('btn-toggle-raw-email');
  const rawEmailWrap = document.getElementById('raw-email-wrap');
  const rawEmailInput = document.getElementById('raw-email-input');

  const sectionCockpit = document.getElementById('section-cockpit');
  const sectionResults = document.getElementById('section-results');
  const timelineList = document.getElementById('timeline-list');
  const agentStageTitle = document.getElementById('agent-stage-title');
  const agentStageSub = document.getElementById('agent-stage-sub');
  const agentDecisionFeed = document.getElementById('agent-decision-feed');
  const evidenceStream = document.getElementById('evidence-stream');
  const evidenceCountBadge = document.getElementById('evidence-count-badge');
  const investigationTimer = document.getElementById('investigation-timer');
  const coreCanvas = document.getElementById('agent-core-canvas');

  // Stage 3 Results Elements
  const resInvIdBadge = document.getElementById('res-inv-id-badge');
  const resTypePill = document.getElementById('res-type-pill');
  const resTargetText = document.getElementById('res-target-text');
  const resStatusPill = document.getElementById('res-status-pill');
  const resStatusText = document.getElementById('res-status-text');
  const resDurationPill = document.getElementById('res-duration-pill');

  const resRiskScore = document.getElementById('res-risk-score');
  const resRiskLevel = document.getElementById('res-risk-level');
  const resConfidence = document.getElementById('res-confidence');
  const resHeadline = document.getElementById('res-headline');
  const resExecSummary = document.getElementById('res-exec-summary');
  const resConfidenceNote = document.getElementById('res-confidence-note');
  const resQuickTags = document.getElementById('res-quick-tags');
  const btnToggleWhySummary = document.getElementById('btn-toggle-why-summary');

  // Guidance elements
  const guidanceActionBanner = document.getElementById('guidance-action-banner');
  const guidanceImmediateTitle = document.getElementById('guidance-immediate-title');
  const guidanceImmediateDetail = document.getElementById('guidance-immediate-detail');
  const guidanceWhyList = document.getElementById('guidance-why-list');
  const guidanceDonotList = document.getElementById('guidance-donot-list');
  const guidanceStepsList = document.getElementById('guidance-steps-list');
  const guidanceSeverityBadge = document.getElementById('guidance-severity-badge');

  // Agent decisions
  const agentStatusTag = document.getElementById('agent-status-tag');
  const agentTerminationReason = document.getElementById('agent-termination-reason');
  const agentDecisionsContainer = document.getElementById('agent-decisions-container');

  // Timeline
  const resTimelineDetailed = document.getElementById('res-timeline-detailed');

  // Evidence
  const resEvidenceCountBadge = document.getElementById('res-evidence-count-badge');
  const resEvidenceCardsContainer = document.getElementById('res-evidence-cards-container');
  const evidenceFilterButtons = document.getElementById('evidence-filter-buttons');
  let currentEvidenceFilter = 'ALL';

  // Threat DNA
  const resDnaFingerprint = document.getElementById('res-dna-fingerprint');
  const resDnaIdentity = document.getElementById('res-dna-identity');
  const resDnaDelivery = document.getElementById('res-dna-delivery');
  const resDnaTarget = document.getElementById('res-dna-target');
  const resDnaSocialTraits = document.getElementById('res-dna-social-traits');
  const resDnaUrlTraits = document.getElementById('res-dna-url-traits');
  const resDnaDomainTraits = document.getElementById('res-dna-domain-traits');
  const resDnaInfraTraits = document.getElementById('res-dna-infra-traits');
  const resDnaReputationTraits = document.getElementById('res-dna-reputation-traits');
  const resDnaThreatIntel = document.getElementById('res-dna-threat-intel');
  const resDnaCampaignContext = document.getElementById('res-dna-campaign-context');

  // Module 6: Threat Intelligence & Incident Response Elements
  const resM6Container = document.getElementById('res-m6-container');
  const btnToggleThreatIntel = document.getElementById('btn-toggle-threat-intel');
  const btnToggleCampaign = document.getElementById('btn-toggle-campaign');
  const btnCreateIncident = document.getElementById('btn-create-incident');
  const m6StatIntelStatus = document.getElementById('m6-stat-intel-status');
  const m6StatIndicators = document.getElementById('m6-stat-indicators');
  const m6StatRelated = document.getElementById('m6-stat-related');
  const m6StatAssessment = document.getElementById('m6-stat-assessment');
  const m6StatSeverity = document.getElementById('m6-stat-severity');
  const m6CreatedIncidentCard = document.getElementById('m6-created-incident-card');
  const incBadgeStatus = document.getElementById('inc-badge-status');
  const incBadgeId = document.getElementById('inc-badge-id');
  const incBadgeCreated = document.getElementById('inc-badge-created');
  const incBadgeDetails = document.getElementById('inc-badge-details');
  const resThreatIntelIndicators = document.getElementById('res-threat-intel-indicators');
  const resCampaignCorrelationBody = document.getElementById('res-campaign-correlation-body');
  const resResponseGuidanceBody = document.getElementById('res-response-guidance-body');
  const m6ThreatIntelSection = document.getElementById('m6-threat-intel-section');
  const m6CampaignSection = document.getElementById('m6-campaign-section');

  // Correlations & Contributors & Limitations
  const resCorrelationsList = document.getElementById('res-correlations-list');
  const resContributorsList = document.getElementById('res-contributors-list');
  const resLimitationsContainer = document.getElementById('res-limitations-container');

  // Footer & Actions
  const resInvId = document.getElementById('res-inv-id');
  const btnViewReport = document.getElementById('btn-view-report');
  const btnExportJson = document.getElementById('btn-export-json');
  const btnNewInvestigation = document.getElementById('btn-new-investigation');

  // Graph elements
  const graphCanvas = document.getElementById('graph-canvas');
  const graphNodeModal = document.getElementById('graph-node-modal');
  const modalNodeTitle = document.getElementById('modal-node-title');
  const modalNodeContent = document.getElementById('modal-node-content');
  const modalNodeClose = document.getElementById('modal-node-close');
  const graphBtnReset = document.getElementById('graph-btn-reset');
  const graphBtnZoomIn = document.getElementById('graph-btn-zoom-in');
  const graphBtnZoomOut = document.getElementById('graph-btn-zoom-out');

  // ── 1. Initialize Navigation & URL Parameters ───────────────────────────
  if (window.NS && window.NS.renderNav && sidebarNav) {
    window.NS.renderNav(sidebarNav, 'investigation_center');
  }

  // Handle URL query parameters for direct links (e.g. ?url=..., ?domain=..., ?type=qr)
  const urlParams = new URLSearchParams(window.location.search);
  if (urlParams.get('url')) {
    switchInputType('URL');
    targetInput.value = urlParams.get('url');
  } else if (urlParams.get('domain')) {
    switchInputType('DOMAIN');
    targetInput.value = urlParams.get('domain');
  } else if (urlParams.get('type') === 'qr') {
    switchInputType('QR_IMAGE');
  } else if (urlParams.get('type') === 'email') {
    switchInputType('EMAIL');
  }

  // ── 2. Input Type Tab Switching ─────────────────────────────────────────
  typeTabs.addEventListener('click', (e) => {
    const btn = e.target.closest('.ic-type-btn');
    if (!btn) return;
    const type = btn.getAttribute('data-type');
    switchInputType(type);
  });

  function switchInputType(type) {
    currentInputType = type;
    document.querySelectorAll('.ic-type-btn').forEach(b => {
      b.classList.toggle('active', b.getAttribute('data-type') === type);
    });

    fieldTextGroup.style.display = 'none';
    fieldQrGroup.style.display = 'none';
    fieldEmailGroup.style.display = 'none';

    if (type === 'URL') {
      fieldTextGroup.style.display = 'flex';
      targetInput.placeholder = 'Paste suspicious URL (e.g. https://auth-secure-verify.com/login)...';
      targetInput.focus();
    } else if (type === 'DOMAIN') {
      fieldTextGroup.style.display = 'flex';
      targetInput.placeholder = 'Enter target domain name (e.g. suspicious-bank-alert.xyz)...';
      targetInput.focus();
    } else if (type === 'WEBPAGE') {
      fieldTextGroup.style.display = 'flex';
      targetInput.placeholder = 'Enter webpage URL to retrieve and inspect static structure & scripts...';
      targetInput.focus();
    } else if (type === 'QR_IMAGE') {
      fieldQrGroup.style.display = 'block';
    } else if (type === 'EMAIL') {
      fieldEmailGroup.style.display = 'block';
    }
  }

  // Paste helper
  if (btnPaste) {
    btnPaste.addEventListener('click', async () => {
      try {
        const text = await navigator.clipboard.readText();
        if (text) {
          targetInput.value = text.trim();
          targetInput.focus();
        }
      } catch (err) {
        targetInput.focus();
      }
    });
  }

  // ── 3. File Dropzone Handlers (QR & Email) ──────────────────────────────
  // QR Dropzone
  qrFileInput.addEventListener('click', (e) => e.stopPropagation());
  qrDropzone.addEventListener('click', (e) => {
    if (e.target !== qrFileInput) {
      qrFileInput.click();
    }
  });

  qrFileInput.addEventListener('change', () => {
    if (qrFileInput.files && qrFileInput.files[0]) {
      handleQrFile(qrFileInput.files[0]);
    }
  });

  ['dragenter', 'dragover'].forEach(name => {
    qrDropzone.addEventListener(name, (e) => {
      e.preventDefault();
      qrDropzone.classList.add('dragover');
    });
  });
  ['dragleave', 'drop'].forEach(name => {
    qrDropzone.addEventListener(name, (e) => {
      e.preventDefault();
      qrDropzone.classList.remove('dragover');
      if (name === 'drop' && e.dataTransfer.files && e.dataTransfer.files[0]) {
        handleQrFile(e.dataTransfer.files[0]);
      }
    });
  });

  function handleQrFile(file) {
    selectedQrFile = file;
    qrDropText.innerHTML = `Selected QR Image: <b>${esc(file.name)}</b> (${Math.round(file.size / 1024)} KB)`;
    btnStartQr.disabled = false;

    // Render image preview thumbnail
    try {
      const reader = new FileReader();
      reader.onload = (ev) => {
        const previewImg = document.getElementById('qr-preview-img');
        const previewWrap = document.getElementById('qr-preview-wrap');
        const defaultIcon = document.getElementById('qr-default-icon');
        if (previewImg && previewWrap) {
          previewImg.src = ev.target.result;
          previewWrap.style.display = 'block';
          if (defaultIcon) defaultIcon.style.display = 'none';
        }
      };
      reader.readAsDataURL(file);
    } catch (e) {
      // preview optional
    }
  }

  // Load sample QR code for instant 1-click testing
  const btnLoadSampleQr = document.getElementById('btn-load-sample-qr');
  if (btnLoadSampleQr) {
    btnLoadSampleQr.addEventListener('click', async () => {
      try {
        btnLoadSampleQr.disabled = true;
        btnLoadSampleQr.innerHTML = '<span>⏳ Generating Sample...</span>';
        const r = await fetch('/api/sample/qr');
        const blob = await r.blob();
        const file = new File([blob], 'sample_phish_qr.png', { type: 'image/png' });
        handleQrFile(file);
        btnLoadSampleQr.disabled = false;
        btnLoadSampleQr.innerHTML = '<span>⚡ Load Test Sample QR</span>';
      } catch (err) {
        btnLoadSampleQr.disabled = false;
        btnLoadSampleQr.innerHTML = '<span>⚡ Load Test Sample QR</span>';
        alert('Could not generate sample QR: ' + err.message);
      }
    });
  }

  // Global clipboard paste: screenshot of QR automatically loads into QR mode
  window.addEventListener('paste', (e) => {
    if (!e.clipboardData || !e.clipboardData.items) return;
    for (const item of e.clipboardData.items) {
      if (item.type.indexOf('image') !== -1) {
        const file = item.getAsFile();
        if (file) {
          switchInputType('QR_IMAGE');
          handleQrFile(file);
          break;
        }
      }
    }
  });

  // Email Dropzone
  emailFileInput.addEventListener('click', (e) => e.stopPropagation());
  emailDropzone.addEventListener('click', (e) => {
    if (e.target !== emailFileInput) {
      emailFileInput.click();
    }
  });

  emailFileInput.addEventListener('change', () => {
    if (emailFileInput.files && emailFileInput.files[0]) {
      handleEmailFile(emailFileInput.files[0]);
    }
  });

  ['dragenter', 'dragover'].forEach(name => {
    emailDropzone.addEventListener(name, (e) => {
      e.preventDefault();
      emailDropzone.classList.add('dragover');
    });
  });
  ['dragleave', 'drop'].forEach(name => {
    emailDropzone.addEventListener(name, (e) => {
      e.preventDefault();
      emailDropzone.classList.remove('dragover');
      if (name === 'drop' && e.dataTransfer.files && e.dataTransfer.files[0]) {
        handleEmailFile(e.dataTransfer.files[0]);
      }
    });
  });

  function handleEmailFile(file) {
    selectedEmailFile = file;
    emailDropText.innerHTML = `Selected Email File: <b>${esc(file.name)}</b> (${Math.round(file.size / 1024)} KB)`;
    btnStartEmail.disabled = false;
  }

  if (btnToggleRawEmail) {
    btnToggleRawEmail.addEventListener('click', () => {
      const isVisible = rawEmailWrap.style.display !== 'none';
      rawEmailWrap.style.display = isVisible ? 'none' : 'block';
      if (!isVisible) {
        rawEmailInput.focus();
        btnStartEmail.disabled = false;
      }
    });
  }

  // ── 4. Unified Investigation Submission ─────────────────────────────────
  btnStart.addEventListener('click', executeInvestigation);
  targetInput.addEventListener('keydown', (e) => {
    if (e.key === 'Enter') executeInvestigation();
  });
  btnStartQr.addEventListener('click', executeInvestigation);
  btnStartEmail.addEventListener('click', executeInvestigation);

  async function executeInvestigation() {
    let payload = null;
    let formData = null;

    if (currentInputType in { 'URL': 1, 'DOMAIN': 1, 'WEBPAGE': 1 }) {
      const val = targetInput.value.trim();
      if (!val) {
        alert('Please enter a target URL or domain to investigate.');
        targetInput.focus();
        return;
      }
      payload = {
        input_type: currentInputType,
        target: val
      };
    } else if (currentInputType === 'QR_IMAGE') {
      if (!selectedQrFile) {
        alert('Please select or upload a QR image.');
        return;
      }
      formData = new FormData();
      formData.append('input_type', 'QR_IMAGE');
      formData.append('qr_image', selectedQrFile);
    } else if (currentInputType === 'EMAIL') {
      const rawText = rawEmailInput ? rawEmailInput.value.trim() : '';
      if (!selectedEmailFile && !rawText) {
        alert('Please select an .eml email file or paste raw RFC822 email text.');
        return;
      }
      formData = new FormData();
      formData.append('input_type', 'EMAIL');
      if (selectedEmailFile) {
        formData.append('email_file', selectedEmailFile);
      } else {
        formData.append('raw_email', rawText);
      }
    }

    // UI Transition to Cockpit (Stage 2)
    startCockpitUI();

    try {
      let resp;
      if (formData) {
        resp = await fetch('/api/investigate/unified', {
          method: 'POST',
          body: formData
        });
      } else {
        resp = await fetch('/api/investigate/unified', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(payload)
        });
      }

      if (!resp.ok) {
        const errJson = await resp.json().catch(() => ({}));
        throw new Error((errJson.error && errJson.error.message) || `Investigation failed with HTTP ${resp.status}`);
      }

      const report = await resp.json();
      activeInvestigation = report;
      renderInvestigationResults(report);

    } catch (err) {
      stopTimer();
      agentStageTitle.textContent = 'INVESTIGATION ERROR';
      agentStageTitle.style.color = 'var(--ic-red)';
      agentStageSub.textContent = err.message || 'An error occurred during evidence collection.';
      addDecisionLog('ERROR: ' + err.message);
    }
  }

  function startCockpitUI() {
    sectionCockpit.style.display = 'grid';
    sectionResults.style.display = 'none';
    sectionCockpit.scrollIntoView({ behavior: 'smooth', block: 'start' });

    // Reset components
    timelineList.innerHTML = '';
    evidenceStream.innerHTML = '';
    agentDecisionFeed.innerHTML = '';
    evidenceCountBadge.textContent = '0 items';
    agentStageTitle.textContent = 'AI INVESTIGATION AGENT ACTIVE';
    agentStageTitle.style.color = 'var(--ic-cyan)';
    agentStageSub.textContent = `Orchestrating multi-source investigation for ${currentInputType}...`;

    // Start timer & neural core
    startTimer();
    startAgentCore();

    // Initial timeline
    renderInitialTimeline();
    addDecisionLog(`[00:00] Initialized adaptive investigation workflow for ${currentInputType}.`);
  }

  function renderInitialTimeline() {
    const defaultSteps = [
      { id: 'start', title: 'Target Ingestion & Normalization', status: 'completed' },
      { id: 'dispatch', title: 'Adaptive Capability Selection', status: 'running' },
      { id: 'intel', title: 'Technical Evidence Collection', status: 'queued' },
      { id: 'corr', title: 'Cross-Source Threat Correlation', status: 'queued' },
      { id: 'synthesis', title: 'Threat DNA & Graph Synthesis', status: 'queued' },
    ];
    timelineList.innerHTML = defaultSteps.map(s => `
      <div class="ic-timeline-item ${s.status}" id="tl-step-${s.id}">
        <div class="ic-timeline-node"></div>
        <div class="ic-timeline-content">
          <div class="ic-timeline-title">${esc(s.title)}</div>
          <div class="ic-timeline-status">${s.status.toUpperCase()}</div>
        </div>
      </div>
    `).join('');
  }

  function addDecisionLog(msg) {
    const row = document.createElement('div');
    row.textContent = msg;
    agentDecisionFeed.prepend(row);
  }

  function startTimer() {
    timerSeconds = 0;
    investigationTimer.textContent = '00:00';
    if (timerInterval) clearInterval(timerInterval);
    timerInterval = setInterval(() => {
      timerSeconds++;
      const m = String(Math.floor(timerSeconds / 60)).padStart(2, '0');
      const s = String(timerSeconds % 60).padStart(2, '0');
      investigationTimer.textContent = `${m}:${s}`;
    }, 1000);
  }

  function stopTimer() {
    if (timerInterval) {
      clearInterval(timerInterval);
      timerInterval = null;
    }
  }

  // ── 5. Neural Core Animation ─────────────────────────────────────────────
  function startAgentCore() {
    if (!coreCanvas) return;
    const ctx = coreCanvas.getContext('2d');
    const W = coreCanvas.width;
    const H = coreCanvas.height;
    const cx = W / 2;
    const cy = H / 2;
    let t = 0;

    function frame() {
      ctx.clearRect(0, 0, W, H);
      t += 0.02;

      // Outer cyan orbit ring
      ctx.beginPath();
      ctx.arc(cx, cy, 140, 0, Math.PI * 2);
      ctx.strokeStyle = 'rgba(0, 200, 255, 0.18)';
      ctx.lineWidth = 1.5;
      ctx.stroke();

      // Middle counter-rotating dashed ring
      ctx.beginPath();
      ctx.arc(cx, cy, 100, t * -0.6, t * -0.6 + Math.PI * 1.5);
      ctx.setLineDash([8, 12]);
      ctx.strokeStyle = 'rgba(26, 111, 255, 0.5)';
      ctx.lineWidth = 2.5;
      ctx.stroke();
      ctx.setLineDash([]);

      // Inner fast spinning pulse ring
      ctx.beginPath();
      ctx.arc(cx, cy, 60, t * 1.2, t * 1.2 + Math.PI * 1.2);
      ctx.strokeStyle = 'rgba(0, 200, 255, 0.85)';
      ctx.lineWidth = 3;
      ctx.stroke();

      // Core pulsing orb
      const pulse = 0.5 + 0.5 * Math.sin(t * 3);
      ctx.beginPath();
      ctx.arc(cx, cy, 26 + pulse * 6, 0, Math.PI * 2);
      ctx.fillStyle = `rgba(0, 200, 255, ${0.25 + pulse * 0.3})`;
      ctx.shadowColor = '#00c8ff';
      ctx.shadowBlur = 18;
      ctx.fill();
      ctx.shadowBlur = 0;

      // 6 Satellite orbiting nodes
      for (let i = 0; i < 6; i++) {
        const angle = t * 0.8 + (i * Math.PI / 3);
        const r = 120 + Math.sin(t * 2 + i) * 12;
        const nx = cx + Math.cos(angle) * r;
        const ny = cy + Math.sin(angle) * r;

        ctx.beginPath();
        ctx.arc(nx, ny, 4, 0, Math.PI * 2);
        ctx.fillStyle = '#00c8ff';
        ctx.fill();

        // Connecting lines to core
        ctx.beginPath();
        ctx.moveTo(cx, cy);
        ctx.lineTo(nx, ny);
        ctx.strokeStyle = 'rgba(0, 200, 255, 0.08)';
        ctx.lineWidth = 1;
        ctx.stroke();
      }

      coreAnimationId = requestAnimationFrame(frame);
    }

    const pulseRing = document.querySelector('.ic-core-pulse-ring');
    if (pulseRing) pulseRing.style.display = 'block';

    if (coreAnimationId) cancelAnimationFrame(coreAnimationId);
    coreAnimationId = requestAnimationFrame(frame);
  }

  function stopAgentCore() {
    if (coreAnimationId) {
      cancelAnimationFrame(coreAnimationId);
      coreAnimationId = null;
    }
    const pulseRing = document.querySelector('.ic-core-pulse-ring');
    if (pulseRing) pulseRing.style.display = 'none';

    if (coreCanvas) {
      const ctx = coreCanvas.getContext('2d');
      const W = coreCanvas.width;
      const H = coreCanvas.height;
      ctx.clearRect(0, 0, W, H);

      const cx = W / 2;
      const cy = H / 2;

      ctx.beginPath();
      ctx.arc(cx, cy, 54, 0, Math.PI * 2);
      ctx.fillStyle = 'rgba(0, 221, 136, 0.08)';
      ctx.strokeStyle = '#00dd88';
      ctx.lineWidth = 2.5;
      ctx.fill();
      ctx.stroke();

      ctx.beginPath();
      ctx.arc(cx, cy, 32, 0, Math.PI * 2);
      ctx.fillStyle = 'rgba(0, 221, 136, 0.2)';
      ctx.fill();

      ctx.font = 'bold 26px monospace';
      ctx.fillStyle = '#00dd88';
      ctx.textAlign = 'center';
      ctx.textBaseline = 'middle';
      ctx.fillText('✓', cx, cy);
    }
  }

  // ── 6. Results & Stage 3 Synthesis Rendering (Section 20 Architecture) ────
  function renderInvestigationResults(report) {
    stopTimer();
    stopAgentCore();

    // Re-enable start buttons
    if (btnStart) btnStart.disabled = false;
    if (btnStartQr) btnStartQr.disabled = false;
    if (btnStartEmail) btnStartEmail.disabled = false;

    agentStageTitle.textContent = 'INVESTIGATION COMPLETE';
    agentStageTitle.style.color = 'var(--ic-green)';
    agentStageSub.textContent = `Evidence correlated across ${report.modules_executed ? report.modules_executed.length : 0} modules. Full report ready.`;

    // 1. Header Bar
    if (resInvIdBadge) resInvIdBadge.textContent = `INVESTIGATION: ${report.investigation_id || 'UNKNOWN'}`;
    if (resTypePill) resTypePill.textContent = `${(report.input_type || currentInputType).toUpperCase()} INVESTIGATION`;
    if (resTargetText) {
      const tgt = report.target;
      resTargetText.textContent = (typeof tgt === 'string') ? tgt : (tgt && tgt.normalized_url) ? tgt.normalized_url : (report.normalized_input || report.original_input || 'Target Artifact');
    }
    if (resStatusText) resStatusText.textContent = `STATUS: ${(report.status || 'COMPLETED').toUpperCase()}`;
    if (resStatusPill) resStatusPill.className = `ic-status-pill ${(report.status || 'completed').toLowerCase()}`;
    if (resDurationPill) {
      const dur = report.duration_seconds || (timerSeconds > 0 ? timerSeconds : 1.2);
      resDurationPill.textContent = `DURATION: ${typeof dur === 'number' ? dur.toFixed(1) : dur}s`;
    }

    // 2. Executive Summary & Composite Risk Gauge
    const risk = report.risk_assessment || report.summary || {};
    const score = risk.composite_score !== undefined ? risk.composite_score : (risk.risk_score || 0);
    const level = risk.risk_level || 'LOW';

    resRiskScore.textContent = score;
    resRiskScore.className = `ic-gauge-score ${level}`;
    resRiskLevel.textContent = level;
    resRiskLevel.className = `ic-gauge-badge ${level}`;
    resConfidence.textContent = `Assessment Confidence: ${risk.confidence || 0}%`;

    resExecSummary.textContent = report.executive_summary || 'Analysis complete.';
    resHeadline.textContent = `Threat Evaluation: ${level} Risk Target`;
    if (resConfidenceNote) {
      resConfidenceNote.textContent = risk.confidence_explanation || 'Confidence is evidence-derived based on verified data availability.';
    }

    if (btnToggleWhySummary) {
      btnToggleWhySummary.onclick = () => {
        const guidancePanel = document.getElementById('guidance-panel');
        if (guidancePanel) {
          guidancePanel.scrollIntoView({ behavior: 'smooth', block: 'center' });
        }
      };
    }

    // Quick tags for modules
    const executedTags = (report.modules_executed || []).map(m => `
      <span class="ic-trait-pill" style="border-color:var(--ic-border); color:var(--ic-cyan);">✓ ${esc(m.replace(/_/g, ' '))}</span>
    `);
    const unavailableTags = (report.modules_unavailable || []).map(u => `
      <span class="ic-trait-pill" style="border-color:rgba(255,255,255,0.1); color:var(--ic-text-muted);">○ ${esc(u.replace(/_/g, ' '))} UNAVAILABLE</span>
    `);
    resQuickTags.innerHTML = executedTags.concat(unavailableTags).join('');

    // 3. Analyst Operational Guidance (Prominent SOC Action Banner)
    const guidance = report.analyst_guidance || {};
    if (guidanceActionBanner) {
      guidanceActionBanner.className = `ic-immediate-action-banner ${level}`;
    }
    if (guidanceImmediateTitle) {
      guidanceImmediateTitle.textContent = guidance.immediate_action || 'EVALUATE TARGET WITH CAUTION';
    }
    if (guidanceImmediateDetail) {
      guidanceImmediateDetail.textContent = guidance.action_detail || 'Review technical evidence ledger before interacting.';
    }
    if (guidanceSeverityBadge) {
      guidanceSeverityBadge.textContent = `${level} PRIORITY ACTION`;
      guidanceSeverityBadge.style.color = (level === 'HIGH' || level === 'CRITICAL') ? 'var(--ic-red)' : (level === 'MEDIUM' ? 'var(--ic-amber)' : 'var(--ic-green)');
    }

    if (guidanceWhyList) {
      const whyItems = guidance.why_it_matters || guidance.why || [];
      guidanceWhyList.innerHTML = whyItems.length ? whyItems.map(w => `<li>${esc(w)}</li>`).join('') : '<li>No high-severity threats detected.</li>';
    }

    if (guidanceDonotList) {
      const doNotItems = guidance.do_not || [];
      guidanceDonotList.innerHTML = doNotItems.length ? doNotItems.map(d => `<li>${esc(d)}</li>`).join('') : '<li>No active prohibitions specified.</li>';
    }

    if (guidanceStepsList) {
      const stepItems = guidance.recommended_next_steps || [];
      guidanceStepsList.innerHTML = stepItems.length ? stepItems.map(s => `<li>${esc(s)}</li>`).join('') : '<li>Maintain standard security monitoring procedures.</li>';
    }

    // 4. AI Investigation Agent Operational Decisions
    if (agentStatusTag) {
      agentStatusTag.textContent = `STATUS: ${(report.status || 'COMPLETED').toUpperCase()}`;
    }
    if (agentTerminationReason) {
      agentTerminationReason.textContent = report.termination_reason || 'Sufficient evidence collected for high-confidence assessment.';
    }
    if (agentDecisionsContainer) {
      const decisions = report.agent_decisions || [];
      if (decisions.length > 0) {
        agentDecisionsContainer.innerHTML = decisions.map((d, i) => {
          const decId = d.decision_id || `DEC-${String(i + 1).padStart(2, '0')}`;
          const decChoice = d.selected || d.decision || 'Execute Capability';
          return `
            <div class="ic-dec-card">
              <div class="ic-dec-top">
                <span>${esc(decId)}</span>
                <span style="color:var(--ic-text-dim);font-size:10px;">${esc(d.source || 'ORCHESTRATOR')}</span>
              </div>
              <div class="ic-dec-field">
                <span class="ic-dec-label">Observed</span>
                <span class="ic-dec-val">${esc(d.observed || 'Input artifact processed')}</span>
              </div>
              <div class="ic-dec-field">
                <span class="ic-dec-label">Selected / Decision</span>
                <span class="ic-dec-val" style="color:var(--ic-cyan);font-weight:600;">${esc(decChoice)}</span>
              </div>
              <div class="ic-dec-field">
                <span class="ic-dec-label">Reason</span>
                <span class="ic-dec-val" style="color:var(--ic-text-dim);">${esc(d.reason || '')}</span>
              </div>
            </div>
          `;
        }).join('');
      } else {
        agentDecisionsContainer.innerHTML = '<div style="font-size:12px;color:var(--ic-text-muted);">No decision logs generated.</div>';
      }
    }

    // 5. Intelligent Investigation Timeline (Module, Status, Why, Result, Next)
    if (resTimelineDetailed) {
      const tSteps = report.timeline || [];
      if (tSteps.length > 0) {
        resTimelineDetailed.innerHTML = tSteps.map(s => {
          const st = (s.status || 'COMPLETED').toUpperCase();
          const whyText = s.why || 'Standard capability sequence';
          const resText = s.result || 'Capability executed successfully';
          const nextText = s.next || 'Downstream synthesis';
          return `
            <div class="ic-st-row">
              <div class="ic-st-module">${esc(s.title || s.module)}</div>
              <div><span class="ic-st-status ${st}">${esc(st)}</span></div>
              <div class="ic-st-why"><b style="color:var(--ic-text-muted);font-size:10px;">WHY:</b> ${esc(whyText)}</div>
              <div class="ic-st-res"><b style="color:var(--ic-text-muted);font-size:10px;">RESULT:</b> ${esc(resText)}</div>
              <div class="ic-st-next"><b style="color:var(--ic-text-muted);font-size:10px;">NEXT:</b> ${esc(nextText)}</div>
            </div>
          `;
        }).join('');
      } else {
        resTimelineDetailed.innerHTML = '<div style="font-size:12px;color:var(--ic-text-muted);">No timeline steps recorded.</div>';
      }
    }

    // Update Cockpit Timeline as well
    if (report.timeline) {
      timelineList.innerHTML = report.timeline.map((step) => `
        <div class="ic-timeline-item ${(step.status || 'completed').toLowerCase()}">
          <div class="ic-timeline-node"></div>
          <div class="ic-timeline-content">
            <div class="ic-timeline-title">${esc(step.title || step.module)}</div>
            <div class="ic-timeline-status">${esc(step.status || 'COMPLETED')}</div>
          </div>
        </div>
      `).join('');
    }

    // 6. Verified Technical Evidence Cards with Expandables
    const evList = report.evidence || [];
    renderEvidenceCards(evList, currentEvidenceFilter);
    initEvidenceFilterTabs(evList);

    // Update Cockpit Live Stream as well
    evidenceCountBadge.textContent = `${evList.length} items`;
    if (evList.length > 0) {
      evidenceStream.innerHTML = evList.map(ev => {
        const isSus = /suspicious|flagged|malicious|invalid|cross-domain|fail/i.test(ev.observation || '');
        return `
          <div class="ic-evidence-card ${isSus ? 'suspicious' : ev.verificationStatus === 'VERIFIED' ? 'verified' : 'inferred'}">
            <div class="ic-evidence-top">
              <span>${esc(ev.source)}</span>
              <span>${esc(ev.verificationStatus || ev.confidence)}</span>
            </div>
            <div class="ic-evidence-obs">${esc(ev.observation)}</div>
          </div>
        `;
      }).join('');
    }

    // 7. Threat DNA Profile
    const dna = report.threat_dna || {};
    resDnaFingerprint.textContent = dna.fingerprint || 'NS-DNA-UNKNOWN';
    resDnaIdentity.textContent = dna.identity || 'Standard Evaluation Target';
    resDnaDelivery.textContent = `Vector: ${dna.attack_vector || report.input_type || 'Direct'}`;
    if (resDnaTarget) {
      resDnaTarget.textContent = `Target: ${dna.target || 'Potential account credentials'}`;
    }

    if (resDnaSocialTraits) {
      const st = dna.social_engineering_traits || dna.social_engineering || [];
      resDnaSocialTraits.innerHTML = st.length ? st.map(t => `<span class="ic-trait-pill" style="border-color:rgba(255,170,0,0.4);color:var(--ic-amber);">${esc(t)}</span>`).join('') : '<span style="color:var(--ic-text-muted);font-size:12px;">None detected</span>';
    }

    if (resDnaUrlTraits) {
      const ut = dna.url_traits || [];
      resDnaUrlTraits.innerHTML = ut.length ? ut.map(t => `<span class="ic-trait-pill" style="border-color:rgba(0,200,255,0.3);color:var(--ic-cyan);">${esc(t)}</span>`).join('') : '<span style="color:var(--ic-text-muted);font-size:12px;">None detected</span>';
    }

    if (resDnaDomainTraits) {
      const dt = dna.domain_traits || [];
      resDnaDomainTraits.innerHTML = dt.length ? dt.map(t => `<span class="ic-trait-pill">${esc(t)}</span>`).join('') : '<span style="color:var(--ic-text-muted);font-size:12px;">Standard / Clean</span>';
    }

    if (resDnaInfraTraits) {
      const it = dna.infrastructure_traits || dna.infra_traits || [];
      resDnaInfraTraits.innerHTML = it.length ? it.map(t => `<span class="ic-trait-pill">${esc(t)}</span>`).join('') : '<span style="color:var(--ic-text-muted);font-size:12px;">Insufficient infrastructure evidence</span>';
    }

    if (resDnaReputationTraits) {
      const rep = dna.external_reputation || 'NOT CONFIGURED';
      resDnaReputationTraits.innerHTML = `<span class="ic-trait-pill" style="border-color:rgba(255,255,255,0.1);color:var(--ic-text-dim);">${esc(rep)}</span>`;
    }

    // 8. Cross-Source Correlations
    const corr = report.correlation || {};
    const supporting = corr.supporting_evidence || [];
    if (supporting.length > 0) {
      resCorrelationsList.innerHTML = supporting.map(s => `
        <div style="background:rgba(6,9,14,0.6); border:1px solid rgba(0,200,255,0.2); border-left:3px solid var(--ic-cyan); border-radius:4px; padding:10px 14px; font-size:12px;">
          <div style="font-weight:700; color:var(--ic-text); margin-bottom:4px; display:flex; justify-content:space-between;">
            <span>${esc(s.type)}</span>
            <span style="font-family:var(--ns-mono); color:var(--ic-cyan); font-size:10px;">${esc(s.confidence || 'HIGH')}</span>
          </div>
          <div style="color:var(--ic-text-dim); line-height:1.45;">${esc(s.description)}</div>
        </div>
      `).join('');
    } else {
      resCorrelationsList.innerHTML = '<div style="font-size:12px; color:var(--ic-text-muted);">Independent evidence did not indicate cross-layer convergence.</div>';
    }

    // 9. Multi-Dimensional Risk Factors & Contributors Breakdown
    if (resContributorsList) {
      const contribs = (report.risk_assessment && report.risk_assessment.contributors) || [];
      if (contribs.length > 0) {
        resContributorsList.innerHTML = contribs.map(c => `
          <div style="display:flex; justify-content:space-between; align-items:center; background:rgba(6,9,14,0.6); padding:8px 12px; border-radius:4px; font-size:12px;">
            <span style="color:var(--ic-text);">${esc(c.factor)}</span>
            <span style="font-family:var(--ns-mono); font-weight:700; color:${c.points > 0 ? 'var(--ic-red)' : 'var(--ic-text-muted)'};">
              ${c.status === 'EVALUATED' ? (c.points > 0 ? `+${c.points} pts` : '0 pts (Clean)') : 'UNAVAILABLE'}
            </span>
          </div>
        `).join('');
      } else {
        resContributorsList.innerHTML = '<div style="font-size:12px; color:var(--ic-text-muted);">No risk contributor factors recorded.</div>';
      }
    }

    // 10. Investigation Limitations & Disclosures
    if (resLimitationsContainer) {
      const limits = (report.risk_assessment && report.risk_assessment.limitations) || [];
      if (limits.length > 0) {
        resLimitationsContainer.innerHTML = limits.map(l => {
          if (typeof l === 'string') {
            return `
              <div class="ic-limitation-card">
                <div class="ic-limitation-desc">${esc(l)}</div>
              </div>
            `;
          }
          return `
            <div class="ic-limitation-card">
              <div class="ic-limitation-title">
                <span>${esc(l.module || l.dimension || 'Module')}</span>
                <span class="ic-st-status UNAVAILABLE">${esc(l.status || 'UNAVAILABLE')}</span>
              </div>
              <div class="ic-limitation-desc">${esc(l.reason || '')}</div>
              ${l.impact ? '<div class="ic-limitation-impact">Impact: ' + esc(l.impact) + '</div>' : ''}
            </div>
          `;
        }).join('');
      } else {
        resLimitationsContainer.innerHTML = '<div style="font-size:12px; color:var(--ic-text-muted);">All investigative capabilities executed with complete data provenance.</div>';
      }
    }

    // 11. Investigation ID & Export Actions
    resInvId.textContent = report.investigation_id || '—';
    const repTarget = report.original_input || report.normalized_input || (report.target && (report.target.original_url || report.target.normalized_url)) || '';
    btnViewReport.href = `/report?id=${encodeURIComponent(report.investigation_id || '')}&url=${encodeURIComponent(repTarget)}`;

    btnExportJson.onclick = () => {
      const dataStr = "data:text/json;charset=utf-8," + encodeURIComponent(JSON.stringify(report, null, 2));
      const a = document.createElement('a');
      a.setAttribute('href', dataStr);
      a.setAttribute('download', `${report.investigation_id}_evidence_package.json`);
      document.body.appendChild(a);
      a.click();
      a.remove();
    };

    // 11B. Module 6: Threat Intelligence & Incident Response Synthesis
    renderModule6Results(report);

    // Show Stage 3 FIRST so container dimensions are computed by the browser
    sectionResults.style.display = 'flex';
    sectionResults.scrollIntoView({ behavior: 'smooth', block: 'start' });

    // 12. Threat Relationship Graph (rendered after layout pass)
    requestAnimationFrame(() => {
      setTimeout(() => {
        renderThreatGraph(report.threat_graph || { nodes: [], edges: [] });
      }, 60);
    });
  }

  // ── Helper: Module 6 Synthesis and Incident Response Handler ──────────────
  function renderModule6Results(report) {
    if (!resM6Container) return;
    resM6Container.style.display = 'block';

    const m6 = report.module6_summary || {};
    const intel = report.threat_intelligence || {};
    const camp = report.campaign_correlation || {};
    const incAssess = report.incident_assessment || {};
    const guidance = report.response_guidance || {};

    // 1. Module 6 Summary Bar
    if (m6StatIntelStatus) {
      m6StatIntelStatus.textContent = (m6.threat_intel_status || 'COMPLETED').toUpperCase();
    }
    if (m6StatIndicators) {
      // indicators_checked can be a number (from module6_summary) or array (from threat_intelligence)
      const indArr = intel.indicators || [];
      const indCount = typeof intel.indicators_checked === 'number' ? intel.indicators_checked : (typeof m6.indicators_checked === 'number' ? m6.indicators_checked : indArr.length);
      m6StatIndicators.textContent = `${indCount} ${indCount === 1 ? 'indicator' : 'indicators'}`;
    }
    if (m6StatRelated) {
      const relInvs = camp.related_investigations || camp.matches || [];
      const matchCount = typeof camp.total_matches === 'number' ? camp.total_matches : relInvs.length;
      m6StatRelated.textContent = matchCount > 0 ? `${matchCount} potential ${matchCount === 1 ? 'match' : 'matches'}` : '0 matches';
    }
    if (m6StatAssessment) {
      m6StatAssessment.textContent = incAssess.incident_recommended ? 'INCIDENT RECOMMENDED' : 'MONITORING ONLY';
      m6StatAssessment.style.color = incAssess.incident_recommended ? 'var(--ic-red)' : 'var(--ic-green)';
    }
    if (m6StatSeverity) {
      const sev = (incAssess.severity || 'LOW').toUpperCase();
      m6StatSeverity.textContent = sev;
      m6StatSeverity.style.color = (sev === 'HIGH' || sev === 'CRITICAL') ? 'var(--ic-red)' : (sev === 'MEDIUM' ? 'var(--ic-amber)' : 'var(--ic-green)');
    }

    // 2. Discovered Indicator Threat Intelligence Cards
    if (resThreatIntelIndicators) {
      const indicators = intel.indicators || intel.indicators_checked || [];
      if (indicators.length === 0) {
        resThreatIntelIndicators.innerHTML = `
          <div style="font-size:12px; color:var(--ic-text-muted); padding:16px; background:rgba(6,9,14,0.4); border-radius:6px; border:1px dashed rgba(255,255,255,0.08);">
            No verified indicators queued for external threat-intelligence enrichment.
          </div>`;
      } else {
        resThreatIntelIndicators.innerHTML = indicators.map(ind => {
          const st = (ind.status || 'NO_MATCH').toUpperCase();
          const sources = ind.sources && ind.sources.length ? ind.sources.join(', ') : 'NeuraShield Global ThreatDB';
          const rep = ind.reputation || (st === 'NO_MATCH' ? 'No recorded malicious reputation in local threat intelligence repository or external feeds.' : (st === 'KNOWN_BENIGN' ? 'Legitimate trusted global infrastructure with verified benign classification.' : 'Telemetry unavailable'));
          const firstSeen = ind.first_seen || 'UNAVAILABLE';
          const lastSeen = ind.last_seen || 'UNAVAILABLE';
          const relInds = ind.related_indicators && ind.related_indicators.length ? ind.related_indicators.join(', ') : '';

          // Format Date Cleanly (e.g. Sep 15, 1997 or Sep 25, 2026 · 07:26 UTC)
          function formatIntelDate(val) {
            if (!val || val === 'UNAVAILABLE' || val === 'None') {
              return '<span class="ic-dim-tag">No Prior Record</span>';
            }
            try {
              const d = new Date(val);
              if (!isNaN(d.getTime())) {
                const dateStr = d.toLocaleDateString('en-US', { year: 'numeric', month: 'short', day: 'numeric' });
                const timeStr = d.toLocaleTimeString('en-US', { hour: '2-digit', minute: '2-digit', hour12: false });
                return `${dateStr} <span class="ic-time-dim">${timeStr} UTC</span>`;
              }
            } catch(e) {}
            return esc(String(val).split('.')[0].replace('T', ' '));
          }

          // Format Confidence Cleanly (No 'HIGH%' glitch)
          function formatIntelConfidence(conf) {
            if (conf === undefined || conf === null || conf === 'UNAVAILABLE') {
              return '<span class="ic-conf-badge medium">Standard (Verified)</span>';
            }
            const s = String(conf).trim().toUpperCase();
            if (s === 'HIGH' || s === 'HIGH%') {
              return '<span class="ic-conf-badge high">High (95%+)</span>';
            }
            if (s === 'MEDIUM' || s === 'MEDIUM%') {
              return '<span class="ic-conf-badge medium">Medium (75%)</span>';
            }
            if (s === 'LOW' || s === 'LOW%') {
              return '<span class="ic-conf-badge low">Low (&lt;50%)</span>';
            }
            const num = parseFloat(s);
            if (!isNaN(num)) {
              const lvl = num >= 80 ? 'high' : (num >= 50 ? 'medium' : 'low');
              return `<span class="ic-conf-badge ${lvl}">${Math.round(num)}% Verified</span>`;
            }
            return `<span class="ic-conf-badge high">${esc(conf)}</span>`;
          }

          // Format Type with Icon
          function formatIntelType(type) {
            const t = (type || 'INDICATOR').toUpperCase();
            if (t === 'DOMAIN') return '🌐 Domain';
            if (t === 'URL') return '🔗 URL Target';
            if (t === 'IP' || t === 'IPV4' || t === 'IPV6') return '🖥️ IP Address';
            if (t === 'EMAIL') return '📧 Sender Email';
            return '🔍 ' + t;
          }

          // Format Status Badge
          function formatStatusBadge(status) {
            if (status === 'KNOWN_MALICIOUS') {
              return '<span class="ic-st-badge malicious"><span class="badge-dot red"></span> Known Malicious</span>';
            }
            if (status === 'SUSPICIOUS') {
              return '<span class="ic-st-badge suspicious"><span class="badge-dot amber"></span> Suspicious</span>';
            }
            if (status === 'KNOWN_BENIGN') {
              return '<span class="ic-st-badge benign"><span class="badge-dot green"></span> Verified Benign</span>';
            }
            return '<span class="ic-st-badge clean"><span class="badge-dot cyan"></span> Clean / No Match</span>';
          }

          return `
            <div class="ic-indicator-card modern">
              <div class="ic-indicator-head-row">
                <div class="ic-indicator-badge-group">
                  <span class="ic-indicator-type-pill">${formatIntelType(ind.type)}</span>
                  <span class="ic-indicator-val-code" title="${esc(ind.value)}">${esc(ind.value)}</span>
                </div>
                <div>
                  ${formatStatusBadge(st)}
                </div>
              </div>

              <div class="ic-indicator-rep-banner ${st.toLowerCase()}">
                <div class="ic-rep-badge-title">Threat Reputation Assessment</div>
                <div class="ic-rep-body-text">${esc(rep)}</div>
              </div>

              <div class="ic-indicator-meta-grid">
                <div class="ic-ind-meta-item">
                  <span class="ic-ind-label">Verified Intelligence Sources</span>
                  <span class="ic-ind-val">${esc(sources)}</span>
                </div>
                <div class="ic-ind-meta-item">
                  <span class="ic-ind-label">Confidence Assessment</span>
                  <span class="ic-ind-val">${formatIntelConfidence(ind.confidence)}</span>
                </div>
                <div class="ic-ind-meta-item">
                  <span class="ic-ind-label">First Seen In Feeds</span>
                  <span class="ic-ind-val">${formatIntelDate(firstSeen)}</span>
                </div>
                <div class="ic-ind-meta-item">
                  <span class="ic-ind-label">Last Observed Activity</span>
                  <span class="ic-ind-val">${formatIntelDate(lastSeen)}</span>
                </div>
                <div class="ic-ind-meta-item full-width">
                  <span class="ic-ind-label">Correlated Threat Indicators</span>
                  <span class="ic-ind-val">${relInds ? esc(relInds) : '<span class="ic-dim-tag">None identified (Isolated infrastructure)</span>'}</span>
                </div>
              </div>
            </div>
          `;
        }).join('');
      }
    }

    // 3. Campaign & Historical Infrastructure Panel
    if (resCampaignCorrelationBody) {
      const matches = camp.related_investigations || camp.matches || [];
      if (matches.length === 0) {
        resCampaignCorrelationBody.innerHTML = `
          <div style="padding:14px 16px; background:rgba(6,9,14,0.5); border:1px solid rgba(255,255,255,0.08); border-radius:4px;">
            <div style="font-weight:700; color:var(--ic-text); font-size:12px; margin-bottom:4px;">NO RELATED ACTIVITY FOUND</div>
            <div style="font-size:11px; color:var(--ic-text-muted); line-height:1.45;">
              Telemetry cross-referencing did not identify overlapping infrastructure or shared indicators with past investigations. (Note: This indicates no active database match was observed, not that no campaign exists.)
            </div>
          </div>
        `;
      } else {
        resCampaignCorrelationBody.innerHTML = matches.map(m => `
          <div class="ic-campaign-card">
            <div class="ic-campaign-top">
              <div style="display:flex; align-items:center; gap:8px;">
                <span class="ic-campaign-label">POTENTIALLY RELATED INVESTIGATION</span>
                <a href="/report?id=${encodeURIComponent(m.investigation_id)}" target="_blank" style="font-family:var(--ns-mono); color:var(--ic-cyan); font-weight:700; font-size:12px; text-decoration:none;">
                  ${esc(m.investigation_id)} ↗
                </a>
              </div>
              <span style="font-size:11px; font-family:var(--ns-mono); color:var(--ic-amber); background:rgba(255,170,0,0.1); border:1px solid rgba(255,170,0,0.3); padding:2px 6px; border-radius:3px;">
                ${esc(m.relationship_label || m.relationship || 'SHARED_INFRASTRUCTURE')}
              </span>
            </div>
            <div style="margin-top:8px; font-size:12px; color:var(--ic-text-dim);">
              <div><b>Shared Indicators:</b> <span style="font-family:var(--ns-mono); color:var(--ic-text);">${esc((m.shared_indicators || [m.shared_indicator]).join(', '))}</span></div>
              <div style="margin-top:4px;"><b>Observed Telemetry:</b> ${esc(m.details || m.relationship_label || 'Shared infrastructure observed across telemetry')}</div>
              <div style="margin-top:4px; font-size:11px; color:var(--ic-text-muted);">
                <b>Provenance Notice:</b> Observed relationship based on verified technical overlap. Attacker identity and attribution are not inferred.
              </div>
            </div>
          </div>
        `).join('');
      }
    }

    // 4. Incident Response Guidance Panel
    if (resResponseGuidanceBody) {
      const actions = guidance.recommended_actions || [];
      const actionListHtml = actions.length > 0 ? actions.map(act => `
        <div class="ic-guidance-item">
          <div class="ic-guidance-top">
            <div style="display:flex; align-items:center; gap:6px;">
              <span class="ic-priority-chip ${esc(act.priority || 'P2')}">${esc(act.priority || 'P2')}</span>
              <span class="ic-guidance-badge">[ RECOMMENDED ACTION ]</span>
              <span style="font-weight:700; font-size:12px; color:var(--ic-text);">${esc(act.action)}</span>
            </div>
            <span style="font-size:11px; color:var(--ic-text-muted);">${esc(act.target || '')}</span>
          </div>
          <div style="font-size:12px; color:var(--ic-text-dim); margin-top:6px; line-height:1.45;">
            ${esc(act.description || '')}
          </div>
          <div style="font-size:11px; color:var(--ic-cyan); margin-top:6px;">
            <b>Evidence Basis:</b> ${esc(act.evidence_basis || act.rationale || 'Technical telemetry')}
          </div>
        </div>
      `).join('') : '<div style="font-size:12px; color:var(--ic-text-muted); padding:10px;">No immediate containment actions required.</div>';

      resResponseGuidanceBody.innerHTML = `
        <div style="margin-bottom:14px; background:rgba(6,9,14,0.6); border:1px solid rgba(0,200,255,0.2); border-radius:4px; padding:12px;">
          <div style="display:flex; justify-content:space-between; align-items:center;">
            <span style="font-weight:700; font-size:12px; color:var(--ic-text);">Incident Escalation Assessment:</span>
            <span style="font-weight:700; font-size:11px; color:${incAssess.incident_recommended ? 'var(--ic-red)' : 'var(--ic-green)'};">
              ${incAssess.incident_recommended ? 'INCIDENT CREATION RECOMMENDED' : 'MONITORING ONLY'}
            </span>
          </div>
          <div style="font-size:12px; color:var(--ic-text-dim); margin-top:6px; line-height:1.45;">
            ${esc(incAssess.reason || 'Telemetry analyzed for multi-indicator convergence.')}
          </div>
        </div>
        <div style="display:flex; flex-direction:column; gap:8px;">
          ${actionListHtml}
        </div>
      `;
    }

    // 5. Threat DNA Module 6 boxes
    if (resDnaThreatIntel) {
      const m6Dna = (report.threat_dna && report.threat_dna.threat_intelligence) || {};
      const hasIntel = m6Dna.known_malicious_indicators !== undefined || m6Dna.external_reputation;
      if (hasIntel) {
        resDnaThreatIntel.innerHTML = `
          <div style="font-size:12px; line-height:1.5;">
            <div><b>Reputation:</b> <span style="color:${m6Dna.external_reputation && /malicious/i.test(m6Dna.external_reputation) ? 'var(--ic-red)' : 'var(--ic-text)'}">${esc(m6Dna.external_reputation || 'Clean / None')}</span></div>
            <div><b>Confidence:</b> <span style="font-family:var(--ns-mono); color:var(--ic-cyan);">${m6Dna.intelligence_confidence || 0}%</span></div>
            <div><b>Malicious IoCs:</b> <span style="color:${(m6Dna.known_malicious_indicators || 0) > 0 ? 'var(--ic-red)' : 'var(--ic-text-muted)'}">${m6Dna.known_malicious_indicators || 0}</span></div>
          </div>
        `;
      } else {
        resDnaThreatIntel.textContent = 'No external reputation hits found';
      }
    }

    if (resDnaCampaignContext) {
      const cDna = (report.threat_dna && report.threat_dna.campaign_context) || {};
      const relatedCount = cDna.potentially_related_investigations ? cDna.potentially_related_investigations.length : 0;
      resDnaCampaignContext.innerHTML = `
        <div style="font-size:12px; line-height:1.5;">
          <div><b>Related Invs:</b> <span style="color:${relatedCount > 0 ? 'var(--ic-amber)' : 'var(--ic-text-muted)'}; font-family:var(--ns-mono);">${relatedCount} observed</span></div>
          <div><b>Shared Infra:</b> ${esc((cDna.shared_infrastructure && cDna.shared_infrastructure.length) ? cDna.shared_infrastructure.join(', ') : 'None')}</div>
          <div><b>Brand Target:</b> ${esc(cDna.brand_targeting_patterns || 'None')}</div>
        </div>
      `;
    }

    // 6. Risk Delta display in Risk Contributors
    const delta = report.risk_assessment && report.risk_assessment.risk_delta;
    if (resContributorsList && delta && delta.previous_score !== undefined) {
      const deltaHtml = `
        <div style="background:rgba(0,229,255,0.06); border:1px solid rgba(0,229,255,0.25); border-radius:4px; padding:10px 12px; margin-bottom:10px; font-size:12px;">
          <div style="font-weight:700; color:var(--ic-cyan); margin-bottom:6px; font-size:11px; text-transform:uppercase; letter-spacing:0.5px;">
            Module 6 Threat Intelligence Impact
          </div>
          <div style="display:flex; justify-content:space-between; margin-bottom:3px; color:var(--ic-text-dim);">
            <span>Baseline Risk Assessment:</span>
            <b style="font-family:var(--ns-mono); color:var(--ic-text);">${delta.previous_score} / 100</b>
          </div>
          <div style="display:flex; justify-content:space-between; margin-bottom:3px; color:var(--ic-text-dim);">
            <span>External Intelligence Evidence:</span>
            <b style="color:${/malicious/i.test(delta.new_evidence) ? 'var(--ic-red)' : 'var(--ic-text)'};">${esc(delta.new_evidence)}</b>
          </div>
          <div style="display:flex; justify-content:space-between; margin-bottom:3px; color:var(--ic-text-dim);">
            <span>Impact On Score:</span>
            <b style="font-family:var(--ns-mono); color:${delta.final_score > delta.previous_score ? 'var(--ic-red)' : 'var(--ic-text-muted)'};">${esc(delta.risk_impact)}</b>
          </div>
          <div style="display:flex; justify-content:space-between; border-top:1px solid rgba(255,255,255,0.1); padding-top:4px; margin-top:4px;">
            <span style="font-weight:700; color:var(--ic-text);">Final Verified Risk:</span>
            <b style="font-family:var(--ns-mono); color:var(--ic-cyan); font-size:13px;">${delta.final_score} / 100</b>
          </div>
        </div>
      `;
      resContributorsList.insertAdjacentHTML('afterbegin', deltaHtml);
    }

    // 7. Incident Creation Button Action
    if (btnCreateIncident) {
      const existingIncId = (incAssess && incAssess.incident_id) || (report.threat_dna && report.threat_dna.incident_context && report.threat_dna.incident_context.incident_id);
      if (existingIncId) {
        showCreatedIncidentCard(existingIncId, incAssess.status || 'TRIAGED', report);
        btnCreateIncident.disabled = true;
        btnCreateIncident.innerHTML = '<span>[ INCIDENT CREATED ]</span>';
        btnCreateIncident.style.background = 'rgba(255,255,255,0.1)';
        btnCreateIncident.style.color = 'var(--ic-text-muted)';
      } else {
        btnCreateIncident.disabled = false;
        btnCreateIncident.innerHTML = '<span>[ CREATE INCIDENT ]</span>';
        btnCreateIncident.style.background = 'var(--ic-cyan)';
        btnCreateIncident.style.color = '#050b14';

        btnCreateIncident.onclick = async () => {
          btnCreateIncident.disabled = true;
          btnCreateIncident.innerHTML = '<span>CREATING INCIDENT...</span>';
          try {
            const resp = await fetch(`/api/investigations/${encodeURIComponent(report.investigation_id)}/incidents`, {
              method: 'POST',
              headers: { 'Content-Type': 'application/json' },
              body: JSON.stringify({
                title: incAssess.title || `Phishing Incident: ${report.target || 'Target Artifact'}`,
                severity: incAssess.severity || 'HIGH',
                assigned_to: 'SOC-Analyst-Tier2',
                description: report.executive_summary || 'Incident auto-escalated from unified investigation findings.'
              })
            });

            if (!resp.ok) {
              const errData = await resp.json().catch(() => ({}));
              throw new Error((errData.error && errData.error.message) || `Failed to create incident (${resp.status})`);
            }

            const data = await resp.json();
            const inc = data.incident;
            showCreatedIncidentCard(inc.id || inc.incident_id, inc.status, report, inc);
            btnCreateIncident.innerHTML = '<span>[ INCIDENT CREATED ]</span>';
            btnCreateIncident.style.background = 'rgba(255,255,255,0.1)';
            btnCreateIncident.style.color = 'var(--ic-text-muted)';
          } catch (err) {
            alert(`Incident creation failed: ${err.message}`);
            btnCreateIncident.disabled = false;
            btnCreateIncident.innerHTML = '<span>[ CREATE INCIDENT ]</span>';
          }
        };
      }
    }

    // 8. Navigation Jump Buttons
    if (btnToggleThreatIntel && m6ThreatIntelSection) {
      btnToggleThreatIntel.onclick = () => {
        m6ThreatIntelSection.scrollIntoView({ behavior: 'smooth', block: 'center' });
      };
    }
    if (btnToggleCampaign && m6CampaignSection) {
      btnToggleCampaign.onclick = () => {
        m6CampaignSection.scrollIntoView({ behavior: 'smooth', block: 'center' });
      };
    }
  }

  function showCreatedIncidentCard(incId, status, report, incData) {
    if (!m6CreatedIncidentCard) return;
    m6CreatedIncidentCard.style.display = 'block';
    if (incBadgeId) incBadgeId.textContent = incId;
    if (incBadgeStatus) {
      incBadgeStatus.textContent = `STATUS: ${(status || 'TRIAGED').toUpperCase()}`;
      incBadgeStatus.className = `ic-status-pill ${(status || 'triaged').toLowerCase()}`;
    }
    if (incBadgeCreated) {
      incBadgeCreated.textContent = `Linked Investigation: ${report.investigation_id || 'Active'}`;
    }
    if (incBadgeDetails) {
      const title = (incData && incData.title) || (report.incident_assessment && report.incident_assessment.title) || `Phishing Incident: ${report.target}`;
      const sev = (incData && incData.severity) || (report.incident_assessment && report.incident_assessment.severity) || 'HIGH';
      const assigned = (incData && incData.assigned_to) || 'SOC-Analyst-Tier2';
      const indCount = (incData && incData.indicators && incData.indicators.length) || (report.threat_intelligence && report.threat_intelligence.indicators_checked && report.threat_intelligence.indicators_checked.length) || 1;
      const evCount = (report.evidence && report.evidence.length) || 0;

      incBadgeDetails.innerHTML = `
        <div style="display:grid; grid-template-columns: repeat(auto-fit, minmax(180px, 1fr)); gap:10px; font-size:12px;">
          <div><b>Title:</b> <span style="color:var(--ic-text);">${esc(title)}</span></div>
          <div><b>Severity:</b> <span style="color:${sev === 'HIGH' || sev === 'CRITICAL' ? 'var(--ic-red)' : 'var(--ic-amber)'}; font-weight:700;">${esc(sev)}</span></div>
          <div><b>Assigned Analyst:</b> <span style="color:var(--ic-cyan);">${esc(assigned)}</span></div>
          <div><b>Linked Indicators:</b> <span style="font-family:var(--ns-mono); color:var(--ic-text);">${indCount} IoCs</span></div>
          <div><b>Preserved Evidence:</b> <span style="font-family:var(--ns-mono); color:var(--ic-text);">${evCount} items</span></div>
          <div><b>Incident Workspace:</b> <a href="/incident-response" target="_blank" style="color:var(--ic-cyan); text-decoration:none;">Open Incident Console ↗</a></div>
        </div>
      `;
    }
    m6CreatedIncidentCard.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
  }

  // ── Helper: Evidence Filtering and Rich Card Rendering ───────────────────
  function initEvidenceFilterTabs(evidenceList) {
    if (!evidenceFilterButtons) return;
    evidenceFilterButtons.onclick = (e) => {
      const btn = e.target.closest('.ic-filter-btn');
      if (!btn) return;
      currentEvidenceFilter = btn.getAttribute('data-filter') || 'ALL';
      document.querySelectorAll('.ic-filter-btn').forEach(b => {
        b.classList.toggle('active', b === btn);
      });
      renderEvidenceCards(evidenceList, currentEvidenceFilter);
    };
  }

  function renderEvidenceCards(evidenceList, filter) {
    if (!resEvidenceCardsContainer) return;
    const filtered = evidenceList.filter(ev => {
      if (filter === 'ALL') return true;
      const status = (ev.verificationStatus || 'VERIFIED').toUpperCase();
      return status === filter;
    });

    if (resEvidenceCountBadge) {
      resEvidenceCountBadge.textContent = `${filtered.length} Items`;
    }

    if (filtered.length === 0) {
      resEvidenceCardsContainer.innerHTML = `
        <div style="font-size:12px; color:var(--ic-text-muted); grid-column: 1 / -1; padding:20px; text-align:center;">
          No evidence items matching filter "${esc(filter)}".
        </div>
      `;
      return;
    }

    resEvidenceCardsContainer.innerHTML = filtered.map((ev, idx) => {
      const status = (ev.verificationStatus || 'VERIFIED').toUpperCase();
      const whyMatters = ev.why_it_matters || ev.whyItMatters || 'Contributes structural technical telemetry to the composite investigation.';
      const actionGuidance = ev.action_guidance || (
        /fail|phish|malicious|suspicious|cross-domain/i.test(ev.observation || '')
          ? 'Block or quarantine entity across organizational perimeter; do not permit client interaction.'
          : 'Preserve evidence record for baseline telemetry comparison.'
      );
      const impactText = ev.impact || 'Telemetry Signal';
      const cardId = `ev-card-${idx}`;

      return `
        <div class="ic-evidence-card-rich status-${status}">
          <div class="ic-ev-header">
            <span style="color:var(--ic-text-dim);">${esc(ev.source || 'MODULE')}</span>
            <div style="display:flex; gap:6px; align-items:center;">
              <span class="ic-ev-pill ${status}">${esc(status)}</span>
              <span style="color:var(--ic-text-muted); font-size:10px;">${esc(ev.confidence || 'MEDIUM')}</span>
            </div>
          </div>
          <div class="ic-ev-obs">${esc(ev.observation)}</div>

          <!-- Why It Matters Expandable -->
          <div class="ic-ev-collapsible">
            <button type="button" class="ic-ev-toggle-btn" onclick="document.getElementById('${cardId}-why').style.display = document.getElementById('${cardId}-why').style.display === 'none' ? 'block' : 'none'">
              <span>▶ Why It Matters</span>
            </button>
            <div id="${cardId}-why" class="ic-ev-expand-content" style="display:none;">
              ${esc(whyMatters)}
            </div>
          </div>

          <!-- What Should I Do Expandable -->
          <div class="ic-ev-collapsible">
            <button type="button" class="ic-ev-toggle-btn" style="color:var(--ic-amber);" onclick="document.getElementById('${cardId}-act').style.display = document.getElementById('${cardId}-act').style.display === 'none' ? 'block' : 'none'">
              <span>▶ What Should I Do?</span>
            </button>
            <div id="${cardId}-act" class="ic-ev-expand-content" style="display:none; color:var(--ic-amber);">
              ${esc(actionGuidance)}
            </div>
          </div>

          <div class="ic-ev-impact-badge">${esc(impactText)}</div>
        </div>
      `;
    }).join('');
  }

  // ── 7. Interactive Threat Relationship Graph ────────────────────────────
  let graphData = { nodes: [], edges: [] };
  let graphScale = 1;
  let graphOffsetX = 0;
  let graphOffsetY = 0;
  let isDragging = false;
  let dragStartX = 0;
  let dragStartY = 0;
  let hoveredNode = null;

  function renderThreatGraph(graph) {
    if (!graphCanvas) return;
    graphData = graph || { nodes: [], edges: [] };
    const wrap = graphCanvas.parentElement;
    const w = (wrap && wrap.clientWidth > 100) ? wrap.clientWidth : (graphCanvas.clientWidth || 920);
    const h = (wrap && wrap.clientHeight > 100) ? wrap.clientHeight : 480;
    graphCanvas.width = w;
    graphCanvas.height = h;

    const nodes = graphData.nodes || [];
    const count = nodes.length;

    if (count === 0) {
      const ctx = graphCanvas.getContext('2d');
      ctx.clearRect(0, 0, w, h);
      ctx.font = '12px monospace';
      ctx.fillStyle = '#8b949e';
      ctx.textAlign = 'center';
      ctx.fillText('No interrelated threat entities identified in telemetry.', w / 2, h / 2);
      return;
    }

    // Arrange nodes radially around center
    const cx = w / 2;
    const cy = h / 2;

    nodes.forEach((n, idx) => {
      if (idx === 0) {
        n.x = cx;
        n.y = cy;
      } else {
        const angle = ((idx - 1) / Math.max(count - 1, 1)) * Math.PI * 2;
        const radius = Math.min(w, h) * 0.35 + ((idx % 2) * 25);
        n.x = cx + Math.cos(angle) * radius;
        n.y = cy + Math.sin(angle) * radius;
      }
    });

    drawGraph();
  }

  function drawGraph() {
    if (!graphCanvas) return;
    const ctx = graphCanvas.getContext('2d');
    const W = graphCanvas.width;
    const H = graphCanvas.height;

    ctx.clearRect(0, 0, W, H);
    ctx.save();
    ctx.translate(graphOffsetX, graphOffsetY);
    ctx.scale(graphScale, graphScale);

    const nodeMap = Object.fromEntries((graphData.nodes || []).map(n => [n.id, n]));

    // Draw Edges
    (graphData.edges || []).forEach(e => {
      const from = nodeMap[e.from];
      const to = nodeMap[e.to];
      if (from && to) {
        ctx.beginPath();
        ctx.moveTo(from.x, from.y);
        ctx.lineTo(to.x, to.y);
        ctx.strokeStyle = 'rgba(0, 200, 255, 0.35)';
        ctx.lineWidth = 1.8;
        ctx.stroke();

        // Label on edge midpoint
        const mx = (from.x + to.x) / 2;
        const my = (from.y + to.y) / 2;
        ctx.font = '10px monospace';
        ctx.fillStyle = 'rgba(255, 255, 255, 0.6)';
        ctx.textAlign = 'center';
        ctx.fillText(e.label || '', mx, my - 6);
      }
    });

    // Draw Nodes
    (graphData.nodes || []).forEach(n => {
      ctx.beginPath();
      ctx.arc(n.x, n.y, 18, 0, Math.PI * 2);

      let color = '#00c8ff';
      let typeGlyph = '◆';

      if (n.type === 'threat_intel') {
        color = (n.risk === 'CRITICAL' || n.risk === 'HIGH') ? '#ff3355' : '#ffaa00';
        typeGlyph = '⚡';
      } else if (n.type === 'campaign') {
        color = '#ffaa00';
        typeGlyph = '⬡';
      } else if (n.type === 'incident') {
        color = '#ff3355';
        typeGlyph = '🛡';
      } else if (n.type === 'investigation') {
        color = '#00c8ff';
        typeGlyph = '🔍';
      } else if (n.type === 'qr') {
        color = '#1a6fff';
        typeGlyph = '📱';
      } else if (n.type === 'email') {
        color = '#00dd88';
        typeGlyph = '✉';
      } else if (n.type === 'sender') {
        color = '#ffaa00';
        typeGlyph = '👤';
      } else if (n.type === 'domain') {
        color = '#00c8ff';
        typeGlyph = '🌐';
      } else if (n.type === 'ip') {
        color = '#a371f7';
        typeGlyph = 'IP';
      } else if (n.type === 'url') {
        color = '#00c8ff';
        typeGlyph = '🔗';
      } else {
        if (n.risk === 'CRITICAL' || n.risk === 'HIGH') color = '#ff3355';
        else if (n.risk === 'WARNING' || n.risk === 'MEDIUM') color = '#ffaa00';
      }

      ctx.fillStyle = '#06090e';
      ctx.fill();
      ctx.strokeStyle = color;
      ctx.lineWidth = 3;
      ctx.shadowColor = color;
      ctx.shadowBlur = 10;
      ctx.stroke();
      ctx.shadowBlur = 0;

      // Icon / initial letter inside node
      ctx.font = 'bold 11px monospace';
      ctx.fillStyle = color;
      ctx.textAlign = 'center';
      ctx.textBaseline = 'middle';
      ctx.fillText(typeGlyph, n.x, n.y);

      // Node label (truncated for cleanliness)
      ctx.textBaseline = 'alphabetic';
      ctx.font = '11px -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto';
      ctx.fillStyle = '#e6edf3';
      ctx.textAlign = 'center';
      const rawLabel = n.label || n.id;
      const displayLabel = rawLabel.length > 28 ? rawLabel.substring(0, 25) + '...' : rawLabel;
      ctx.fillText(displayLabel, n.x, n.y + 30);
    });

    ctx.restore();
  }

  // Handle window resize for graph canvas
  window.addEventListener('resize', () => {
    if (graphData && graphData.nodes && graphData.nodes.length) {
      renderThreatGraph(graphData);
    }
  });

  // Graph interaction (Pan & Zoom)
  if (graphCanvas) {
    graphCanvas.addEventListener('mousedown', (e) => {
      isDragging = true;
      dragStartX = e.clientX - graphOffsetX;
      dragStartY = e.clientY - graphOffsetY;
    });

    window.addEventListener('mousemove', (e) => {
      if (!isDragging) return;
      graphOffsetX = e.clientX - dragStartX;
      graphOffsetY = e.clientY - dragStartY;
      drawGraph();
    });

    window.addEventListener('mouseup', () => {
      isDragging = false;
    });

    graphCanvas.addEventListener('click', (e) => {
      const rect = graphCanvas.getBoundingClientRect();
      const mouseX = (e.clientX - rect.left - graphOffsetX) / graphScale;
      const mouseY = (e.clientY - rect.top - graphOffsetY) / graphScale;

      const clicked = (graphData.nodes || []).find(n => {
        const dx = n.x - mouseX;
        const dy = n.y - mouseY;
        return (dx * dx + dy * dy) <= 18 * 18;
      });

      if (clicked) {
        modalNodeTitle.textContent = `Entity: ${clicked.label || clicked.id}`;
        modalNodeContent.innerHTML = `
          <div><b>Type:</b> ${esc(clicked.type || 'N/A')}</div>
          <div><b>Risk:</b> ${esc(clicked.risk || 'INFO')}</div>
          <div><b>Metadata:</b> ${esc(JSON.stringify(clicked.metadata || {}))}</div>
        `;
        graphNodeModal.style.display = 'block';
      }
    });
  }

  if (modalNodeClose) {
    modalNodeClose.addEventListener('click', () => {
      graphNodeModal.style.display = 'none';
    });
  }

  if (graphBtnReset) {
    graphBtnReset.addEventListener('click', () => {
      graphScale = 1;
      graphOffsetX = 0;
      graphOffsetY = 0;
      drawGraph();
    });
  }
  if (graphBtnZoomIn) {
    graphBtnZoomIn.addEventListener('click', () => {
      graphScale = Math.min(graphScale * 1.25, 3);
      drawGraph();
    });
  }
  if (graphBtnZoomOut) {
    graphBtnZoomOut.addEventListener('click', () => {
      graphScale = Math.max(graphScale * 0.8, 0.4);
      drawGraph();
    });
  }

  // Reset to new investigation
  if (btnNewInvestigation) {
    btnNewInvestigation.addEventListener('click', () => {
      stopAgentCore();
      sectionCockpit.style.display = 'none';
      sectionResults.style.display = 'none';
      targetInput.value = '';
      selectedQrFile = null;
      selectedEmailFile = null;
      qrDropText.textContent = 'Click or drag & drop a QR code image here';
      emailDropText.textContent = 'Click or drag & drop an .eml email file here';
      btnStartQr.disabled = true;
      btnStartEmail.disabled = true;
      window.scrollTo({ top: 0, behavior: 'smooth' });
      targetInput.focus();
    });
  }

})();
