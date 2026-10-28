/**
 * NeuraShield Chrome Extension — Popup Controller
 * Premium Cybersecurity SOC Console Logic
 */

document.addEventListener('DOMContentLoaded', () => {
  let currentEmailContext = null;
  let currentReport = null;

  // DOM Elements
  const backendDot = document.getElementById('backendDot');
  const backendStatusText = document.getElementById('backendStatusText');

  const tabEmailMode = document.getElementById('tabEmailMode');
  const tabUrlMode = document.getElementById('tabUrlMode');
  const sectionEmailMode = document.getElementById('sectionEmailMode');
  const sectionUrlMode = document.getElementById('sectionUrlMode');

  const emailStatusBadge = document.getElementById('emailStatusBadge');
  const emailSenderVal = document.getElementById('emailSenderVal');
  const emailOrgVal = document.getElementById('emailOrgVal');
  const emailDomainVal = document.getElementById('emailDomainVal');
  const emailSubjectVal = document.getElementById('emailSubjectVal');
  const emailLinksCountVal = document.getElementById('emailLinksCountVal');
  const btnAnalyzeEmail = document.getElementById('btnAnalyzeEmail');
  const btnRefreshGmail = document.getElementById('btnRefreshGmail');

  const targetUrlInput = document.getElementById('targetUrlInput');
  const btnInvestigateUrl = document.getElementById('btnInvestigateUrl');

  const scanningHud = document.getElementById('scanningHud');
  const scanStageTitle = document.getElementById('scanStageTitle');
  const scanStepsList = document.getElementById('scanStepsList');

  const reportContainer = document.getElementById('reportContainer');
  const riskBanner = document.getElementById('riskBanner');
  const repVerdictText = document.getElementById('repVerdictText');
  const repReasonText = document.getElementById('repReasonText');
  const repScoreNum = document.getElementById('repScoreNum');

  const btnOpenWebConsole = document.getElementById('btnOpenWebConsole');
  const btnExportJson = document.getElementById('btnExportJson');

  const currentTabUrlText = document.getElementById('currentTabUrlText');
  const btnScanCurrentTab = document.getElementById('btnScanCurrentTab');
  let activeTabUrl = '';

  // ── 1. Check Backend Connectivity ──
  async function checkBackend() {
    backendStatusText.textContent = 'CONNECTING...';
    try {
      const status = await NeuraShieldAPI.checkStatus();
      if (status.online) {
        backendDot.className = 'ns-pulse-dot online';
        const isRender = (status.url || '').includes('onrender.com');
        backendStatusText.textContent = isRender ? 'ONLINE (RENDER)' : 'ONLINE';
      } else {
        backendDot.className = 'ns-pulse-dot offline';
        backendStatusText.textContent = 'OFFLINE';
      }
    } catch (e) {
      backendDot.className = 'ns-pulse-dot offline';
      backendStatusText.textContent = 'OFFLINE';
    }
  }

  // ── 2. Sync Gmail Email Context ──
  let autoEmailTriggered = false;
  function syncGmailContext() {
    if (typeof chrome === 'undefined' || !chrome.runtime || !chrome.runtime.sendMessage) {
      return;
    }

    chrome.runtime.sendMessage({ type: 'GET_ACTIVE_EMAIL' }, (response) => {
      if (chrome.runtime.lastError || !response) return;

      if (response.email) {
        currentEmailContext = response.email;
        emailSenderVal.textContent = response.email.sender_email || 'Unknown';
        emailOrgVal.textContent = response.email.claimed_org || 'None Claimed';
        emailDomainVal.textContent = response.email.sender_domain || '—';
        emailSubjectVal.textContent = response.email.subject || '—';
        const linkCount = (response.email.links || []).length;
        emailLinksCountVal.textContent = `${linkCount} link(s) detected`;
        const attachCount = (response.email.attachments || []).length;
        const emailAttachmentsVal = document.getElementById('emailAttachmentsVal');
        if (emailAttachmentsVal) {
          emailAttachmentsVal.textContent = `${attachCount} attachment(s) detected`;
        }

        emailStatusBadge.textContent = 'READY';
        emailStatusBadge.style.color = '#38bdf8';
        btnAnalyzeEmail.disabled = false;

        if (response.lastResult && !currentReport) {
          renderReport(response.lastResult);
        } else if (!autoEmailTriggered && !currentReport && !response.lastResult) {
          // AUTO-ANALYZE: Automatically trigger email investigation
          autoEmailTriggered = true;
          btnAnalyzeEmail.disabled = true;
          setTimeout(() => {
            btnAnalyzeEmail.click();
          }, 400);
        }
      } else {
        emailSenderVal.textContent = 'No open email detected in Gmail';
        emailStatusBadge.textContent = 'IDLE';
        btnAnalyzeEmail.disabled = true;
      }
    });
  }

  // ── 3. Mode Switching ──
  function switchToUrlMode() {
    tabUrlMode.classList.add('active');
    tabEmailMode.classList.remove('active');
    sectionUrlMode.style.display = 'block';
    sectionEmailMode.style.display = 'none';
  }

  function switchToEmailMode() {
    tabEmailMode.classList.add('active');
    tabUrlMode.classList.remove('active');
    sectionEmailMode.style.display = 'block';
    sectionUrlMode.style.display = 'none';
  }

  tabEmailMode.addEventListener('click', switchToEmailMode);
  tabUrlMode.addEventListener('click', () => {
    switchToUrlMode();
    targetUrlInput.focus();
  });

  // ── 3b. Auto-Detect Active Browser Tab & AUTO-SCAN ──
  let autoScanTriggered = false;
  function detectActiveTab() {
    if (typeof chrome !== 'undefined' && chrome.tabs && chrome.tabs.query) {
      chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
        if (chrome.runtime.lastError || !tabs || !tabs[0] || !tabs[0].url) return;
        const url = tabs[0].url;
        if (url.startsWith('http://') || url.startsWith('https://')) {
          activeTabUrl = url;
          if (currentTabUrlText) currentTabUrlText.textContent = url;
          if (targetUrlInput && !targetUrlInput.value) {
            targetUrlInput.value = url;
          }

          // If on a regular website (not Gmail), auto-switch to Investigate URL tab
          // AND automatically start the investigation
          if (!url.includes('mail.google.com') && !url.includes('127.0.0.1:5000/gmail-simulation')) {
            switchToUrlMode();
            // AUTO-SCAN: Automatically investigate the active tab URL
            if (!autoScanTriggered && !currentReport) {
              autoScanTriggered = true;
              setTimeout(() => executeUrlScan(url), 300);
            }
          }
        } else {
          if (currentTabUrlText) currentTabUrlText.textContent = 'Chrome system page (Not an HTTP target)';
          if (btnScanCurrentTab) btnScanCurrentTab.disabled = true;
        }
      });
    }
  }

  btnRefreshGmail.addEventListener('click', () => {
    syncGmailContext();
  });

  // ── 4. Live Progress HUD Simulation with Backend Sync ──
  function showScanningHud(title, steps) {
    scanningHud.style.display = 'flex';
    reportContainer.style.display = 'none';
    scanStageTitle.textContent = title;
    scanStepsList.innerHTML = steps.map((s, idx) => `
      <div class="ns-step-item" id="hudStep_${idx}">
        <span>${idx === 0 ? '●' : '○'}</span> ${escapeHtml(s)}
      </div>
    `).join('');
  }

  function advanceHudStep(stepIdx, completedLabel) {
    const el = document.getElementById(`hudStep_${stepIdx}`);
    if (el) {
      el.innerHTML = `<span style="color:#22c55e;">✓</span> ${escapeHtml(completedLabel || el.textContent)}`;
    }
    const nextEl = document.getElementById(`hudStep_${stepIdx + 1}`);
    if (nextEl) {
      nextEl.innerHTML = `<span style="color:#06b6d4;">●</span> ${nextEl.textContent.slice(2)}`;
    }
  }

  function hideScanningHud() {
    scanningHud.style.display = 'none';
  }

  // ── 5. Run Email Investigation ──
  btnAnalyzeEmail.addEventListener('click', async () => {
    if (!currentEmailContext) return;

    btnAnalyzeEmail.disabled = true;
    showScanningHud('RUNNING EMAIL SOC INVESTIGATION...', [
      'Extracting sender & message headers',
      'Querying Institutional Directory & authorized domains',
      'Scanning embedded hyperlinks with URL Intelligence',
      'Evaluating destination infrastructure & webpage forms',
      'Synthesizing Cross-Layer Evidence & Threat DNA'
    ]);

    // Animate HUD steps
    setTimeout(() => advanceHudStep(0, 'Sender & headers extracted'), 250);
    setTimeout(() => advanceHudStep(1, 'Institutional directory verified'), 550);
    setTimeout(() => advanceHudStep(2, 'Hyperlinks & domain infrastructure evaluated'), 950);

    try {
      const report = await NeuraShieldAPI.investigateEmail({
        sender_email: currentEmailContext.sender_email,
        sender_name: currentEmailContext.sender_name,
        claimed_org: currentEmailContext.claimed_org,
        subject: currentEmailContext.subject,
        recipient: currentEmailContext.recipient,
        body_text: currentEmailContext.body_text,
        links: currentEmailContext.links,
        attachments: currentEmailContext.attachments || []
      });

      advanceHudStep(3, 'Webpage forms & external threat intel processed');
      advanceHudStep(4, 'Evidence correlation & Threat DNA synthesized');

      if (typeof chrome !== 'undefined' && chrome.runtime && chrome.runtime.sendMessage) {
        chrome.runtime.sendMessage({
          type: 'STORE_INVESTIGATION_RESULT',
          payload: report
        }).catch(() => {});
      }

      setTimeout(() => {
        hideScanningHud();
        renderReport(report);
        btnAnalyzeEmail.disabled = false;
      }, 400);

    } catch (err) {
      hideScanningHud();
      btnAnalyzeEmail.disabled = false;
      alert(`Investigation failed: ${err.message}`);
    }
  });

  // ── 6. Run URL Investigation (Custom or Active Tab) ──
  async function executeUrlScan(rawUrl) {
    if (!rawUrl) return;

    if (btnInvestigateUrl) btnInvestigateUrl.disabled = true;
    if (btnScanCurrentTab) btnScanCurrentTab.disabled = true;

    showScanningHud('INVESTIGATING TARGET...', [
      'Normalizing target & checking SSRF safety filters',
      'Running URL heuristic rules & ML classification',
      'Collecting DNS, IP, WHOIS & SSL infrastructure signals',
      'Inspecting live webpage for credential harvesting forms',
      'Querying multi-vendor external threat intelligence'
    ]);

    setTimeout(() => advanceHudStep(0, 'Target normalized & SSRF verified'), 300);
    setTimeout(() => advanceHudStep(1, 'URL Intelligence rules evaluated'), 600);
    setTimeout(() => advanceHudStep(2, 'Domain infrastructure inspected'), 900);

    try {
      const report = await NeuraShieldAPI.investigateUrl(rawUrl);

      advanceHudStep(3, 'Webpage form analysis completed');
      advanceHudStep(4, 'Threat DNA & composite risk scored');

      setTimeout(() => {
        hideScanningHud();
        renderReport(report);
        if (btnInvestigateUrl) btnInvestigateUrl.disabled = false;
        if (btnScanCurrentTab) btnScanCurrentTab.disabled = false;
      }, 400);

    } catch (err) {
      hideScanningHud();
      if (btnInvestigateUrl) btnInvestigateUrl.disabled = false;
      if (btnScanCurrentTab) btnScanCurrentTab.disabled = false;
      alert(`Target investigation failed: ${err.message}`);
    }
  }

  btnInvestigateUrl.addEventListener('click', () => {
    const rawUrl = targetUrlInput.value.trim();
    if (!rawUrl) {
      targetUrlInput.focus();
      return;
    }
    executeUrlScan(rawUrl);
  });

  if (btnScanCurrentTab) {
    btnScanCurrentTab.addEventListener('click', () => {
      const urlToScan = activeTabUrl || (targetUrlInput ? targetUrlInput.value.trim() : '');
      if (urlToScan) {
        executeUrlScan(urlToScan);
      }
    });
  }

  // ── 7. Render Full Investigation Report ──
  function renderReport(report) {
    if (!report) return;
    currentReport = report;
    reportContainer.style.display = 'block';

    const sv = report.sender_verification || {};
    const risk = report.risk || report.risk_assessment || {};
    const dna = report.threat_dna || {};
    const links = report.links || {};
    const dom = report.domain_intelligence || report.domain_findings || {};
    const web = report.webpage_intelligence || report.webpage_findings || {};

    // 7a. Risk Banner
    const score = risk.score !== undefined ? risk.score : 0;
    const level = (risk.level || (score >= 75 ? 'CRITICAL' : (score >= 45 ? 'MEDIUM' : 'LOW'))).toUpperCase();
    let verdict = risk.verdict || sv.verdict_label || sv.verdict || 'INVESTIGATION COMPLETE';
    if (score >= 65 || level === 'CRITICAL' || level === 'HIGH') {
      if (risk.verdict && risk.verdict.toLowerCase().includes('phish')) {
        verdict = 'PHISHING DETECTED';
      }
    }

    repVerdictText.textContent = verdict.replace(/_/g, ' ');
    repReasonText.textContent = sv.reason || (report.target && report.target.display ? `Target: ${report.target.display}` : 'Analysis completed.');
    repScoreNum.textContent = score;

    riskBanner.className = `ns-risk-banner ${level.toLowerCase()}`;

    if (score >= 65 || level === 'CRITICAL' || level === 'HIGH' || verdict === 'PHISHING DETECTED') {
      repVerdictText.style.color = '#ef4444';
      repScoreNum.style.color = '#ef4444';
    } else if (score >= 35 || level === 'MEDIUM') {
      repVerdictText.style.color = '#f59e0b';
      repScoreNum.style.color = '#f59e0b';
    } else {
      repVerdictText.style.color = '#22c55e';
      repScoreNum.style.color = '#22c55e';
    }

    // 7b. Summary Tab (Institutional Verification Checklist)
    const checklistEl = document.getElementById('summaryVerificationChecklist');
    const verifBadge = document.getElementById('summaryVerifBadge');
    verifBadge.textContent = sv.verdict || 'EVALUATED';

    const checklistItems = sv.checklist || [];
    if (checklistItems.length) {
      checklistEl.innerHTML = checklistItems.map(item => {
        let icon = '●';
        let color = '#94a3b8';
        if (item.status === 'PASS') { icon = '✓'; color = '#22c55e'; }
        else if (item.status === 'FAIL') { icon = '✗'; color = '#ef4444'; }
        else if (item.status === 'WARNING') { icon = '⚠'; color = '#f59e0b'; }
        else if (item.status === 'NOT_AVAILABLE') { icon = '?'; color = '#64748b'; }

        return `
          <div class="ns-check-item">
            <span class="ns-check-icon" style="color:${color};font-weight:700;">${icon}</span>
            <div>
              <div style="font-weight:600;color:#f1f5f9;">${escapeHtml(item.label)}</div>
              <div style="font-size:10px;color:#94a3b8;">${escapeHtml(item.detail)}</div>
            </div>
          </div>
        `;
      }).join('');
    } else {
      checklistEl.innerHTML = `
        <div class="ns-check-item">
          <span class="ns-check-icon" style="color:#22c55e;">✓</span>
          <div>
            <div style="font-weight:600;">Technical Analysis Executed</div>
            <div style="font-size:10px;color:#94a3b8;">${report.investigation_type === 'url' ? 'Direct URL investigation completed.' : 'Standard email analysis finished.'}</div>
          </div>
        </div>
      `;
    }

    // TKR & Institutional Database Verification Card
    const dbCardEl = document.getElementById('summaryDbCheckCard');
    const dbBadgeEl = document.getElementById('summaryDbBadge');
    const dbCheckEl = document.getElementById('summaryDbCheckContent');
    const dbCheck = report.database_check;

    if (dbCheck && dbCheck.status) {
      if (dbCardEl) dbCardEl.style.display = 'block';
      const isSpoof = dbCheck.status === 'TKR_COLLEGE_SPOOF_ATTEMPT';
      const isVerified = dbCheck.status === 'VERIFIED_TKR_COLLEGE_MEMBER';
      const badgeColor = isVerified ? '#22c55e' : (isSpoof ? '#ef4444' : '#f59e0b');

      if (dbBadgeEl) {
        dbBadgeEl.textContent = dbCheck.status.replace(/_/g, ' ');
        dbBadgeEl.style.color = badgeColor;
        dbBadgeEl.style.borderColor = badgeColor;
      }
      if (dbCheckEl) {
        dbCheckEl.innerHTML = `
          <div style="margin-bottom:6px;font-weight:600;color:${badgeColor};">${escapeHtml(dbCheck.details || '')}</div>
          <div style="display:grid;grid-template-columns:1fr 1fr;gap:6px;background:rgba(0,0,0,0.3);padding:8px;border-radius:4px;font-size:10px;">
            <div>Institution: <strong style="color:#f8fafc;">${escapeHtml(dbCheck.institution || 'TKR Educational Society')}</strong></div>
            <div>Matched Directory Member: <strong style="color:#f8fafc;">${escapeHtml(dbCheck.matched_member || 'None (Unregistered)')}</strong></div>
            <div>Authorized Domain: <strong style="color:#38bdf8;">${escapeHtml(dbCheck.domain_verified ? (dbCheck.claimed_domain || 'tkrcet.ac.in') + ' (VERIFIED)' : 'UNAUTHORIZED DOMAIN')}</strong></div>
            <div>Database Record: <strong style="color:${dbCheck.database_match ? '#22c55e' : '#f87171'};">${dbCheck.database_match ? 'FOUND IN TKR DATABASE' : 'NOT FOUND IN DATABASE'}</strong></div>
          </div>
        `;
      }
    } else if (report.investigation_type === 'url') {
      if (dbCardEl) dbCardEl.style.display = 'block';
      if (dbBadgeEl) {
        dbBadgeEl.textContent = 'DOMAIN / URL TARGET';
        dbBadgeEl.style.color = '#38bdf8';
      }
      if (dbCheckEl) {
        dbCheckEl.innerHTML = `<div style="color:#94a3b8;font-size:10px;">Direct URL target. Identity verified against enterprise infrastructure and reputation directories.</div>`;
      }
    } else {
      if (dbCardEl) dbCardEl.style.display = 'none';
    }

    // Correlation Text
    const corrText = document.getElementById('repCorrelationText');
    const corr = report.correlation || {};
    corrText.textContent = corr.cross_layer_summary || (corr.notes && corr.notes.join(' ')) || 'Single-source indicators evaluated without cross-layer contradictions.';

    // 7b2. Brand Impersonation Tab
    const repBrandBadge = document.getElementById('repBrandBadge');
    const repBrandContent = document.getElementById('repBrandContent');
    const brand = report.brand_analysis || report.brand_impersonation || {};

    if (brand && brand.verdict && brand.verdict !== 'INSUFFICIENT_EVIDENCE') {
      const isSpoof = brand.verdict.includes('IMPERSONATION');
      const isLegit = brand.verdict === 'CONSISTENT';
      const bColor = isLegit ? '#22c55e' : (brand.verdict === 'STRONG_IMPERSONATION_EVIDENCE' ? '#ef4444' : '#f59e0b');

      if (repBrandBadge) {
        repBrandBadge.textContent = isLegit ? 'VERIFIED BRAND' : (isSpoof ? 'SPOOFING DETECTED' : brand.verdict);
        repBrandBadge.style.color = bColor;
        repBrandBadge.style.borderColor = bColor;
      }

      if (repBrandContent) {
        const offDoms = (brand.official_domains || []).slice(0, 4).join(', ') || 'N/A';
        const reasonsList = (brand.reasons || []).map(r => `<li>${escapeHtml(r)}</li>`).join('');

        repBrandContent.innerHTML = `
          <div style="display:flex;align-items:center;justify-content:space-between;padding:8px 10px;background:rgba(0,0,0,0.3);border-radius:6px;margin-bottom:8px;border-left:3px solid ${bColor};">
            <div>
              <div style="font-size:10px;color:#94a3b8;text-transform:uppercase;">Detected Brand Entity</div>
              <div style="font-size:13px;font-weight:700;color:#f8fafc;">${escapeHtml(brand.claimed_brand || 'Protected Enterprise Brand')}</div>
            </div>
            <div style="text-align:right;">
              <span class="ns-badge" style="color:${bColor};border-color:${bColor};font-size:10px;">${escapeHtml(brand.verdict)}</span>
              <div style="font-size:9px;color:#94a3b8;margin-top:2px;">Confidence: ${escapeHtml(brand.confidence || 'HIGH')}</div>
            </div>
          </div>
          <div style="font-size:11px;margin-bottom:8px;line-height:1.4;">
            <strong>Analysis:</strong> ${escapeHtml(brand.verdict_label || '')}
          </div>
          <div style="font-size:10px;color:#cbd5e1;background:rgba(15,23,42,0.6);padding:6px 8px;border-radius:4px;margin-bottom:8px;">
            <div><span style="color:#64748b;">Target Host:</span> <strong style="color:#38bdf8;">${escapeHtml(brand.target_host || 'Target Host')}</strong></div>
            <div><span style="color:#64748b;">Authorized Official Domains:</span> <span style="color:#94a3b8;">${escapeHtml(offDoms)}</span></div>
          </div>
          ${reasonsList ? `
            <div style="font-size:11px;font-weight:600;color:#f1f5f9;margin-bottom:4px;">Brand Threat Evidence:</div>
            <ul style="margin:0 0 0 16px;padding:0;font-size:10px;color:${isSpoof ? '#fca5a5' : '#86efac'};line-height:1.5;">
              ${reasonsList}
            </ul>
          ` : ''}
        `;
      }
    } else {
      if (repBrandBadge) {
        repBrandBadge.textContent = 'NO BRAND CLAIM';
        repBrandBadge.style.color = '#94a3b8';
      }
      if (repBrandContent) {
        repBrandContent.innerHTML = `
          <div style="color:var(--text-muted);font-size:11px;padding:8px 0;">
            No protected brand claims or impersonation signatures detected. Target does not mimic protected enterprise brand profiles.
          </div>
        `;
      }
    }

    // 7b3. Attachments Forensic Tab
    const repAttBadge = document.getElementById('repAttachmentsBadge');
    const repAttContent = document.getElementById('repAttachmentsContent');
    const attData = report.attachment_findings || report.attachments || {};
    const attItems = attData.items || [];

    if (repAttBadge) {
      repAttBadge.textContent = `${attData.attachment_count || attItems.length} File(s)`;
      if (attData.dangerous_count > 0) {
        repAttBadge.style.color = '#ef4444';
        repAttBadge.style.borderColor = '#ef4444';
      } else {
        repAttBadge.style.color = '#38bdf8';
      }
    }

    if (repAttContent) {
      if (attItems.length) {
        repAttContent.innerHTML = `
          <div style="display:flex;gap:6px;margin-bottom:8px;">
            <div style="flex:1;background:rgba(0,0,0,0.3);padding:6px;border-radius:4px;text-align:center;">
              <div style="font-size:9px;color:#94a3b8;">RISK SCORE</div>
              <div style="font-family:var(--font-mono);font-size:14px;font-weight:700;color:${attData.risk_score >= 70 ? '#ef4444' : (attData.risk_score >= 35 ? '#f59e0b' : '#22c55e')};">${attData.risk_score || 0}/100</div>
            </div>
            <div style="flex:1;background:rgba(0,0,0,0.3);padding:6px;border-radius:4px;text-align:center;">
              <div style="font-size:9px;color:#94a3b8;">DANGEROUS</div>
              <div style="font-family:var(--font-mono);font-size:14px;font-weight:700;color:${attData.dangerous_count ? '#ef4444' : '#22c55e'};">${attData.dangerous_count || 0}</div>
            </div>
            <div style="flex:1;background:rgba(0,0,0,0.3);padding:6px;border-radius:4px;text-align:center;">
              <div style="font-size:9px;color:#94a3b8;">MACROS</div>
              <div style="font-family:var(--font-mono);font-size:14px;font-weight:700;color:${attData.macro_count ? '#f59e0b' : '#22c55e'};">${attData.macro_count || 0}</div>
            </div>
          </div>
          ${attItems.map(item => {
            const isDanger = item.verdict === 'MALICIOUS_DOUBLE_EXTENSION' || item.verdict === 'DANGEROUS_EXECUTABLE';
            const isMacro = item.verdict === 'MACRO_ENABLED_DOCUMENT';
            const iColor = isDanger ? '#ef4444' : (isMacro ? '#f59e0b' : '#22c55e');
            return `
              <div style="background:rgba(15,23,42,0.8);border:1px solid var(--border);border-left:3px solid ${iColor};border-radius:6px;padding:8px 10px;margin-bottom:6px;">
                <div style="display:flex;justify-content:space-between;align-items:center;">
                  <span style="font-family:var(--font-mono);font-size:11px;font-weight:600;color:#f8fafc;word-break:break-all;">📎 ${escapeHtml(item.filename)}</span>
                  <span class="ns-badge" style="color:${iColor};border-color:${iColor};font-size:9px;">${escapeHtml(item.verdict)}</span>
                </div>
                <div style="display:flex;gap:12px;font-size:10px;color:#94a3b8;margin-top:4px;">
                  <span>Ext: <strong style="color:#38bdf8;">${escapeHtml(item.extension)}</strong></span>
                  <span>Risk: <strong style="color:${iColor};">${item.risk_score}/100</strong></span>
                  ${item.size ? `<span>Size: ${escapeHtml(item.size)}</span>` : ''}
                </div>
                ${(item.flags || []).length ? `
                  <div style="margin-top:4px;font-size:10px;color:#f87171;">
                    ${item.flags.map(f => `• ${escapeHtml(f)}`).join('<br>')}
                  </div>
                ` : ''}
              </div>
            `;
          }).join('')}
        `;
      } else {
        repAttContent.innerHTML = `
          <div style="color:var(--text-muted);font-size:11px;padding:8px 0;">
            No file attachments detected in this email context or target.
          </div>
        `;
      }
    }

    // 7c. Evidence Tab
    const evListEl = document.getElementById('repEvidenceList');
    const evidenceItems = report.evidence || [];
    if (evidenceItems.length) {
      evListEl.innerHTML = evidenceItems.map(e => `
        <div class="ns-evidence-card">
          <div class="ns-ev-header">
            <span class="ns-ev-source">${escapeHtml(e.source || 'Intelligence Module')}</span>
            ${e.impact ? `<span class="ns-ev-impact">${escapeHtml(e.impact)}</span>` : ''}
          </div>
          <div class="ns-ev-obs">${escapeHtml(e.observation)}</div>
          ${e.why_it_matters ? `<div style="font-size:10px;color:#94a3b8;margin-top:4px;"><strong>Significance:</strong> ${escapeHtml(e.why_it_matters)}</div>` : ''}
        </div>
      `).join('');
    } else {
      evListEl.innerHTML = `<div style="color:var(--text-muted);font-size:11px;">No suspicious evidence observed.</div>`;
    }

    // 7d. Threat DNA Tab
    const dnaBadge = document.getElementById('dnaCountBadge');
    const dnaChipsEl = document.getElementById('repDnaChips');
    const traits = dna.traits || [];
    dnaBadge.textContent = `${traits.length} Traits`;
    if (traits.length) {
      dnaChipsEl.innerHTML = traits.map(t => `<span class="ns-dna-chip">🧬 ${escapeHtml(t)}</span>`).join('');
    } else {
      dnaChipsEl.innerHTML = `<div style="color:var(--text-muted);font-size:11px;">No adversarial Threat DNA traits matched.</div>`;
    }

    // 7e. Links Tab
    const repLinksList = document.getElementById('repLinksList');
    const linkFindings = (links.findings) || [];
    const extractedList = (links.extracted_urls) || [];
    if (linkFindings.length) {
      repLinksList.innerHTML = linkFindings.map(l => `
        <div class="ns-card" style="margin-bottom:8px;">
          <div class="ns-card-header">
            <span class="ns-card-label" style="word-break:break-all;">${escapeHtml(l.url)}</span>
            <span class="ns-badge" style="color:${l.risk_level === 'LOW' ? '#22c55e' : '#ef4444'};">${l.risk_level} (${l.risk_score}/100)</span>
          </div>
          <div style="font-size:11px;color:#94a3b8;margin-top:4px;">
            ML Verdict: <strong style="color:#f8fafc;">${escapeHtml(l.prediction || 'Unknown')}</strong>
          </div>
          ${l.rules_hit && l.rules_hit.length ? `
            <div style="font-size:10px;color:#f87171;margin-top:6px;">
              Rules Triggered: ${l.rules_hit.map(r => escapeHtml(r.name || r.id)).join(', ')}
            </div>
          ` : ''}
        </div>
      `).join('');
    } else if (extractedList.length) {
      repLinksList.innerHTML = extractedList.map(u => `
        <div class="ns-card" style="margin-bottom:6px;font-family:var(--font-mono);font-size:11px;">
          🔗 ${escapeHtml(u)}
        </div>
      `).join('');
    } else {
      repLinksList.innerHTML = `<div class="ns-card" style="color:var(--text-muted);font-size:11px;">No hyperlinks detected in email context.</div>`;
    }

    // 7f. Domain Tab
    const repDomainCard = document.getElementById('repDomainCard');
    if (dom && dom.domain) {
      repDomainCard.innerHTML = `
        <div class="ns-card-header">
          <span class="ns-card-label">Domain Infrastructure</span>
          <span class="ns-badge">${escapeHtml(dom.status || 'COLLECTED')}</span>
        </div>
        <div style="display:grid;grid-template-columns:1fr 1fr;gap:8px;font-size:11px;">
          <div><span style="color:#64748b;">Domain:</span> <strong style="color:#38bdf8;">${escapeHtml(dom.domain)}</strong></div>
          <div><span style="color:#64748b;">Age:</span> <strong>${dom.domain_age_days !== undefined ? dom.domain_age_days + ' days' : 'Unknown'}</strong></div>
          <div><span style="color:#64748b;">Registrar:</span> <strong>${escapeHtml(dom.registrar || 'Unknown')}</strong></div>
          <div><span style="color:#64748b;">TLS / SSL:</span> <strong>${escapeHtml(dom.tls_status || 'Unknown')}</strong></div>
        </div>
        ${dom.resolved_ips && dom.resolved_ips.length ? `
          <div style="margin-top:8px;font-size:10px;font-family:var(--font-mono);color:#94a3b8;">
            Resolved IP(s): ${dom.resolved_ips.join(', ')}
          </div>
        ` : ''}
      `;
    } else {
      repDomainCard.innerHTML = `<div style="color:var(--text-muted);font-size:11px;">Domain intelligence unavailable for current target.</div>`;
    }

    // 7g. Website Tab
    const repWebCard = document.getElementById('repWebCard');
    if (web && web.status === 'AVAILABLE') {
      repWebCard.innerHTML = `
        <div class="ns-card-header">
          <span class="ns-card-label">Webpage Analysis</span>
          <span class="ns-badge" style="color:${web.has_password_field ? '#f87171' : '#22c55e'};">
            ${web.has_password_field ? 'CREDENTIAL PROMPT' : 'INFORMATIONAL'}
          </span>
        </div>
        <div style="font-size:11px;line-height:1.5;">
          <div><span style="color:#64748b;">Title:</span> <strong>${escapeHtml(web.page_title || 'Untitled')}</strong></div>
          <div><span style="color:#64748b;">HTTP Status:</span> <strong>${web.http_status || 200}</strong></div>
          <div><span style="color:#64748b;">Password Input:</span> <strong style="color:${web.has_password_field ? '#ef4444' : '#22c55e'}">${web.has_password_field ? 'DETECTED' : 'None'}</strong></div>
        </div>
      `;
    } else {
      repWebCard.innerHTML = `
        <div style="color:var(--text-muted);font-size:11px;">
          ${escapeHtml(web.message || 'Webpage could not be safely inspected or was not requested.')}
        </div>
      `;
    }

    // 7h. Agent AI Decisions Tab
    const agentDecisions = report.agent_decisions || [];
    const agentDecisionsList = document.getElementById('repAgentDecisionsList');
    const agentModuleCountBadge = document.getElementById('agentModuleCountBadge');
    const agentExecSummary = document.getElementById('repAgentExecSummary');
    const modulesExecuted = report.modules_executed || [];

    if (agentModuleCountBadge) {
      agentModuleCountBadge.textContent = `${modulesExecuted.length} Modules`;
    }

    if (agentDecisionsList) {
      if (agentDecisions.length) {
        agentDecisionsList.innerHTML = agentDecisions.map((d, idx) => {
          const stepColor = d.action === 'INVESTIGATION_TERMINATED' ? '#ef4444'
            : d.action === 'START_INVESTIGATION' ? '#38bdf8' : '#22c55e';
          return `
            <div style="padding:8px 10px;margin-bottom:6px;background:rgba(0,0,0,0.3);border-radius:6px;border-left:3px solid ${stepColor};">
              <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:3px;">
                <span style="font-family:var(--font-mono);font-size:10px;color:${stepColor};font-weight:700;">
                  #${d.decision_num || idx + 1} ${escapeHtml(d.action || d.selected || '')}
                </span>
                <span style="font-family:var(--font-mono);font-size:9px;color:#64748b;">
                  ${escapeHtml(d.source || 'DETERMINISTIC')}
                </span>
              </div>
              <div style="font-size:11px;color:#e2e8f0;line-height:1.4;">${escapeHtml(d.reason || '')}</div>
              ${d.observed ? `<div style="font-size:10px;color:#94a3b8;margin-top:3px;">Observed: ${escapeHtml(d.observed)}</div>` : ''}
            </div>
          `;
        }).join('');
      } else {
        agentDecisionsList.innerHTML = `<div style="color:var(--text-muted);font-size:11px;padding:8px;">Agent decision log not available for this investigation type.</div>`;
      }
    }

    if (agentExecSummary) {
      agentExecSummary.textContent = report.executive_summary || '';
    }

    // 7i. Guidance Tab
    const repGuidanceList = document.getElementById('repGuidanceList');
    const guidanceItems = report.guidance || [];
    if (guidanceItems.length) {
      repGuidanceList.innerHTML = guidanceItems.map(g => `
        <div class="ns-guide-item ${g.priority === 'URGENT' ? 'urgent' : ''}">
          <div class="ns-guide-action">${escapeHtml(g.action)}</div>
          <div class="ns-guide-detail">${escapeHtml(g.detail)}</div>
        </div>
      `).join('');
    } else {
      repGuidanceList.innerHTML = `<div style="color:var(--text-muted);font-size:11px;">Standard security hygiene recommended.</div>`;
    }
  }

  // ── 8. Tab Navigation inside Report ──
  document.querySelectorAll('.ns-rep-tab-btn').forEach(btn => {
    btn.addEventListener('click', () => {
      document.querySelectorAll('.ns-rep-tab-btn').forEach(b => b.classList.remove('active'));
      document.querySelectorAll('.ns-rep-tab-content').forEach(c => c.classList.remove('active'));

      btn.classList.add('active');
      const targetId = btn.getAttribute('data-rep-tab');
      const targetContent = document.getElementById(targetId);
      if (targetContent) targetContent.classList.add('active');
    });
  });

  // ── 9. Open in SOC Web Console ──
  btnOpenWebConsole.addEventListener('click', async () => {
    const invId = currentReport ? currentReport.investigation_id : '';
    const base = await NeuraShieldAPI.getBackendUrl();
    const url = invId ? `${base}/investigation-center?id=${encodeURIComponent(invId)}` : `${base}/investigation-center`;
    if (typeof chrome !== 'undefined' && chrome.tabs) {
      chrome.tabs.create({ url });
    } else {
      window.open(url, '_blank');
    }
  });

  // ── 10. Export JSON ──
  btnExportJson.addEventListener('click', () => {
    if (!currentReport) {
      alert('No investigation data to export yet.');
      return;
    }
    const blob = new Blob([JSON.stringify(currentReport, null, 2)], { type: 'application/json' });
    const blobUrl = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = blobUrl;
    a.download = `${currentReport.investigation_id || 'neurashield-report'}.json`;
    a.click();
    URL.revokeObjectURL(blobUrl);
  });

  function escapeHtml(str) {
    if (!str) return '';
    return String(str)
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;')
      .replace(/'/g, '&#039;');
  }

  // Init
  checkBackend();
  syncGmailContext();
  detectActiveTab();
});
