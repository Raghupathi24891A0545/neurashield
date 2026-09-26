/**
 * NeuraShield Chrome Extension — Gmail Content Script
 * Detects opened emails in Gmail, extracts sender/links/context,
 * and renders the NeuraShield Cybersecurity Investigation Console.
 */

(() => {
  let lastProcessedEmailKey = null;
  let isAnalyzing = false;

  console.log('[NeuraShield] Gmail Content Script initialized.');

  // ── Helper: Safe DOM Selector Query ──
  function qs(selector, context = document) {
    try {
      return context.querySelector(selector);
    } catch (e) {
      return null;
    }
  }

  function qsa(selector, context = document) {
    try {
      return Array.from(context.querySelectorAll(selector));
    } catch (e) {
      return [];
    }
  }

  // ── Detect Claimed Organization in Client Context ──
  function detectClientClaimedOrg(senderName, subject, bodyText) {
    const combined = `${senderName || ''} ${subject || ''} ${(bodyText || '').slice(0, 1000)}`.toLowerCase();
    
    // Known institutional keywords & patterns
    if (combined.includes('tkr college') || combined.includes('tkrcet') || combined.includes('tkr educational')) {
      return 'TKR College';
    }
    if (combined.includes('administration office') || combined.includes('exam cell') || combined.includes('academic cell')) {
      if (combined.includes('college') || combined.includes('university') || combined.includes('institution')) {
        return 'Educational Institution';
      }
    }
    return null;
  }

  // ── Extract Opened Email Data from Gmail DOM ──
  function extractGmailContext() {
    // 1. Locate message containers
    const messageContainers = qsa('[data-message-id], .adn.ads, div[role="listitem"]');
    if (!messageContainers.length) {
      // Alternate fallback: check for body container
      const altBody = qs('.a3s.aiL');
      if (!altBody) return null;
    }

    // Find the latest / currently open email container
    let activeContainer = messageContainers[messageContainers.length - 1] || document.body;

    // 2. Sender Display Name and Email Address
    const senderEl = qs('span.gD', activeContainer) || qs('[email]', activeContainer) || qs('span.gD') || qs('[data-hovercard-id]');
    let senderEmail = null;
    let senderName = null;

    if (senderEl) {
      senderEmail = senderEl.getAttribute('email') || senderEl.getAttribute('data-hovercard-id') || null;
      senderName = senderEl.getAttribute('name') || senderEl.textContent.trim() || null;
      if (!senderEmail && senderName && senderName.includes('@')) {
        const m = senderName.match(/[\w\.-]+@[\w\.-]+\.\w+/);
        if (m) senderEmail = m[0];
      }
    }

    if (!senderEmail) {
      // Try searching for email string in header area
      const headerArea = qs('.gF.gK, .gE.iv.gt', activeContainer) || qs('.gF.gK, .gE.iv.gt');
      if (headerArea) {
        const m = headerArea.textContent.match(/[\w\.-]+@[\w\.-]+\.\w+/);
        if (m) senderEmail = m[0];
      }
    }

    if (!senderEmail) return null; // No opened email found

    senderEmail = senderEmail.trim().toLowerCase();
    const senderDomain = senderEmail.split('@')[1] || 'NOT_AVAILABLE';

    // 3. Subject
    const subjectEl = qs('h2.hP') || qs('h2[data-thread-perm-id]') || qs('.ha h2');
    const subject = subjectEl ? subjectEl.textContent.trim() : 'NOT_AVAILABLE';

    // 4. Recipient
    const recipientEl = qs('span.g2', activeContainer) || qs('[data-hovercard-id]', qs('.gE.iv.gt', activeContainer));
    const recipient = recipientEl ? (recipientEl.getAttribute('email') || recipientEl.textContent.trim()) : 'NOT_AVAILABLE';

    // 5. Body Text
    const bodyEl = qs('.a3s.aiL', activeContainer) || qs('.a3s.aiL');
    const bodyText = bodyEl ? bodyEl.textContent.trim().slice(0, 3000) : '';

    // 6. Hyperlinks
    const links = [];
    if (bodyEl) {
      const anchorEls = qsa('a[href]', bodyEl);
      for (const a of anchorEls) {
        let href = a.getAttribute('href');
        if (href) {
          href = href.trim();
          // Unwrap Gmail / Google redirect proxy (e.g. https://www.google.com/url?q=...)
          if (href.includes('google.com/url?') || (href.includes('google.co') && href.includes('/url?'))) {
            try {
              const urlObj = new URL(href);
              const actual = urlObj.searchParams.get('q') || urlObj.searchParams.get('url');
              if (actual) href = decodeURIComponent(actual).trim();
            } catch(e) {}
          }
          // Default scheme-less or protocol-relative links to https://
          if (href.startsWith('//')) {
            href = 'https:' + href;
          } else if (!href.startsWith('http://') && !href.startsWith('https://')) {
            if (!href.startsWith('mailto:') && !href.startsWith('tel:') && !href.startsWith('#') && !href.startsWith('javascript:')) {
              href = 'https://' + href;
            }
          }
          // Upgrade http:// to https:// for known modern domains enforcing HTTPS
          if (href.startsWith('http://')) {
            try {
              const host = new URL(href).hostname.toLowerCase();
              if (host === 'gmail.com' || host === 'google.com' || host.endsWith('.google.com') || host.endsWith('tkrcet.ac.in') || host.endsWith('tkrec.ac.in')) {
                href = 'https://' + href.slice(7);
              }
            } catch(e) {}
          }
          if (href.startsWith('http') && !href.includes('mail.google.com') && !links.includes(href)) {
            links.push(href);
          }
        }
      }
    }

    // 6b. Extract Attachments from Gmail DOM
    const attachments = [];
    const attachEls = qsa('.aZo, .aQy, [role="listitem"] .aSH, span.aV3.hq, div.a3I, div[aria-label*="Attachment"], .attachment-item, .attachment-chip', activeContainer);
    for (const el of attachEls) {
      let rawName = el.getAttribute('download_url') || el.getAttribute('aria-label') || el.textContent.trim();
      if (rawName && rawName.length > 2) {
        if (rawName.includes(':')) {
          const parts = rawName.split(':');
          if (parts.length >= 2 && parts[1].includes('.')) rawName = parts[1];
        }
        const cleanName = rawName.split('\n')[0].replace(/Download/gi, '').trim();
        if (cleanName && cleanName.length > 2 && !attachments.some(a => a.name === cleanName)) {
          attachments.push({
            name: cleanName,
            size: el.getAttribute('data-size') || 'Attached file'
          });
        }
      }
    }

    // 7. Claimed Organization
    const claimedOrg = detectClientClaimedOrg(senderName, subject, bodyText);

    return {
      sender_email: senderEmail,
      sender_name: senderName || senderEmail.split('@')[0],
      sender_domain: senderDomain,
      claimed_org: claimedOrg,
      subject: subject,
      recipient: recipient,
      body_text: bodyText,
      links: links,
      attachments: attachments,
      extracted_at: new Date().toISOString()
    };
  }

  // ── Render NeuraShield Banner into Gmail Email View ──
  function renderNeuraShieldBanner(emailContext) {
    if (!emailContext) return;

    // Check if banner is already rendered for this specific sender & subject
    const emailKey = `${emailContext.sender_email}|${emailContext.subject}|${emailContext.links.length}`;
    if (lastProcessedEmailKey === emailKey && qs('#neurashield-gmail-banner')) {
      return;
    }

    // Remove existing banner if email changed
    const existing = qs('#neurashield-gmail-banner');
    if (existing) existing.remove();

    // Notify background script
    if (typeof chrome !== 'undefined' && chrome.runtime && chrome.runtime.sendMessage) {
      chrome.runtime.sendMessage({
        type: 'GMAIL_EMAIL_OPENED',
        payload: emailContext
      }).catch(() => {});
    }

    // Target injection position in Gmail
    // Prefer right above the email body `.a3s.aiL` or below email header
    const targetMount = qs('.a3s.aiL') || qs('.adn.ads') || qs('.ii.gt');
    if (!targetMount || !targetMount.parentElement) return;

    const banner = document.createElement('div');
    banner.id = 'neurashield-gmail-banner';

    banner.innerHTML = `
      <div class="ns-gmail-header">
        <div class="ns-gmail-brand">
          <svg class="ns-gmail-shield-icon" viewBox="0 0 100 100" fill="none" xmlns="http://www.w3.org/2000/svg">
            <path d="M50 5 L90 20 V50 C90 75 50 95 50 95 C50 95 10 75 10 50 V20 L50 5 Z" fill="rgba(6,182,212,0.15)" stroke="#06b6d4" stroke-width="6"/>
            <path d="M50 30 V70 M30 50 H70" stroke="#00f260" stroke-width="7"/>
          </svg>
          <span class="ns-gmail-title">NeuraShield</span>
          <span class="ns-gmail-subtitle">Email Intelligence</span>
        </div>
        <div class="ns-gmail-status-pill">
          <span class="ns-gmail-pulse"></span>
          <span>INVESTIGATION READY</span>
        </div>
      </div>

      <div class="ns-gmail-details-grid">
        <div>
          <div class="ns-gmail-label">Sender</div>
          <div class="ns-gmail-val">${escapeHtml(emailContext.sender_name || emailContext.sender_email)}</div>
          <div class="ns-gmail-val-mono" style="font-size:11px;">${escapeHtml(emailContext.sender_email)}</div>
        </div>
        <div>
          <div class="ns-gmail-label">Claimed Organization</div>
          <div class="ns-gmail-val" style="color:${emailContext.claimed_org ? '#38bdf8' : '#94a3b8'};">
            ${escapeHtml(emailContext.claimed_org || 'None Claimed')}
          </div>
        </div>
        <div>
          <div class="ns-gmail-label">Sending Domain</div>
          <div class="ns-gmail-val-mono">${escapeHtml(emailContext.sender_domain)}</div>
        </div>
        <div>
          <div class="ns-gmail-label">Embedded Links</div>
          <div class="ns-gmail-val" style="color:${emailContext.links.length > 0 ? '#fbbf24' : '#94a3b8'};">
            ${emailContext.links.length} Link(s) Detected
          </div>
        </div>
      </div>

      <div class="ns-gmail-actions">
        <button id="nsAnalyzeBtn" class="ns-gmail-btn">
          <span>⚡</span> ANALYZE WITH NEURASHIELD
        </button>
        ${emailContext.links.length > 0 ? `
          <button id="nsAnalyzeLinksBtn" class="ns-gmail-btn ns-gmail-btn-secondary">
            <span>🔗</span> ANALYZE ${emailContext.links.length} LINK(S)
          </button>
        ` : ''}
        <span style="font-family:ui-monospace,monospace;font-size:10px;color:#64748b;margin-left:auto;">
          Enterprise Identity Verification Engine
        </span>
      </div>

      <div id="nsResultContainer" class="ns-gmail-result-drawer" style="display:none;"></div>
    `;

    targetMount.parentElement.insertBefore(banner, targetMount);
    lastProcessedEmailKey = emailKey;

    // Attach Event Handlers
    const analyzeBtn = banner.querySelector('#nsAnalyzeBtn');
    if (analyzeBtn) {
      analyzeBtn.addEventListener('click', () => runEmailInvestigation(emailContext));
    }

    const analyzeLinksBtn = banner.querySelector('#nsAnalyzeLinksBtn');
    if (analyzeLinksBtn) {
      analyzeLinksBtn.addEventListener('click', () => runEmailInvestigation(emailContext, { focusLinks: true }));
    }

    // Auto-trigger investigation immediately without requiring manual click
    setTimeout(() => {
      runEmailInvestigation(emailContext);
    }, 150);
  }

  // ── Execute Real NeuraShield Investigation ──
  async function runEmailInvestigation(emailContext, options = {}) {
    if (isAnalyzing) return;
    isAnalyzing = true;

    const banner = qs('#neurashield-gmail-banner');
    const btn = qs('#nsAnalyzeBtn', banner);
    const resultBox = qs('#nsResultContainer', banner);

    if (btn) {
      btn.disabled = true;
      btn.innerHTML = `<span>⏳</span> INVESTIGATING...`;
    }

    if (resultBox) {
      resultBox.style.display = 'block';
      resultBox.innerHTML = `
        <div style="padding:14px;background:rgba(0,0,0,0.3);border-radius:6px;border:1px solid rgba(6,182,212,0.2);">
          <div style="display:flex;align-items:center;gap:10px;margin-bottom:12px;">
            <div class="ns-gmail-pulse"></div>
            <strong style="font-size:12px;color:#38bdf8;text-transform:uppercase;letter-spacing:0.05em;">NeuraShield SOC Investigation In Progress</strong>
          </div>
          <div style="font-family:ui-monospace,monospace;font-size:11px;color:#94a3b8;line-height:1.7;">
            <div>✓ Parsing email headers & claimed identity...</div>
            <div>✓ Querying institutional directory & authorized domains...</div>
            <div>✓ Extracting & evaluating embedded hyperlink signals...</div>
            <div style="color:#38bdf8;">● Correlating multi-layer threat evidence & synthesizing Threat DNA...</div>
          </div>
        </div>
      `;
    }

    try {
      const report = await NeuraShieldAPI.investigateEmail({
        sender_email: emailContext.sender_email,
        sender_name: emailContext.sender_name,
        claimed_org: emailContext.claimed_org,
        subject: emailContext.subject,
        recipient: emailContext.recipient,
        body_text: emailContext.body_text,
        links: emailContext.links
      });

      // Store in background
      if (typeof chrome !== 'undefined' && chrome.runtime && chrome.runtime.sendMessage) {
        chrome.runtime.sendMessage({
          type: 'STORE_INVESTIGATION_RESULT',
          payload: report
        }).catch(() => {});
      }

      displayInvestigationResult(report);

    } catch (err) {
      if (resultBox) {
        resultBox.innerHTML = `
          <div style="padding:14px;background:rgba(239,68,68,0.1);border:1px solid rgba(239,68,68,0.3);border-radius:6px;color:#f87171;font-size:12px;">
            <strong>Investigation Notice:</strong> ${escapeHtml(err.message || 'NeuraShield backend unavailable at http://127.0.0.1:5000.')}
          </div>
        `;
      }
    } finally {
      isAnalyzing = false;
      if (btn) {
        btn.disabled = false;
        btn.innerHTML = `<span>⚡</span> RE-ANALYZE WITH NEURASHIELD`;
      }
    }
  }

  // ── Render Investigation Findings into Banner Result Drawer ──
  function displayInvestigationResult(report) {
    const resultBox = qs('#nsResultContainer');
    if (!resultBox) return;

    if (report.backend_offline) {
      resultBox.innerHTML = `
        <div style="padding:14px;background:rgba(239,68,68,0.1);border:1px solid rgba(239,68,68,0.3);border-radius:6px;color:#f87171;font-size:12px;">
          <strong>Backend Offline:</strong> Could not connect to NeuraShield backend at http://127.0.0.1:5000. Please launch the backend server.
        </div>
      `;
      return;
    }

    const sv = report.sender_verification || {};
    const risk = report.risk || {};
    const dna = report.threat_dna || {};
    const links = report.links || {};

    let verdictBadge = 'ns-badge-unverified';
    if (sv.verdict === 'VERIFIED_INSTITUTIONAL_SENDER') verdictBadge = 'ns-badge-verified';
    else if (sv.verdict === 'POSSIBLE_ORGANIZATION_IMPERSONATION' || risk.level === 'HIGH' || risk.level === 'CRITICAL') verdictBadge = 'ns-badge-impersonation';

    resultBox.innerHTML = `
      <div style="background:rgba(0,0,0,0.35);border:1px solid rgba(255,255,255,0.08);border-radius:6px;padding:16px;">
        <!-- Header / Verdict Row -->
        <div style="display:flex;justify-content:space-between;align-items:flex-start;margin-bottom:14px;flex-wrap:wrap;gap:10px;">
          <div>
            <div style="font-family:ui-monospace,monospace;font-size:10px;text-transform:uppercase;color:#64748b;">Identity Verification Verdict</div>
            <div style="display:flex;align-items:center;gap:8px;margin-top:4px;">
              <span class="ns-gmail-status-pill ${verdictBadge}" style="font-size:11px;font-weight:700;">
                ${escapeHtml(sv.verdict_label || sv.verdict || 'UNKNOWN')}
              </span>
              <span style="font-family:ui-monospace,monospace;font-size:11px;color:#94a3b8;">
                Risk: <strong style="color:${risk.level === 'LOW' ? '#4ade80' : (risk.level === 'MEDIUM' ? '#fbbf24' : '#f87171')}">${risk.level} (${risk.score || 0}/100)</strong>
              </span>
            </div>
          </div>
          <div style="font-family:ui-monospace,monospace;font-size:10px;color:#64748b;">
            Ref: ${escapeHtml(report.investigation_id || 'NS-INV')}
          </div>
        </div>

        <!-- Verification Reason -->
        <div style="font-size:12px;color:#cbd5e1;line-height:1.6;margin-bottom:14px;background:rgba(255,255,255,0.02);padding:10px 12px;border-radius:4px;border-left:3px solid ${verdictBadge === 'ns-badge-verified' ? '#22c55e' : (verdictBadge === 'ns-badge-impersonation' ? '#ef4444' : '#f59e0b')};">
          ${escapeHtml(sv.reason || 'Verification complete.')}
        </div>

        <!-- Threat DNA Section -->
        ${dna.traits && dna.traits.length > 0 ? `
          <div style="margin-bottom:14px;">
            <div style="font-family:ui-monospace,monospace;font-size:10px;text-transform:uppercase;color:#64748b;margin-bottom:6px;">Threat DNA Sequence:</div>
            <div>
              ${dna.traits.map(t => `<span class="ns-dna-chip">🧬 ${escapeHtml(t)}</span>`).join('')}
            </div>
          </div>
        ` : ''}

        <!-- Extracted Links & Investigation -->
        ${links.findings && links.findings.length > 0 ? `
          <div style="margin-bottom:14px;">
            <div style="font-family:ui-monospace,monospace;font-size:10px;text-transform:uppercase;color:#64748b;margin-bottom:6px;">Embedded Link Intelligence:</div>
            ${links.findings.map(l => `
              <div style="background:rgba(0,0,0,0.25);border:1px solid rgba(255,255,255,0.06);border-radius:4px;padding:8px 10px;margin-bottom:6px;font-size:11px;">
                <div style="display:flex;justify-content:space-between;align-items:center;">
                  <span style="font-family:ui-monospace,monospace;color:#38bdf8;word-break:break-all;">${escapeHtml(l.url)}</span>
                  <span style="font-weight:700;color:${l.risk_level === 'LOW' ? '#4ade80' : '#f87171'};font-size:10px;margin-left:8px;">${l.risk_level}</span>
                </div>
                ${l.rules_hit && l.rules_hit.length > 0 ? `
                  <div style="color:#94a3b8;font-size:10px;margin-top:4px;">
                    Triggers: ${l.rules_hit.map(r => r.name || r.id).join(', ')}
                  </div>
                ` : ''}
              </div>
            `).join('')}
          </div>
        ` : ''}

        <!-- Autonomous Agent Decisions -->
        ${(report.agent_decisions && report.agent_decisions.length > 0) ? `
          <div style="margin-bottom:14px;">
            <div style="font-family:ui-monospace,monospace;font-size:10px;text-transform:uppercase;color:#38bdf8;margin-bottom:6px;display:flex;align-items:center;gap:6px;">
              <span>🤖</span> Agentic AI Decisions (${report.agent_decisions.length}):
            </div>
            <div style="display:flex;flex-direction:column;gap:6px;">
              ${report.agent_decisions.map((d, idx) => `
                <div style="background:rgba(0,0,0,0.3);border-radius:4px;border-left:3px solid #06b6d4;padding:6px 10px;font-size:10px;">
                  <div style="display:flex;justify-content:space-between;color:#38bdf8;font-weight:700;">
                    <span>#${d.decision_num || idx + 1} ${escapeHtml(d.action || d.selected || '')}</span>
                    <span style="color:#64748b;font-size:9px;">${escapeHtml(d.source || 'DETERMINISTIC')}</span>
                  </div>
                  <div style="color:#cbd5e1;margin-top:2px;">${escapeHtml(d.reason || '')}</div>
                </div>
              `).join('')}
            </div>
          </div>
        ` : ''}

        <!-- Actionable Guidance -->
        ${report.guidance && report.guidance.length > 0 ? `
          <div style="margin-bottom:14px;">
            <div style="font-family:ui-monospace,monospace;font-size:10px;text-transform:uppercase;color:#64748b;margin-bottom:4px;">Analyst Recommended Actions:</div>
            <ul style="margin:0;padding-left:18px;font-size:11px;color:#e2e8f0;line-height:1.7;">
              ${report.guidance.map(g => `<li><strong>${escapeHtml(g.action)}</strong>: ${escapeHtml(g.detail)}</li>`).join('')}
            </ul>
          </div>
        ` : ''}

        <!-- Footer / Deep Dive -->
        <div style="display:flex;justify-content:space-between;align-items:center;padding-top:10px;border-top:1px solid rgba(255,255,255,0.06);">
          <span style="font-size:11px;color:#94a3b8;">
            Open extension popup in browser toolbar for full evidence ledger & domain breakdown.
          </span>
          <a href="http://127.0.0.1:5000/investigation-center" target="_blank" class="ns-gmail-btn ns-gmail-btn-secondary" style="font-size:10px;text-decoration:none;">
            Open In SOC Console ↗
          </a>
        </div>
      </div>
    `;
  }

  function escapeHtml(str) {
    if (!str) return '';
    return String(str)
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;')
      .replace(/'/g, '&#039;');
  }

  // ── Debounced Scanner Loop ──
  let scanTimeout = null;
  function triggerScan() {
    if (scanTimeout) clearTimeout(scanTimeout);
    scanTimeout = setTimeout(() => {
      const email = extractGmailContext();
      if (email) {
        renderNeuraShieldBanner(email);
      }
    }, 400);
  }

  // ── Observe Gmail Navigation and DOM Mutations ──
  const observer = new MutationObserver((mutations) => {
    // Only inspect if relevant elements are added or modified
    for (const m of mutations) {
      if (m.addedNodes.length > 0) {
        triggerScan();
        break;
      }
    }
  });

  observer.observe(document.body, { childList: true, subtree: true });

  window.addEventListener('hashchange', triggerScan);
  window.addEventListener('popstate', triggerScan);

  // Initial scan
  setTimeout(triggerScan, 1500);

})();
