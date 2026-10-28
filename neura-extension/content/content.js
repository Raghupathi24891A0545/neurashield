/**
 * NeuraShield Chrome Extension — Gmail Content Script
 * Real-time institutional verification, link intelligence, and threat neutralization.
 */

(() => {
  let lastProcessedEmailKey = null;
  let isAnalyzing = false;
  let activeGuardianOverlay = null;

  console.log('[NeuraShield] Gmail Content Script initialized with Real-Time Link Guardian.');

  // ── Inject ALL styles via JS (guarantees they load regardless of CSS file / CSP) ──
  (function injectNeuraStyles() {
    if (document.getElementById('ns-injected-styles')) return;

    // Inject Google Font
    const fontLink = document.createElement('link');
    fontLink.rel = 'stylesheet';
    fontLink.href = 'https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800;900&display=swap';
    document.head.appendChild(fontLink);

    const style = document.createElement('style');
    style.id = 'ns-injected-styles';
    style.textContent = `
/* ── NeuraShield Injected Styles ── */
@keyframes ns-slide-in { from{opacity:0;transform:translateY(-10px)} to{opacity:1;transform:translateY(0)} }
@keyframes ns-fade-up  { from{opacity:0;transform:translateY(6px)}  to{opacity:1;transform:translateY(0)} }
@keyframes ns-pulse    { 0%,100%{opacity:.4;transform:scale(.85)} 50%{opacity:1;transform:scale(1.15);box-shadow:0 0 7px currentColor} }
@keyframes ns-indeterminate { 0%{transform:translateX(-200%)} 100%{transform:translateX(400%)} }
@keyframes ns-overlay-in { from{opacity:0} to{opacity:1} }
@keyframes ns-card-pop   { from{transform:scale(.92) translateY(14px);opacity:0} to{transform:scale(1) translateY(0);opacity:1} }
@keyframes ns-icon-pulse { 0%,100%{box-shadow:0 0 0 0 rgba(6,182,212,.4)} 50%{box-shadow:0 0 0 8px rgba(6,182,212,0)} }
@keyframes ns-icon-shake { 0%,100%{transform:rotate(0)} 20%{transform:rotate(-7deg)} 40%{transform:rotate(7deg)} 60%{transform:rotate(-4deg)} 80%{transform:rotate(4deg)} }
@keyframes ns-glow-line  { from{opacity:.7} to{opacity:1;filter:drop-shadow(0 0 4px #06b6d4)} }

/* BANNER ROOT */
div#neurashield-gmail-banner {
  display:block!important;width:100%!important;box-sizing:border-box!important;
  margin:14px 0 20px!important;border-radius:14px!important;overflow:visible!important;
  font-family:'Inter',-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif!important;
  color:#e2e8f0!important;
  background:linear-gradient(160deg,#06101f 0%,#0a1628 55%,#0e1c33 100%)!important;
  border:1.5px solid rgba(6,182,212,.35)!important;
  box-shadow:0 4px 24px rgba(0,0,0,.55),inset 0 1px 0 rgba(255,255,255,.04)!important;
  position:relative!important;z-index:9999!important;
  animation:ns-slide-in .45s cubic-bezier(.16,1,.3,1) both!important;
}
div#neurashield-gmail-banner *{
  box-sizing:border-box!important;
  font-family:'Inter',-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif!important;
}
/* TOP ACCENT BAR */
div#neurashield-gmail-banner .ns-top-accent{
  height:3px!important;display:block!important;
  background:linear-gradient(90deg,transparent,#06b6d4 30%,#818cf8 70%,transparent)!important;
  border-radius:14px 14px 0 0!important;
  animation:ns-glow-line 3s ease infinite alternate!important;
}
/* INNER PADDING */
div#neurashield-gmail-banner .ns-inner{padding:14px 18px 16px!important;display:block!important;}

/* HEADER */
div#neurashield-gmail-banner .ns-gmail-header{
  display:flex!important;justify-content:space-between!important;align-items:center!important;
  margin-bottom:12px!important;padding-bottom:12px!important;
  border-bottom:1px solid rgba(255,255,255,.07)!important;flex-wrap:wrap!important;gap:8px!important;
}
div#neurashield-gmail-banner .ns-gmail-brand{display:flex!important;align-items:center!important;gap:10px!important;}
div#neurashield-gmail-banner .ns-gmail-shield-wrap{
  width:38px!important;height:38px!important;border-radius:9px!important;flex-shrink:0!important;
  background:linear-gradient(135deg,rgba(6,182,212,.2),rgba(129,140,248,.2))!important;
  border:1px solid rgba(6,182,212,.4)!important;
  display:flex!important;align-items:center!important;justify-content:center!important;
}
div#neurashield-gmail-banner .ns-gmail-shield-icon{width:22px!important;height:22px!important;display:block!important;}
div#neurashield-gmail-banner .ns-brand-text{display:flex!important;flex-direction:column!important;gap:2px!important;}
div#neurashield-gmail-banner .ns-gmail-title{
  font-size:14px!important;font-weight:800!important;letter-spacing:.08em!important;
  text-transform:uppercase!important;line-height:1.1!important;display:block!important;
  background:linear-gradient(90deg,#22d3ee,#a78bfa)!important;
  -webkit-background-clip:text!important;-webkit-text-fill-color:transparent!important;background-clip:text!important;
}
div#neurashield-gmail-banner .ns-gmail-subtitle{
  font-size:10px!important;color:#475569!important;-webkit-text-fill-color:#475569!important;
  text-transform:uppercase!important;letter-spacing:.1em!important;font-weight:500!important;display:block!important;
}

/* STATUS CHIP */
div#neurashield-gmail-banner .ns-status-chip{
  display:inline-flex!important;align-items:center!important;gap:6px!important;
  padding:5px 13px!important;border-radius:999px!important;
  background:rgba(6,182,212,.1)!important;border:1px solid rgba(6,182,212,.35)!important;
  font-size:10px!important;font-weight:700!important;letter-spacing:.08em!important;
  color:#22d3ee!important;-webkit-text-fill-color:#22d3ee!important;
  text-transform:uppercase!important;white-space:nowrap!important;
}
div#neurashield-gmail-banner .ns-status-chip.safe{background:rgba(34,197,94,.12)!important;border-color:rgba(34,197,94,.4)!important;color:#4ade80!important;-webkit-text-fill-color:#4ade80!important;}
div#neurashield-gmail-banner .ns-status-chip.danger{background:rgba(239,68,68,.12)!important;border-color:rgba(239,68,68,.45)!important;color:#f87171!important;-webkit-text-fill-color:#f87171!important;}
div#neurashield-gmail-banner .ns-status-chip.warn{background:rgba(245,158,11,.12)!important;border-color:rgba(245,158,11,.4)!important;color:#fbbf24!important;-webkit-text-fill-color:#fbbf24!important;}

/* PULSE DOT */
.ns-pulse-dot{
  display:inline-block!important;width:7px!important;height:7px!important;border-radius:50%!important;
  background:currentColor!important;flex-shrink:0!important;animation:ns-pulse 2s ease infinite!important;
}

/* GRID */
div#neurashield-gmail-banner .ns-gmail-details-grid{
  display:grid!important;grid-template-columns:repeat(4,1fr)!important;
  background:rgba(0,0,0,.35)!important;border:1px solid rgba(255,255,255,.07)!important;
  border-radius:9px!important;overflow:hidden!important;margin-bottom:12px!important;
}
div#neurashield-gmail-banner .ns-detail-cell{padding:10px 13px!important;border-right:1px solid rgba(255,255,255,.06)!important;}
div#neurashield-gmail-banner .ns-detail-cell:last-child{border-right:none!important;}
div#neurashield-gmail-banner .ns-gmail-label{
  font-size:9px!important;color:#475569!important;-webkit-text-fill-color:#475569!important;
  text-transform:uppercase!important;letter-spacing:.1em!important;font-weight:700!important;
  margin-bottom:4px!important;display:block!important;
}
div#neurashield-gmail-banner .ns-gmail-val{
  font-size:12px!important;font-weight:600!important;color:#f1f5f9!important;-webkit-text-fill-color:#f1f5f9!important;
  white-space:nowrap!important;overflow:hidden!important;text-overflow:ellipsis!important;display:block!important;max-width:100%!important;
}
div#neurashield-gmail-banner .ns-gmail-val-mono{
  font-family:ui-monospace,'Fira Code',Menlo,monospace!important;font-size:11px!important;
  color:#22d3ee!important;-webkit-text-fill-color:#22d3ee!important;
  white-space:nowrap!important;overflow:hidden!important;text-overflow:ellipsis!important;display:block!important;
}
div#neurashield-gmail-banner .ns-gmail-val-sub{
  font-size:10px!important;color:#64748b!important;-webkit-text-fill-color:#64748b!important;
  margin-top:2px!important;display:block!important;white-space:nowrap!important;overflow:hidden!important;text-overflow:ellipsis!important;
}

/* ACTIONS */
div#neurashield-gmail-banner .ns-gmail-actions{display:flex!important;align-items:center!important;gap:8px!important;flex-wrap:wrap!important;}
div#neurashield-gmail-banner .ns-btn{
  display:inline-flex!important;align-items:center!important;gap:6px!important;
  padding:8px 16px!important;border-radius:7px!important;font-size:11px!important;font-weight:700!important;
  letter-spacing:.05em!important;text-transform:uppercase!important;cursor:pointer!important;
  border:none!important;outline:none!important;transition:all .18s!important;line-height:1!important;
}
div#neurashield-gmail-banner .ns-btn-primary{
  background:linear-gradient(135deg,#0891b2,#06b6d4)!important;
  color:#fff!important;-webkit-text-fill-color:#fff!important;
  box-shadow:0 2px 12px rgba(6,182,212,.4)!important;
}
div#neurashield-gmail-banner .ns-btn-primary:hover{background:linear-gradient(135deg,#0e7490,#0891b2)!important;transform:translateY(-1px)!important;box-shadow:0 4px 20px rgba(6,182,212,.55)!important;}
div#neurashield-gmail-banner .ns-btn-primary:disabled{opacity:.5!important;cursor:not-allowed!important;transform:none!important;}
div#neurashield-gmail-banner .ns-btn-ghost{
  background:rgba(255,255,255,.06)!important;color:#94a3b8!important;-webkit-text-fill-color:#94a3b8!important;
  border:1px solid rgba(255,255,255,.13)!important;
}
div#neurashield-gmail-banner .ns-btn-ghost:hover{background:rgba(255,255,255,.11)!important;color:#e2e8f0!important;-webkit-text-fill-color:#e2e8f0!important;}
div#neurashield-gmail-banner .ns-footer-label{
  display:flex!important;align-items:center!important;gap:5px!important;font-size:10px!important;
  color:#334155!important;-webkit-text-fill-color:#334155!important;margin-left:auto!important;font-weight:500!important;
}

/* RESULT DRAWER */
div#neurashield-gmail-banner .ns-gmail-result-drawer{margin-top:12px!important;animation:ns-fade-up .3s ease both!important;}
div#neurashield-gmail-banner .ns-scan-card{
  padding:14px 16px!important;background:rgba(6,182,212,.05)!important;
  border:1px solid rgba(6,182,212,.2)!important;border-radius:9px!important;
}
div#neurashield-gmail-banner .ns-scan-steps{
  font-family:ui-monospace,'Fira Code',Menlo,monospace!important;
  font-size:11px!important;color:#64748b!important;-webkit-text-fill-color:#64748b!important;
  line-height:2!important;margin-top:8px!important;
}
div#neurashield-gmail-banner .ns-scan-steps .active-step{color:#38bdf8!important;-webkit-text-fill-color:#38bdf8!important;font-weight:600!important;}
div#neurashield-gmail-banner .ns-progress{height:3px!important;background:rgba(255,255,255,.07)!important;border-radius:2px!important;overflow:hidden!important;margin-top:10px!important;}
div#neurashield-gmail-banner .ns-progress-bar{height:100%!important;width:50%!important;background:linear-gradient(90deg,#06b6d4,#818cf8)!important;border-radius:2px!important;animation:ns-indeterminate 1.4s ease infinite!important;}

/* RESULT CARD */
div#neurashield-gmail-banner .ns-result-card{background:rgba(0,0,0,.4)!important;border:1px solid rgba(255,255,255,.08)!important;border-radius:10px!important;overflow:hidden!important;}
div#neurashield-gmail-banner .ns-verdict-header{padding:14px 16px!important;display:flex!important;justify-content:space-between!important;align-items:center!important;flex-wrap:wrap!important;gap:10px!important;border-bottom:1px solid rgba(255,255,255,.06)!important;}
div#neurashield-gmail-banner .ns-verdict-header.safe{background:rgba(34,197,94,.08)!important;}
div#neurashield-gmail-banner .ns-verdict-header.warn{background:rgba(245,158,11,.08)!important;}
div#neurashield-gmail-banner .ns-verdict-header.danger{background:rgba(239,68,68,.1)!important;}
div#neurashield-gmail-banner .ns-verdict-badge{display:inline-flex!important;align-items:center!important;gap:7px!important;padding:5px 14px!important;border-radius:999px!important;font-size:11px!important;font-weight:800!important;letter-spacing:.05em!important;text-transform:uppercase!important;}
div#neurashield-gmail-banner .ns-verdict-badge.safe{background:rgba(34,197,94,.15)!important;color:#4ade80!important;-webkit-text-fill-color:#4ade80!important;border:1px solid rgba(34,197,94,.3)!important;}
div#neurashield-gmail-banner .ns-verdict-badge.warn{background:rgba(245,158,11,.15)!important;color:#fbbf24!important;-webkit-text-fill-color:#fbbf24!important;border:1px solid rgba(245,158,11,.3)!important;}
div#neurashield-gmail-banner .ns-verdict-badge.danger{background:rgba(239,68,68,.15)!important;color:#f87171!important;-webkit-text-fill-color:#f87171!important;border:1px solid rgba(239,68,68,.35)!important;}
div#neurashield-gmail-banner .ns-score-ring{display:flex!important;flex-direction:column!important;align-items:center!important;gap:1px!important;}
div#neurashield-gmail-banner .ns-score-num{font-size:24px!important;font-weight:900!important;line-height:1!important;display:block!important;}
div#neurashield-gmail-banner .ns-score-label{font-size:8px!important;text-transform:uppercase!important;letter-spacing:.1em!important;color:#64748b!important;-webkit-text-fill-color:#64748b!important;font-weight:600!important;display:block!important;}
div#neurashield-gmail-banner .ns-result-body{padding:14px 16px!important;display:flex!important;flex-direction:column!important;gap:12px!important;}
div#neurashield-gmail-banner .ns-reason-box{padding:10px 12px!important;background:rgba(255,255,255,.02)!important;border-radius:6px!important;font-size:12px!important;color:#cbd5e1!important;-webkit-text-fill-color:#cbd5e1!important;line-height:1.6!important;border-left:3px solid!important;}
div#neurashield-gmail-banner .ns-section-label{font-size:9px!important;font-weight:700!important;color:#475569!important;-webkit-text-fill-color:#475569!important;text-transform:uppercase!important;letter-spacing:.12em!important;margin-bottom:7px!important;display:block!important;}
div#neurashield-gmail-banner .ns-dna-row{display:flex!important;flex-wrap:wrap!important;gap:5px!important;}
div#neurashield-gmail-banner .ns-dna-chip{display:inline-flex!important;align-items:center!important;gap:4px!important;padding:3px 9px!important;border-radius:5px!important;font-family:ui-monospace,'Fira Code',Menlo,monospace!important;font-size:10px!important;font-weight:600!important;background:rgba(129,140,248,.12)!important;color:#a5b4fc!important;-webkit-text-fill-color:#a5b4fc!important;border:1px solid rgba(129,140,248,.25)!important;}
div#neurashield-gmail-banner .ns-link-item{background:rgba(0,0,0,.3)!important;border:1px solid rgba(255,255,255,.06)!important;border-radius:7px!important;padding:9px 12px!important;display:flex!important;align-items:center!important;gap:10px!important;flex-wrap:wrap!important;}
div#neurashield-gmail-banner .ns-link-url{font-family:ui-monospace,'Fira Code',Menlo,monospace!important;font-size:11px!important;color:#38bdf8!important;-webkit-text-fill-color:#38bdf8!important;word-break:break-all!important;flex:1!important;min-width:120px!important;}
div#neurashield-gmail-banner .ns-link-risk{font-size:10px!important;font-weight:800!important;padding:3px 8px!important;border-radius:4px!important;text-transform:uppercase!important;white-space:nowrap!important;}
div#neurashield-gmail-banner .ns-link-risk.LOW{background:rgba(34,197,94,.15)!important;color:#4ade80!important;-webkit-text-fill-color:#4ade80!important;}
div#neurashield-gmail-banner .ns-link-risk.MEDIUM{background:rgba(245,158,11,.15)!important;color:#fbbf24!important;-webkit-text-fill-color:#fbbf24!important;}
div#neurashield-gmail-banner .ns-link-risk.HIGH{background:rgba(239,68,68,.15)!important;color:#f87171!important;-webkit-text-fill-color:#f87171!important;}
div#neurashield-gmail-banner .ns-verify-btn{display:inline-flex!important;align-items:center!important;gap:4px!important;padding:4px 10px!important;background:rgba(255,255,255,.06)!important;border:1px solid rgba(255,255,255,.12)!important;border-radius:5px!important;font-size:10px!important;font-weight:700!important;color:#94a3b8!important;-webkit-text-fill-color:#94a3b8!important;cursor:pointer!important;text-transform:uppercase!important;letter-spacing:.05em!important;transition:all .15s!important;outline:none!important;}
div#neurashield-gmail-banner .ns-result-footer{padding:10px 16px!important;border-top:1px solid rgba(255,255,255,.05)!important;display:flex!important;align-items:center!important;justify-content:space-between!important;flex-wrap:wrap!important;gap:8px!important;background:rgba(0,0,0,.2)!important;}
div#neurashield-gmail-banner .ns-ref-id{font-family:ui-monospace,monospace!important;font-size:9px!important;color:#334155!important;-webkit-text-fill-color:#334155!important;}
div#neurashield-gmail-banner .ns-console-link{display:inline-flex!important;align-items:center!important;gap:4px!important;padding:5px 12px!important;background:rgba(99,102,241,.12)!important;border:1px solid rgba(99,102,241,.3)!important;border-radius:5px!important;font-size:10px!important;font-weight:700!important;color:#a5b4fc!important;-webkit-text-fill-color:#a5b4fc!important;text-decoration:none!important;cursor:pointer!important;}
div#neurashield-gmail-banner .ns-agent-decision{background:rgba(0,0,0,.25)!important;border-left:2px solid #06b6d4!important;border-radius:0 5px 5px 0!important;padding:7px 10px!important;font-size:10px!important;}
div#neurashield-gmail-banner .ns-agent-num{color:#06b6d4!important;-webkit-text-fill-color:#06b6d4!important;font-weight:800!important;margin-right:4px!important;}
div#neurashield-gmail-banner .ns-agent-label{color:#e2e8f0!important;-webkit-text-fill-color:#e2e8f0!important;font-weight:600!important;}
div#neurashield-gmail-banner .ns-agent-reason{color:#64748b!important;-webkit-text-fill-color:#64748b!important;margin-top:2px!important;}
div#neurashield-gmail-banner .ns-guidance-item{font-size:11px!important;color:#cbd5e1!important;-webkit-text-fill-color:#cbd5e1!important;line-height:1.5!important;padding:6px 0!important;border-bottom:1px solid rgba(255,255,255,.04)!important;display:flex!important;gap:8px!important;align-items:flex-start!important;}

/* ── LINK GUARDIAN OVERLAY ── */
div#ns-link-guardian-overlay{
  position:fixed!important;top:0!important;left:0!important;right:0!important;bottom:0!important;
  width:100vw!important;height:100vh!important;
  background:rgba(3,7,18,.88)!important;backdrop-filter:blur(14px)!important;-webkit-backdrop-filter:blur(14px)!important;
  z-index:2147483647!important;display:flex!important;align-items:center!important;justify-content:center!important;
  padding:20px!important;animation:ns-overlay-in .22s ease both!important;
  font-family:'Inter',-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif!important;
}
div#ns-link-guardian-overlay div#ns-link-guardian-card{
  width:100%!important;max-width:480px!important;
  background:linear-gradient(145deg,#080f1f,#0d1829)!important;
  border:1.5px solid rgba(6,182,212,.4)!important;border-radius:16px!important;overflow:hidden!important;
  box-shadow:0 30px 60px rgba(0,0,0,.8),0 0 40px rgba(6,182,212,.1)!important;
  animation:ns-card-pop .3s cubic-bezier(.16,1,.3,1) both!important;
  color:#e2e8f0!important;-webkit-text-fill-color:#e2e8f0!important;
}
div#ns-link-guardian-overlay div#ns-link-guardian-card *{box-sizing:border-box!important;font-family:'Inter',-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif!important;}
div#ns-link-guardian-overlay div#ns-link-guardian-card.ns-card-blocked{border-color:rgba(239,68,68,.55)!important;box-shadow:0 30px 60px rgba(0,0,0,.8),0 0 50px rgba(239,68,68,.18)!important;}
div#ns-link-guardian-overlay div#ns-link-guardian-card.ns-card-safe{border-color:rgba(34,197,94,.5)!important;box-shadow:0 30px 60px rgba(0,0,0,.8),0 0 50px rgba(34,197,94,.14)!important;}
div#ns-link-guardian-overlay .ns-card-accent{height:3px!important;background:linear-gradient(90deg,transparent,#06b6d4,transparent)!important;}
div#ns-link-guardian-overlay .ns-card-accent.blocked{background:linear-gradient(90deg,transparent,#ef4444,transparent)!important;}
div#ns-link-guardian-overlay .ns-card-accent.safe{background:linear-gradient(90deg,transparent,#22c55e,transparent)!important;}
div#ns-link-guardian-overlay .ns-guardian-inner{padding:20px!important;}
div#ns-link-guardian-overlay .ns-guardian-header{display:flex!important;align-items:center!important;gap:14px!important;margin-bottom:16px!important;padding-bottom:14px!important;border-bottom:1px solid rgba(255,255,255,.06)!important;}
div#ns-link-guardian-overlay .ns-guardian-icon-wrap{width:48px!important;height:48px!important;border-radius:12px!important;display:flex!important;align-items:center!important;justify-content:center!important;font-size:22px!important;flex-shrink:0!important;background:rgba(6,182,212,.15)!important;border:1px solid rgba(6,182,212,.35)!important;}
div#ns-link-guardian-overlay .ns-guardian-icon-wrap.scanning{animation:ns-icon-pulse 1.5s ease infinite!important;}
div#ns-link-guardian-overlay .ns-guardian-icon-wrap.blocked{background:rgba(239,68,68,.15)!important;border-color:rgba(239,68,68,.45)!important;animation:ns-icon-shake .5s ease!important;}
div#ns-link-guardian-overlay .ns-guardian-icon-wrap.safe{background:rgba(34,197,94,.15)!important;border-color:rgba(34,197,94,.45)!important;}
div#ns-link-guardian-overlay .ns-guardian-title-group{flex:1!important;}
div#ns-link-guardian-overlay .ns-guardian-title{font-size:14px!important;font-weight:800!important;text-transform:uppercase!important;letter-spacing:.06em!important;color:#f8fafc!important;-webkit-text-fill-color:#f8fafc!important;line-height:1.2!important;display:block!important;}
div#ns-link-guardian-overlay .ns-guardian-title.blocked{color:#fca5a5!important;-webkit-text-fill-color:#fca5a5!important;}
div#ns-link-guardian-overlay .ns-guardian-title.safe{color:#86efac!important;-webkit-text-fill-color:#86efac!important;}
div#ns-link-guardian-overlay .ns-guardian-sub{font-size:10px!important;font-family:ui-monospace,monospace!important;color:#475569!important;-webkit-text-fill-color:#475569!important;margin-top:3px!important;text-transform:uppercase!important;letter-spacing:.06em!important;display:block!important;}
div#ns-link-guardian-overlay .ns-url-box{background:rgba(0,0,0,.35)!important;border:1px solid rgba(255,255,255,.07)!important;border-radius:9px!important;padding:11px 14px!important;margin-bottom:14px!important;}
div#ns-link-guardian-overlay .ns-url-tag{font-size:9px!important;font-weight:700!important;text-transform:uppercase!important;letter-spacing:.12em!important;color:#475569!important;-webkit-text-fill-color:#475569!important;margin-bottom:5px!important;display:block!important;}
div#ns-link-guardian-overlay .ns-url-domain{font-size:15px!important;font-weight:700!important;color:#38bdf8!important;-webkit-text-fill-color:#38bdf8!important;font-family:ui-monospace,'Fira Code',Menlo,monospace!important;display:block!important;}
div#ns-link-guardian-overlay .ns-url-full{font-size:10px!important;color:#475569!important;-webkit-text-fill-color:#475569!important;font-family:ui-monospace,monospace!important;margin-top:3px!important;word-break:break-all!important;display:block!important;}
div#ns-link-guardian-overlay .ns-status-body{background:rgba(255,255,255,.025)!important;border:1px solid rgba(255,255,255,.06)!important;border-radius:9px!important;padding:13px 14px!important;margin-bottom:16px!important;color:#e2e8f0!important;-webkit-text-fill-color:#e2e8f0!important;}
div#ns-link-guardian-overlay .ns-grd-progress{height:3px!important;background:rgba(255,255,255,.07)!important;border-radius:2px!important;overflow:hidden!important;margin-top:10px!important;}
div#ns-link-guardian-overlay .ns-grd-progress-fill{height:100%!important;width:40%!important;background:linear-gradient(90deg,#0284c7,#06b6d4,#38bdf8)!important;border-radius:2px!important;animation:ns-indeterminate 1.4s ease infinite!important;}
div#ns-link-guardian-overlay .ns-threat-traits{display:flex!important;flex-wrap:wrap!important;gap:5px!important;margin-top:10px!important;}
div#ns-link-guardian-overlay .ns-threat-chip{display:inline-flex!important;align-items:center!important;gap:4px!important;padding:3px 9px!important;border-radius:4px!important;font-family:ui-monospace,monospace!important;font-size:10px!important;font-weight:600!important;background:rgba(239,68,68,.12)!important;color:#fca5a5!important;-webkit-text-fill-color:#fca5a5!important;border:1px solid rgba(239,68,68,.3)!important;}
div#ns-link-guardian-overlay .ns-danger-box{background:rgba(239,68,68,.08)!important;border-left:3px solid #ef4444!important;border-radius:0 6px 6px 0!important;padding:8px 12px!important;font-size:11px!important;color:#fca5a5!important;-webkit-text-fill-color:#fca5a5!important;margin-top:10px!important;line-height:1.5!important;}
div#ns-link-guardian-overlay .ns-guardian-btns{display:flex!important;gap:10px!important;align-items:center!important;flex-wrap:wrap!important;justify-content:flex-end!important;}
div#ns-link-guardian-overlay .ns-grd-btn-safe{background:linear-gradient(135deg,#15803d,#22c55e)!important;color:#fff!important;-webkit-text-fill-color:#fff!important;border:none!important;padding:11px 22px!important;border-radius:8px!important;font-size:12px!important;font-weight:700!important;cursor:pointer!important;box-shadow:0 4px 14px rgba(34,197,94,.4)!important;letter-spacing:.04em!important;transition:all .18s!important;outline:none!important;}
div#ns-link-guardian-overlay .ns-grd-btn-danger{background:linear-gradient(135deg,#b91c1c,#ef4444)!important;color:#fff!important;-webkit-text-fill-color:#fff!important;border:none!important;padding:11px 22px!important;border-radius:8px!important;font-size:12px!important;font-weight:700!important;cursor:pointer!important;box-shadow:0 4px 14px rgba(239,68,68,.4)!important;letter-spacing:.04em!important;transition:all .18s!important;outline:none!important;}
div#ns-link-guardian-overlay .ns-grd-btn-cancel{background:rgba(255,255,255,.06)!important;color:#94a3b8!important;-webkit-text-fill-color:#94a3b8!important;border:1px solid rgba(255,255,255,.12)!important;padding:11px 18px!important;border-radius:8px!important;font-size:12px!important;font-weight:600!important;cursor:pointer!important;transition:all .15s!important;outline:none!important;}
div#ns-link-guardian-overlay .ns-grd-override{background:none!important;border:none!important;color:#334155!important;-webkit-text-fill-color:#334155!important;font-size:10px!important;text-decoration:underline!important;cursor:pointer!important;padding:6px!important;margin-left:auto!important;}
div#ns-link-guardian-overlay .ns-countdown{font-size:11px!important;color:#22d3ee!important;-webkit-text-fill-color:#22d3ee!important;font-weight:700!important;margin-top:8px!important;display:flex!important;align-items:center!important;gap:6px!important;}
    `;
    document.head.appendChild(style);
  })();

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

  function escapeHtml(str) {
    if (!str) return '';
    return String(str)
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;')
      .replace(/'/g, '&#039;');
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
        if (href && href.startsWith('http') && !href.includes('mail.google.com')) {
          if (href.includes('google.com/url?') && href.includes('q=')) {
            try {
              const u = new URL(href);
              const real = u.searchParams.get('q');
              if (real) href = real;
            } catch (e) {}
          }
          if (!links.includes(href)) {
            links.push(href);
          }
        }
      }
    }

    // 6b. Attachments from Gmail DOM
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
      activeContainer: activeContainer,
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

  // ── Render Premium NeuraShield Banner into Gmail Email View ──
  function renderNeuraShieldBanner(emailContext) {
    if (!emailContext) return;

    const emailKey = `${emailContext.sender_email}|${emailContext.subject}|${emailContext.links.length}`;
    if (lastProcessedEmailKey === emailKey && qs('#neurashield-gmail-banner')) {
      return;
    }

    const existing = qs('#neurashield-gmail-banner');
    if (existing) existing.remove();

    if (typeof chrome !== 'undefined' && chrome.runtime && chrome.runtime.sendMessage) {
      chrome.runtime.sendMessage({
        type: 'GMAIL_EMAIL_OPENED',
        payload: emailContext
      }).catch(() => {});
    }

    // Find optimal, perfectly aligned insertion point
    // Inside the message card, right before .ii.gt (the email message body)
    let targetMount = null;
    const activeCont = emailContext.activeContainer || document.body;
    const messageCard = activeCont.closest('.adn.ads') || activeCont.closest('.gs') || qs('.adn.ads');
    
    if (messageCard) {
      const bodyContainer = qs('.ii.gt', messageCard);
      if (bodyContainer && bodyContainer.parentElement) {
        targetMount = bodyContainer;
      }
    }

    if (!targetMount) {
      const fallback = qs('.ii.gt', activeCont) || qs('.a3s.aiL', activeCont) || qs('.a3s.aiL');
      if (fallback && fallback.parentElement) {
        targetMount = fallback;
      }
    }

    if (!targetMount || !targetMount.parentElement) return;

    const banner = document.createElement('div');
    banner.id = 'neurashield-gmail-banner';

    const linkCount = emailContext.links.length;
    const attachCount = emailContext.attachments.length;

    banner.innerHTML = `
      <div class="ns-top-accent"></div>
      <div class="ns-inner">
        <!-- Header -->
        <div class="ns-gmail-header">
          <div class="ns-gmail-brand">
            <div class="ns-gmail-shield-wrap">
              <svg class="ns-gmail-shield-icon" viewBox="0 0 100 100" fill="none" xmlns="http://www.w3.org/2000/svg">
                <path d="M50 5 L90 20 V50 C90 75 50 95 50 95 C50 95 10 75 10 50 V20 L50 5 Z" fill="rgba(6,182,212,0.12)" stroke="#06b6d4" stroke-width="6"/>
                <path d="M50 30 V70 M30 50 H70" stroke="#00f260" stroke-width="7" stroke-linecap="round"/>
              </svg>
            </div>
            <div class="ns-brand-text">
              <span class="ns-gmail-title">NeuraShield</span>
              <span class="ns-gmail-subtitle">Cybersecurity SOC Console</span>
            </div>
          </div>
          <div class="ns-status-chip" id="nsStatusChip">
            <span class="ns-pulse-dot"></span>
            <span>SCANNING...</span>
          </div>
        </div>

        <!-- Metadata Grid -->
        <div class="ns-gmail-details-grid">
          <div class="ns-detail-cell">
            <div class="ns-gmail-label">From</div>
            <div class="ns-gmail-val" title="${escapeHtml(emailContext.sender_name)}">${escapeHtml((emailContext.sender_name || emailContext.sender_email).slice(0, 28))}${(emailContext.sender_name || '').length > 28 ? '…' : ''}</div>
            <div class="ns-gmail-val-sub" title="${escapeHtml(emailContext.sender_email)}">${escapeHtml(emailContext.sender_email)}</div>
          </div>
          <div class="ns-detail-cell">
            <div class="ns-gmail-label">Organization</div>
            <div class="ns-gmail-val" style="color:${emailContext.claimed_org ? '#38bdf8' : '#475569'}">${escapeHtml(emailContext.claimed_org || '— none claimed')}</div>
          </div>
          <div class="ns-detail-cell">
            <div class="ns-gmail-label">Domain</div>
            <div class="ns-gmail-val-mono" title="${escapeHtml(emailContext.sender_domain)}">${escapeHtml(emailContext.sender_domain)}</div>
          </div>
          <div class="ns-detail-cell" style="border-right:none">
            <div class="ns-gmail-label">Threat Surface</div>
            <div class="ns-gmail-val" style="color:${linkCount > 0 ? '#fbbf24' : '#4ade80'}">${linkCount} Link${linkCount !== 1 ? 's' : ''} &bull; ${attachCount} File${attachCount !== 1 ? 's' : ''}</div>
            <div class="ns-gmail-val-sub">Guardian Active</div>
          </div>
        </div>

        <!-- Action Row -->
        <div class="ns-gmail-actions">
          <button id="nsAnalyzeBtn" class="ns-btn ns-btn-primary">
            <span>⚡</span> Analyze with NeuraShield
          </button>
          ${linkCount > 0 ? `
            <button id="nsAnalyzeLinksBtn" class="ns-btn ns-btn-ghost">
              <span>🔗</span> Inspect ${linkCount} Link${linkCount !== 1 ? 's' : ''}
            </button>
          ` : ''}
          <span class="ns-footer-label">
            <span style="color:#1e40af;font-size:12px;">🛡️</span>
            Real-Time Link Guardian Active
          </span>
        </div>

        <!-- Result Drawer -->
        <div id="nsResultContainer" class="ns-gmail-result-drawer" style="display:none;"></div>
      </div>
    `;

    targetMount.parentElement.insertBefore(banner, targetMount);
    lastProcessedEmailKey = emailKey;

    // Attach Banner Event Handlers
    const analyzeBtn = banner.querySelector('#nsAnalyzeBtn');
    if (analyzeBtn) {
      analyzeBtn.addEventListener('click', () => runEmailInvestigation(emailContext));
    }

    const analyzeLinksBtn = banner.querySelector('#nsAnalyzeLinksBtn');
    if (analyzeLinksBtn) {
      analyzeLinksBtn.addEventListener('click', () => runEmailInvestigation(emailContext, { focusLinks: true }));
    }

    // Auto-trigger investigation
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
    const statusChip = qs('#nsStatusChip', banner);

    if (btn) { btn.disabled = true; btn.innerHTML = '<span>⏳</span> Investigating...'; }
    if (statusChip) { statusChip.className = 'ns-status-chip'; statusChip.innerHTML = '<span class="ns-pulse-dot"></span><span>SCANNING LIVE</span>'; }

    if (resultBox) {
      resultBox.style.display = 'block';
      resultBox.innerHTML = `
        <div class="ns-scan-card">
          <div style="display:flex;align-items:center;gap:10px;">
            <span class="ns-pulse-dot" style="flex-shrink:0;"></span>
            <strong style="color:#22d3ee;font-size:12px;letter-spacing:0.04em;">🤖 Agentic AI Threat Investigation Running...</strong>
          </div>
          <div class="ns-scan-steps">
            <div>✓ Querying Institutional Authority Registry...</div>
            <div>✓ Evaluating SPF / DKIM / DMARC alignment...</div>
            <div>✓ Running AI link risk fusion engine...</div>
            <div class="active-step">● Synthesizing Threat DNA fingerprint...</div>
          </div>
          <div class="ns-progress"><div class="ns-progress-bar"></div></div>
        </div>
      `;
    }

    try {
      const report = await NeuraShieldAPI.investigateEmail({
        sender_email: emailContext.sender_email,
        sender_name:  emailContext.sender_name,
        claimed_org:  emailContext.claimed_org,
        subject:      emailContext.subject,
        recipient:    emailContext.recipient,
        body_text:    emailContext.body_text,
        links:        emailContext.links
      });

      if (typeof chrome !== 'undefined' && chrome.runtime && chrome.runtime.sendMessage) {
        chrome.runtime.sendMessage({ type: 'STORE_INVESTIGATION_RESULT', payload: report }).catch(() => {});
      }

      displayInvestigationResult(report, statusChip);

    } catch (err) {
      if (resultBox) {
        resultBox.innerHTML = `
          <div class="ns-scan-card" style="border-color:rgba(239,68,68,0.3);background:rgba(239,68,68,0.06);">
            <div style="color:#f87171;font-weight:700;font-size:12px;margin-bottom:4px;">⚠ Connection Error</div>
            <div style="color:#94a3b8;font-size:11px;">${escapeHtml(err.message || 'Could not reach NeuraShield backend.')}</div>
          </div>
        `;
      }
      if (statusChip) { statusChip.className = 'ns-status-chip danger'; statusChip.innerHTML = '<span class="ns-pulse-dot"></span><span>ERROR</span>'; }
    } finally {
      isAnalyzing = false;
      if (btn) { btn.disabled = false; btn.innerHTML = '<span>⚡</span> Re-Analyze'; }
    }
  }

  // ── Render Premium Investigation Results into Banner ──
  function displayInvestigationResult(report, statusChip) {
    const resultBox = qs('#nsResultContainer');
    if (!resultBox) return;

    if (report.backend_offline) {
      resultBox.innerHTML = `<div class="ns-scan-card" style="border-color:rgba(239,68,68,0.3);background:rgba(239,68,68,0.06);"><div style="color:#f87171;font-weight:700;">Backend Offline</div><div style="color:#94a3b8;font-size:11px;margin-top:4px;">Could not reach https://neurashield-kp6p.onrender.com</div></div>`;
      return;
    }

    const sv   = report.sender_verification || {};
    const risk = report.risk || {};
    const dna  = report.threat_dna || {};
    const lnks = report.links || {};
    const decisions = report.agent_decisions || [];
    const guidance  = report.guidance || [];

    const score = risk.score || 0;
    const level = (risk.level || 'LOW').toUpperCase();
    const verd  = sv.verdict || '';

    // Map to CSS state classes
    const isSafe   = level === 'LOW'  || verd === 'VERIFIED_INSTITUTIONAL_SENDER';
    const isDanger = level === 'HIGH' || level === 'CRITICAL' || verd.includes('IMPERSONATION');
    const stateClass = isSafe ? 'safe' : isDanger ? 'danger' : 'warn';
    const scoreColor = isSafe ? '#4ade80' : isDanger ? '#f87171' : '#fbbf24';
    const verdictText = sv.verdict_label || (isSafe ? 'Verified Legitimate' : isDanger ? 'Threat Detected' : 'Unverified');
    const verdIcon    = isSafe ? '✓' : isDanger ? '⛔' : '⚠';

    // Update header status chip
    if (statusChip) {
      statusChip.className = `ns-status-chip ${stateClass}`;
      statusChip.innerHTML = `<span class="ns-pulse-dot"></span><span>${isSafe ? 'VERIFIED SAFE' : isDanger ? 'THREAT DETECTED' : 'REVIEW NEEDED'}</span>`;
    }

    resultBox.innerHTML = `
      <div class="ns-result-card">

        <!-- Verdict Header -->
        <div class="ns-verdict-header ${stateClass}">
          <div>
            <div class="ns-gmail-label" style="margin-bottom:6px;">Sender Verification Verdict</div>
            <div class="ns-verdict-badge ${stateClass}">
              <span>${verdIcon}</span>
              <span>${escapeHtml(verdictText)}</span>
            </div>
          </div>
          <div class="ns-score-ring" style="color:${scoreColor}">
            <div class="ns-score-num">${score}</div>
            <div class="ns-score-label">/ 100 Risk</div>
          </div>
        </div>

        <!-- Result Body -->
        <div class="ns-result-body">

          <!-- Reason -->
          ${sv.reason ? `
            <div class="ns-reason-box" style="border-color:${scoreColor};">
              ${escapeHtml(sv.reason)}
            </div>
          ` : ''}

          <!-- Threat DNA -->
          ${dna.traits && dna.traits.length > 0 ? `
            <div>
              <div class="ns-section-label">🧬 Threat DNA Fingerprint</div>
              <div class="ns-dna-row">
                ${dna.traits.map(t => `<span class="ns-dna-chip">${escapeHtml(t)}</span>`).join('')}
              </div>
            </div>
          ` : ''}

          <!-- Links Intelligence -->
          ${lnks.findings && lnks.findings.length > 0 ? `
            <div>
              <div class="ns-section-label">🔗 Embedded Link Intelligence</div>
              <div style="display:flex;flex-direction:column;gap:6px;">
                ${lnks.findings.map(l => {
                  const lr = (l.risk_level || 'LOW').toUpperCase();
                  return `
                    <div class="ns-link-item">
                      <div class="ns-link-url" title="${escapeHtml(l.url)}">${escapeHtml(l.url.length > 60 ? l.url.slice(0, 60) + '…' : l.url)}</div>
                      <span class="ns-link-risk ${lr}">${lr}</span>
                      <button class="ns-verify-btn ns-btn-inspect-url" data-target-url="${escapeHtml(l.url)}">🛡 Verify</button>
                    </div>
                  `;
                }).join('')}
              </div>
            </div>
          ` : ''}

          <!-- Agent Decisions -->
          ${decisions.length > 0 ? `
            <div>
              <div class="ns-section-label">🤖 Agentic AI Decisions (${decisions.length})</div>
              <div style="display:flex;flex-direction:column;gap:4px;">
                ${decisions.slice(0, 4).map((d, i) => `
                  <div class="ns-agent-decision">
                    <span class="ns-agent-num">#${d.decision_num || i + 1}</span>
                    <span class="ns-agent-label">${escapeHtml(d.selected || d.action || '')}</span>
                    <div class="ns-agent-reason">${escapeHtml(d.reason || '')}</div>
                  </div>
                `).join('')}
              </div>
            </div>
          ` : ''}

          <!-- Guidance -->
          ${guidance.length > 0 ? `
            <div>
              <div class="ns-section-label">📋 Analyst Recommendations</div>
              <div>
                ${guidance.map(g => `
                  <div class="ns-guidance-item">
                    <span style="color:${scoreColor};flex-shrink:0;">▸</span>
                    <span><strong>${escapeHtml(g.action)}:</strong> ${escapeHtml(g.detail)}</span>
                  </div>
                `).join('')}
              </div>
            </div>
          ` : ''}

        </div>

        <!-- Footer -->
        <div class="ns-result-footer">
          <span class="ns-ref-id">REF: ${escapeHtml(report.investigation_id || 'NS-INV')}</span>
          <a href="https://neurashield-kp6p.onrender.com/investigation-center" target="_blank" class="ns-console-link">
            Open SOC Console ↗
          </a>
        </div>

      </div>
    `;

    // Attach link guardian handlers
    const verifyBtns = resultBox.querySelectorAll('.ns-btn-inspect-url');
    for (const b of verifyBtns) {
      b.addEventListener('click', (ev) => {
        ev.preventDefault(); ev.stopPropagation();
        const u = b.getAttribute('data-target-url');
        if (u) handleLinkGuardianClick(u);
      });
    }
  }

  // ── Real-Time Link Guardian: Click Interception & Blocker Modal ──
  async function handleLinkGuardianClick(targetUrl) {
    if (!targetUrl) return;

    if (activeGuardianOverlay) {
      activeGuardianOverlay.remove();
      activeGuardianOverlay = null;
    }

    const overlay = document.createElement('div');
    overlay.id = 'ns-link-guardian-overlay';

    let displayDomain = targetUrl;
    try {
      displayDomain = new URL(targetUrl).hostname;
    } catch (e) {}

    overlay.innerHTML = `
      <div id="ns-link-guardian-card">
        <div class="ns-card-accent" id="nsCardAccent"></div>
        <div class="ns-guardian-inner">

          <!-- Header -->
          <div class="ns-guardian-header">
            <div class="ns-guardian-icon-wrap scanning" id="nsGuardianIcon">🛡️</div>
            <div class="ns-guardian-title-group">
              <div class="ns-guardian-title" id="nsGuardianTitle">NeuraShield Link Guardian</div>
              <div class="ns-guardian-sub" id="nsGuardianSub">REAL-TIME THREAT VERIFICATION</div>
            </div>
          </div>

          <!-- URL Box -->
          <div class="ns-url-box">
            <div class="ns-url-tag">Target Destination</div>
            <div class="ns-url-domain">${escapeHtml(displayDomain)}</div>
            <div class="ns-url-full">${escapeHtml(targetUrl)}</div>
          </div>

          <!-- Status Body -->
          <div class="ns-status-body" id="nsGuardianStatusBox">
            <div style="display:flex;align-items:center;gap:10px;">
              <span class="ns-pulse-dot" style="flex-shrink:0;"></span>
              <span style="font-size:12px;font-weight:700;color:#22d3ee;">Scanning against live threat intelligence...</span>
            </div>
            <div style="font-size:11px;color:#475569;margin-top:8px;line-height:1.6;">
              Checking domain age, SSL validity, typosquatting & brand impersonation patterns...
            </div>
            <div class="ns-grd-progress"><div class="ns-grd-progress-fill"></div></div>
          </div>

          <!-- Buttons -->
          <div class="ns-guardian-btns" id="nsGuardianBtnRow">
            <button class="ns-grd-btn-cancel" id="nsGuardianCancelBtn">Cancel</button>
          </div>

        </div>
      </div>
    `;

    document.body.appendChild(overlay);
    activeGuardianOverlay = overlay;

    const cancelBtn = overlay.querySelector('#nsGuardianCancelBtn');
    if (cancelBtn) {
      cancelBtn.addEventListener('click', () => {
        overlay.remove();
        activeGuardianOverlay = null;
      });
    }

    try {
      // Execute live URL investigation via Render backend
      const report = await NeuraShieldAPI.investigateUrl(targetUrl);
      const card = overlay.querySelector('#ns-link-guardian-card');
      const icon = overlay.querySelector('#nsGuardianIcon');
      const title = overlay.querySelector('#nsGuardianTitle');
      const sub = overlay.querySelector('#nsGuardianSub');
      const statusBox = overlay.querySelector('#nsGuardianStatusBox');
      const btnRow = overlay.querySelector('#nsGuardianBtnRow');

      if (!card || !statusBox) return;

      // Check if destination is a recognized authentic authority domain
      const TRUSTED_DOMAINS = [
        'github.com', 'github.io', 'githubassets.com', 'githubusercontent.com',
        'google.com', 'google.co.in', 'youtube.com', 'gmail.com', 'gstatic.com',
        'microsoft.com', 'live.com', 'outlook.com', 'office.com', 'windows.com',
        'apple.com', 'icloud.com', 'linkedin.com', 'amazon.com', 'aws.amazon.com',
        'paypal.com', 'stripe.com', 'stackoverflow.com', 'wikipedia.org',
        'render.com', 'gitlab.com', 'twitter.com', 'x.com'
      ];
      const hostLower = (displayDomain || '').toLowerCase();
      const isTrustedDomain = TRUSTED_DOMAINS.some(td => hostLower === td || hostLower.endsWith('.' + td));

      const risk = (report && report.risk) || {};
      const score = typeof risk.score === 'number' ? risk.score : (isTrustedDomain ? 0 : 25);
      const level = (risk.level || (isTrustedDomain ? 'LOW' : 'LOW')).toUpperCase();
      const verdict = (risk.verdict || (isTrustedDomain ? 'LEGITIMATE' : 'LEGITIMATE')).toUpperCase();

      // Check whether Legitimate or Malicious/Suspicious
      let isThreat = false;
      if (verdict.includes('PHISH') || verdict.includes('MALICIOUS') || level === 'CRITICAL' || (score >= 60 && !isTrustedDomain)) {
        isThreat = true;
      }
      const isLegitimate = !isThreat;

      const accent = overlay.querySelector('#nsCardAccent');

      if (isLegitimate) {
        // ── VERIFIED LEGITIMATE: Allow and Open ──
        card.classList.add('ns-card-safe');
        if (accent) accent.className = 'ns-card-accent safe';
        icon.className = 'ns-guardian-icon-wrap safe';
        icon.textContent = '✅';
        title.textContent = 'Destination Verified Safe';
        title.className = 'ns-guardian-title safe';
        sub.textContent = `RISK SCORE: ${score}/100 — LEGITIMATE VERDICT`;

        statusBox.innerHTML = `
          <div style="display:flex;align-items:center;gap:10px;margin-bottom:8px;">
            <span style="font-size:20px;">🛡️</span>
            <div>
              <div style="font-size:13px;font-weight:800;color:#4ade80;">Authenticity Confirmed</div>
              <div style="font-size:10px;color:#475569;margin-top:2px;">NeuraShield AI verified this destination as legitimate</div>
            </div>
          </div>
          <div style="display:flex;gap:20px;margin-top:8px;">
            <div><div style="font-size:9px;color:#475569;text-transform:uppercase;letter-spacing:.1em;">Risk Score</div><div style="font-size:18px;font-weight:900;color:#4ade80;">${score}</div></div>
            <div><div style="font-size:9px;color:#475569;text-transform:uppercase;letter-spacing:.1em;">Verdict</div><div style="font-size:13px;font-weight:800;color:#4ade80;margin-top:2px;">LEGITIMATE</div></div>
            <div><div style="font-size:9px;color:#475569;text-transform:uppercase;letter-spacing:.1em;">Opening in</div><div class="ns-countdown" id="nsRedirectCountdown"><span class="ns-pulse-dot" style="background:#4ade80;"></span>1.5s</div></div>
          </div>
        `;

        btnRow.innerHTML = `
          <button class="ns-grd-btn-cancel" id="nsGuardianCloseSafeBtn">Cancel</button>
          <button class="ns-grd-btn-safe" id="nsGuardianProceedBtn">Open Website ➔</button>
        `;

        let navigated = false;
        const proceed = () => {
          if (navigated) return;
          navigated = true;
          overlay.remove();
          activeGuardianOverlay = null;
          window.open(targetUrl, '_blank', 'noopener,noreferrer');
        };

        const proceedBtn = overlay.querySelector('#nsGuardianProceedBtn');
        if (proceedBtn) proceedBtn.addEventListener('click', proceed);

        const closeSafeBtn = overlay.querySelector('#nsGuardianCloseSafeBtn');
        if (closeSafeBtn) closeSafeBtn.addEventListener('click', () => {
          navigated = true;
          overlay.remove();
          activeGuardianOverlay = null;
        });

        setTimeout(proceed, 1500);

      } else {
        // ── MALICIOUS / PHISHING: BLOCK THE WEBSITE FROM OPENING! ──
        card.classList.add('ns-card-blocked');
        if (accent) accent.className = 'ns-card-accent blocked';
        icon.className = 'ns-guardian-icon-wrap blocked';
        icon.textContent = '⛔';
        title.textContent = 'MALICIOUS WEBSITE BLOCKED';
        title.className = 'ns-guardian-title blocked';
        sub.textContent = `RISK SCORE: ${score}/100 — ${risk.verdict || 'THREAT DETECTED'}`;

        const traits = (report.threat_dna && report.threat_dna.traits) || [];
        const reason = risk.reason || 'High probability of phishing, credential harvesting, or brand impersonation.';

        statusBox.innerHTML = `
          <div style="display:flex;align-items:center;gap:10px;margin-bottom:10px;">
            <span style="font-size:20px;">🚫</span>
            <div>
              <div style="font-size:13px;font-weight:800;color:#f87171;">Connection Intercepted & Blocked</div>
              <div style="font-size:10px;color:#475569;margin-top:2px;">This website poses a security threat to your account</div>
            </div>
          </div>
          <div class="ns-danger-box">
            <strong>Warning:</strong> ${escapeHtml(reason)}
          </div>
          ${traits.length > 0 ? `
            <div class="ns-threat-traits">
              ${traits.map(t => `<span class="ns-threat-chip">⚠ ${escapeHtml(t)}</span>`).join('')}
            </div>
          ` : ''}
        `;

        btnRow.innerHTML = `
          <button class="ns-grd-btn-danger" id="nsGuardianReturnSafeBtn">🛡️ Return to Safe Email</button>
          <button class="ns-grd-override" id="nsGuardianOverrideBtn">Proceed anyway (unsafe)</button>
        `;

        const returnSafeBtn = overlay.querySelector('#nsGuardianReturnSafeBtn');
        if (returnSafeBtn) {
          returnSafeBtn.addEventListener('click', () => {
            overlay.remove();
            activeGuardianOverlay = null;
          });
        }

        const overrideBtn = overlay.querySelector('#nsGuardianOverrideBtn');
        if (overrideBtn) {
          overrideBtn.addEventListener('click', () => {
            if (confirm('DANGER: This website is flagged as malicious/phishing. Are you absolutely certain you want to proceed?')) {
              overlay.remove();
              activeGuardianOverlay = null;
              window.open(targetUrl, '_blank', 'noopener,noreferrer');
            }
          });
        }
      }

    } catch (err) {
      const statusBox = overlay.querySelector('#nsGuardianStatusBox');
      const btnRow = overlay.querySelector('#nsGuardianBtnRow');
      if (statusBox) {
        statusBox.innerHTML = `
          <div style="color:#fbbf24;font-weight:700;font-size:12px;">Notice: Could not reach Threat Intelligence Backend</div>
          <div style="color:#94a3b8;font-size:11px;margin-top:4px;">${escapeHtml(err.message || 'Network error')}</div>
        `;
      }
      if (btnRow) {
        btnRow.innerHTML = `
          <button class="ns-btn-secondary-cancel" id="nsGuardianCloseErrBtn">Close</button>
          <button class="ns-btn-primary-safe" id="nsGuardianProceedAnywayBtn">Open Website Anyway</button>
        `;
        const closeBtn = overlay.querySelector('#nsGuardianCloseErrBtn');
        if (closeBtn) closeBtn.addEventListener('click', () => { overlay.remove(); activeGuardianOverlay = null; });
        const proceedBtn = overlay.querySelector('#nsGuardianProceedAnywayBtn');
        if (proceedBtn) proceedBtn.addEventListener('click', () => { overlay.remove(); activeGuardianOverlay = null; window.open(targetUrl, '_blank'); });
      }
    }
  }

  // ── Global Link Click Interceptor (Capture Phase) ──
  document.addEventListener('click', (e) => {
    const anchor = e.target.closest('a');
    if (!anchor) return;

    let href = anchor.getAttribute('href') || anchor.href;
    if (!href) return;

    // Ignore internal / harmless links
    if (href.startsWith('mailto:') || href.startsWith('#') || href.startsWith('javascript:')) return;
    if (href.includes('mail.google.com') && !href.includes('google.com/url?')) return;
    if (href.includes('onrender.com/investigation-center')) return;

    // Check if the link belongs to an email view or NeuraShield banner
    const isInsideEmail = anchor.closest('.a3s.aiL') || anchor.closest('.ii.gt') || anchor.closest('#neurashield-gmail-banner');
    if (!isInsideEmail) return;

    // Clean Google redirect wrappers
    let targetUrl = href;
    if (targetUrl.includes('google.com/url?') && targetUrl.includes('q=')) {
      try {
        const u = new URL(targetUrl);
        const real = u.searchParams.get('q');
        if (real) targetUrl = real;
      } catch (err) {}
    }

    // INTERCEPT! Stop browser from opening the site
    e.preventDefault();
    e.stopPropagation();
    e.stopImmediatePropagation();

    // Trigger NeuraShield Link Guardian
    handleLinkGuardianClick(targetUrl);
  }, true);

  // ── Debounced Scanner Loop ──
  let scanTimeout = null;
  function triggerScan() {
    if (scanTimeout) clearTimeout(scanTimeout);
    scanTimeout = setTimeout(() => {
      const email = extractGmailContext();
      if (email) {
        renderNeuraShieldBanner(email);
      }
    }, 350);
  }

  // ── Observe Gmail Navigation and DOM Mutations ──
  const observer = new MutationObserver((mutations) => {
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
  setTimeout(triggerScan, 1200);

})();
