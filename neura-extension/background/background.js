/**
 * NeuraShield Chrome Extension — Background Service Worker (Manifest V3)
 * Handles background state, message brokering, badge indicators, and API delegation.
 */

let activeEmailContext = null;
let lastInvestigationResult = null;
const evaluatedTargets = new Map();

chrome.runtime.onInstalled.addListener(() => {
  console.log('[NeuraShield] Extension installed and active.');
  chrome.storage.local.set({
    ns_backend_url: 'http://127.0.0.1:5000',
    installed_at: new Date().toISOString()
  });
});

/**
 * Update Chrome Extension toolbar badge:
 * If risk -> displays 'RISK' in Red / Amber.
 * If safe -> displays 'SAFE' in Green.
 */
function setVerificationBadge(payload, tabId) {
  try {
    if (!payload) {
      chrome.action.setBadgeText({ text: '' });
      if (tabId) chrome.action.setBadgeText({ text: '', tabId });
      return;
    }

    const riskObj = payload.risk || payload.risk_assessment || {};
    const riskLevel = String(riskObj.level || riskObj.risk_level || '').toUpperCase();
    const verdict = String(riskObj.verdict || payload.verdict || '').toLowerCase();
    const score = Number(riskObj.score ?? riskObj.composite_score ?? 0);

    const hasRisk = (
      riskLevel === 'CRITICAL' ||
      riskLevel === 'HIGH' ||
      riskLevel === 'MEDIUM' ||
      verdict.includes('phish') ||
      verdict.includes('susp') ||
      verdict.includes('warn') ||
      score >= 30
    );

    // Strictly enforce: "if risk show risk and safe show safe"
    const text = hasRisk ? 'RISK' : 'SAFE';
    const color = hasRisk
      ? (riskLevel === 'CRITICAL' || riskLevel === 'HIGH' || verdict.includes('phish') || score >= 60 ? '#ef4444' : '#f59e0b')
      : '#22c55e';

    chrome.action.setBadgeText({ text });
    chrome.action.setBadgeBackgroundColor({ color });

    if (tabId) {
      chrome.action.setBadgeText({ text, tabId });
      chrome.action.setBadgeBackgroundColor({ color, tabId });
    }
  } catch (err) {
    console.error('[NeuraShield] Badge update error:', err);
  }
}

// Listen for messages from content scripts and popup
chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (!message || !message.type) {
    sendResponse({ error: 'INVALID_MESSAGE' });
    return false;
  }
  const type = message.type;

  if (type === 'GMAIL_EMAIL_OPENED') {
    activeEmailContext = message.payload;
    chrome.storage.local.set({ active_email: message.payload }, () => {});

    // Update extension badge to indicate an email is ready for investigation
    try {
      chrome.action.setBadgeText({ text: 'SCAN' });
      chrome.action.setBadgeBackgroundColor({ color: '#06b6d4' }); // cyan
      if (sender && sender.tab && sender.tab.id) {
        chrome.action.setBadgeText({ text: 'SCAN', tabId: sender.tab.id });
        chrome.action.setBadgeBackgroundColor({ color: '#06b6d4', tabId: sender.tab.id });
      }
    } catch (e) {}

    sendResponse({ success: true });
    return false;
  }

  if (type === 'GET_ACTIVE_EMAIL') {
    if (activeEmailContext) {
      sendResponse({ email: activeEmailContext, lastResult: lastInvestigationResult });
      return false;
    } else {
      chrome.storage.local.get(['active_email', 'last_result'], (items) => {
        try {
          sendResponse({
            email: items.active_email || null,
            lastResult: items.last_result || null
          });
        } catch (e) {
          // Ignored if channel closed
        }
      });
      return true; // Keep message channel open for async response
    }
  }

  if (type === 'STORE_INVESTIGATION_RESULT') {
    lastInvestigationResult = message.payload;
    chrome.storage.local.set({ last_result: message.payload }, () => {});

    // Cache target result for active navigation
    if (message.payload && message.payload.target) {
      const t = message.payload.target;
      const key = (t.host || t.url || t.display || '').toLowerCase();
      if (key) evaluatedTargets.set(key, message.payload);
    }

    const callerTabId = sender && sender.tab && sender.tab.id ? sender.tab.id : null;
    setVerificationBadge(message.payload, callerTabId);

    // Also update current active tab directly
    chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
      if (tabs && tabs[0] && tabs[0].id) {
        setVerificationBadge(message.payload, tabs[0].id);
      }
    });

    sendResponse({ success: true });
    return false;
  }

  if (type === 'CLEAR_BADGE') {
    try {
      chrome.action.setBadgeText({ text: '' });
      if (sender && sender.tab && sender.tab.id) {
        chrome.action.setBadgeText({ text: '', tabId: sender.tab.id });
      }
    } catch (e) {}
    sendResponse({ success: true });
    return false;
  }

  sendResponse({ status: 'UNKNOWN_MESSAGE_TYPE' });
  return false;
});

// Update badge when user navigates or switches tabs
chrome.tabs.onUpdated.addListener((tabId, changeInfo, tab) => {
  if (changeInfo.status === 'loading' && tab && tab.url) {
    const url = tab.url;
    if (url.includes('mail.google.com')) {
      chrome.action.setBadgeText({ text: 'SCAN', tabId });
      chrome.action.setBadgeBackgroundColor({ color: '#06b6d4', tabId });
    } else {
      let matchedResult = null;
      try {
        const parsed = new URL(url);
        for (const [key, res] of evaluatedTargets.entries()) {
          if (url.includes(key) || key.includes(parsed.hostname)) {
            matchedResult = res;
            break;
          }
        }
      } catch (_) {}

      if (matchedResult) {
        setVerificationBadge(matchedResult, tabId);
      } else {
        // Clear badge on uninspected URL to prevent stale badge
        chrome.action.setBadgeText({ text: '', tabId });
      }
    }
  }
});

chrome.tabs.onActivated.addListener((activeInfo) => {
  chrome.tabs.get(activeInfo.tabId, (tab) => {
    if (chrome.runtime.lastError || !tab || !tab.url) return;
    if (tab.url.includes('mail.google.com')) {
      chrome.action.setBadgeText({ text: 'SCAN', tabId: tab.id });
      chrome.action.setBadgeBackgroundColor({ color: '#06b6d4', tabId: tab.id });
    } else {
      let matchedResult = null;
      try {
        const parsed = new URL(tab.url);
        for (const [key, res] of evaluatedTargets.entries()) {
          if (tab.url.includes(key) || key.includes(parsed.hostname)) {
            matchedResult = res;
            break;
          }
        }
      } catch (_) {}

      if (matchedResult) {
        setVerificationBadge(matchedResult, tab.id);
      } else {
        chrome.action.setBadgeText({ text: '', tabId: tab.id });
      }
    }
  });
});
