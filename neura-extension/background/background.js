/**
 * NeuraShield Chrome Extension — Background Service Worker (Manifest V3)
 * Handles background state, message brokering, badge indicators, and API delegation.
 */

let activeEmailContext = null;
let lastInvestigationResult = null;

chrome.runtime.onInstalled.addListener(() => {
  console.log('[NeuraShield] Extension installed and active.');
  chrome.storage.local.set({
    ns_backend_url: 'https://neurashield-kp6p.onrender.com',
    installed_at: new Date().toISOString()
  });
});

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
    } catch (e) {}

    sendResponse({ success: true });
    return false; // Synchronous response
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

    try {
      const riskLevel = (message.payload && message.payload.risk && message.payload.risk.level) || 'INFO';
      if (riskLevel === 'CRITICAL' || riskLevel === 'HIGH') {
        chrome.action.setBadgeText({ text: 'WARN' });
        chrome.action.setBadgeBackgroundColor({ color: '#ef4444' }); // red
      } else if (riskLevel === 'MEDIUM') {
        chrome.action.setBadgeText({ text: 'MED' });
        chrome.action.setBadgeBackgroundColor({ color: '#f59e0b' }); // amber
      } else {
        chrome.action.setBadgeText({ text: 'SAFE' });
        chrome.action.setBadgeBackgroundColor({ color: '#22c55e' }); // green
      }
    } catch (e) {}

    sendResponse({ success: true });
    return false; // Synchronous response
  }

  if (type === 'CLEAR_BADGE') {
    try {
      chrome.action.setBadgeText({ text: '' });
    } catch (e) {}
    sendResponse({ success: true });
    return false; // Synchronous response
  }

  sendResponse({ status: 'UNKNOWN_MESSAGE_TYPE' });
  return false;
});
