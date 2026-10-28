/**
 * NeuraShield Chrome Extension — API Client Module
 * Communicates with the local or enterprise NeuraShield Cybersecurity Backend.
 */

const NeuraShieldAPI = (() => {
  const DEFAULT_BACKEND = 'https://neurashield-kp6p.onrender.com';

  async function getBackendUrl() {
    try {
      if (typeof chrome !== 'undefined' && chrome.storage && chrome.storage.local) {
        const stored = await chrome.storage.local.get(['ns_backend_url']);
        if (stored && stored.ns_backend_url) {
          return stored.ns_backend_url.replace(/\/+$/, '');
        }
      }
    } catch (e) {
      // Fallback to default
    }
    return DEFAULT_BACKEND;
  }

  async function checkStatus() {
    const base = await getBackendUrl();
    try {
      const res = await fetch(`${base}/api/extension/status`, {
        method: 'GET',
        headers: { 'Accept': 'application/json' }
      });
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      const data = await res.json();
      return { online: true, url: base, ...data };
    } catch (err) {
      return { online: false, url: base, error: 'NeuraShield backend unavailable' };
    }
  }

  async function verifySender(payload) {
    const base = await getBackendUrl();
    try {
      const res = await fetch(`${base}/api/institutions/verify-sender`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Accept': 'application/json'
        },
        body: JSON.stringify(payload)
      });
      if (!res.ok) throw new Error(`Server returned HTTP ${res.status}`);
      return await res.json();
    } catch (err) {
      return {
        status: 'BACKEND_OFFLINE',
        verdict: 'UNKNOWN',
        error: `Could not connect to NeuraShield backend at ${base}. Please ensure backend is running.`
      };
    }
  }

  async function investigateEmail(payload) {
    const base = await getBackendUrl();
    try {
      const res = await fetch(`${base}/api/extension/email/investigate`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Accept': 'application/json'
        },
        body: JSON.stringify(payload)
      });
      if (!res.ok) {
        const errJson = await res.json().catch(() => ({}));
        throw new Error(errJson.error || `HTTP ${res.status}`);
      }
      return await res.json();
    } catch (err) {
      return {
        error: 'INVESTIGATION_FAILED',
        backend_offline: true,
        message: `Failed to reach NeuraShield backend at ${base}. Error: ${err.message}`
      };
    }
  }

  async function investigateUrl(targetUrl) {
    const base = await getBackendUrl();
    try {
      const res = await fetch(`${base}/api/extension/url/investigate`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Accept': 'application/json'
        },
        body: JSON.stringify({ url: targetUrl })
      });
      if (!res.ok) {
        const errJson = await res.json().catch(() => ({}));
        throw new Error(errJson.error || `HTTP ${res.status}`);
      }
      return await res.json();
    } catch (err) {
      return {
        error: 'INVESTIGATION_FAILED',
        backend_offline: true,
        message: `Failed to reach NeuraShield backend at ${base}. Error: ${err.message}`
      };
    }
  }

  return {
    getBackendUrl,
    checkStatus,
    verifySender,
    investigateEmail,
    investigateUrl
  };
})();

if (typeof module !== 'undefined' && module.exports) {
  module.exports = NeuraShieldAPI;
}
