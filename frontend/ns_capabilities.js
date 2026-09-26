/* Applies the central capability registry (/api/capabilities) to any page.
   Markup contract:
     data-cap-badge="email"  → element text/class set to ACTIVE / IN DEVELOPMENT / COMING SOON
     data-cap-node="email"   → class 'active' when ACTIVE, 'planned' otherwise
     data-cap-link="email"   → href set to the module route when usable, disabled otherwise
   Static fallback text in the HTML is overwritten, so status can never go stale. */
(function () {
  const LABEL = { ACTIVE: 'Active', IN_DEVELOPMENT: 'In development', COMING_SOON: 'Coming soon' };
  function apply(caps) {
    const by = Object.fromEntries((caps.modules || []).map((m) => [m.key, m]));
    document.querySelectorAll('[data-cap-badge]').forEach((el) => {
      const m = by[el.getAttribute('data-cap-badge')]; if (!m) return;
      el.className = m.status === 'ACTIVE' ? 'ns-badge ns-badge-cyan' : 'ns-planned-tag';
      el.innerHTML = m.status === 'ACTIVE' ? '<span class="dot"></span> Active' : (m.status === 'IN_DEVELOPMENT' ? '◐ In development' : '⏳ Coming soon');
      if (m.limitations && m.limitations.length) el.title = m.limitations.join(' ');
    });
    document.querySelectorAll('[data-cap-node]').forEach((el) => {
      const m = by[el.getAttribute('data-cap-node')]; if (!m) return;
      el.classList.remove('active', 'planned'); el.classList.add(m.status === 'ACTIVE' ? 'active' : 'planned');
      el.title = LABEL[m.status] || m.status;
    });
    document.querySelectorAll('[data-cap-link]').forEach((el) => {
      const m = by[el.getAttribute('data-cap-link')]; if (!m) return;
      if (m.route && m.status !== 'COMING_SOON') { el.setAttribute('href', m.route); el.style.opacity = ''; el.style.cursor = ''; el.removeAttribute('aria-disabled'); }
      else { el.removeAttribute('href'); el.style.opacity = '0.4'; el.style.cursor = 'not-allowed'; el.setAttribute('aria-disabled', 'true'); }
    });
    document.querySelectorAll('[data-cap-text]').forEach((el) => {
      const m = by[el.getAttribute('data-cap-text')]; if (m) el.textContent = m.summary;
    });
  }
  fetch('/api/capabilities').then((r) => r.json()).then(apply).catch(() => {});
})();
