# Engineering completion report — Phase 1 audit + Module 4 (2026-09-23)

## 1. What was already present
Modules 1–3 (URL, Domain, Webpage) with rules, two models, partial fusion/DNA/graph, a URL-centric report, landing page,
dashboards, bulk CSV upload, SQLite. Full inventory and issues: `docs/IMPLEMENTATION_MAP.md`.

## 2. What was changed
- `backend/app.py`: password hashing + legacy upgrade, secret key, cookie flags, digit-in-domain false-positive fix,
  simulated-demo gating + labelling, `/warning` no longer fabricates, investigations persisted to DB, report dispatch for e-mail,
  owner-only access to e-mail investigations, Module 4 registration, debug off by default.
- `model/webpage_intelligence/fetcher.py`: redirect hops validated before connecting; peer-IP check.
- `frontend/landing.html`, `user_dashboard.html`, `domain_intelligence.html`, `webpage_intelligence.html`, `upload.html`: status badges/nodes
  driven by the capability registry; Email + Investigation Center navigation; stale "Webpage = planned" fixed; simulated showcase hidden.
- Launchers: `debug` only with `FLASK_DEBUG=1`; `RUN_MAC.command` installs from `requirements.txt`.

## 3. Newly implemented
Module 4 Email Intelligence (backend + page), central capability registry (`/api/capabilities`), persistent investigations +
Investigation Center (`/investigations`), data-driven universal report (`investigation_report.html`, used for e-mail),
e-mail Threat DNA with trait-similarity lookup, evidence graph, timeline, evidence package with cybercrime.gov.in link (never auto-submits).

## 4. Dataset changes
Folder structure `datasets/email_intelligence/...` created. **NOT DOWNLOADED**: zenodo.org and spamassassin.apache.org are blocked
from the environment used for this work (proxy 403; recorded in `checksums/download_manifest.json`). Download/verify, audit and
training scripts are ready in `scripts/email_dataset/` and were exercised end-to-end on a synthetic fixture set only.
Dataset 4's README states spam, scam and phishing were all merged into label 1 — it is excluded from phishing training by default.

## 5. Backend changes
New: `backend/email_routes.py`, `backend/capabilities.py`, `model/email_intelligence/*` (9 modules). Error schema `{"error":{"code","message"}}`.

## 6. Frontend changes
New: `email_intelligence.html`, `investigation_report.html`, `investigations.html`, `ns_investigation.css`, `ns_investigation.js`,
`ns_capabilities.js`. All e-mail-derived text is HTML-escaped. Checked at 1440 / 820 / 390 px (no horizontal scroll on the new pages).

## 7. Database changes (auto-migrated at start-up, additive only)
`investigations` (all investigation payloads, JSON) and `email_analyses` (e-mail summary row + DNA traits). Existing tables untouched;
existing plaintext passwords upgrade to hashes on each user's next successful login.

## 8. Security improvements
See `docs/SECURITY_NOTES.md`.

## 9. ML changes
No e-mail model trained (no real data). ML layer reports UNAVAILABLE with the reason; risk is rules-only and says so.
URL model: the digit-in-domain rule no longer overrides the model — note the RF model itself still scores some digit domains
(e.g. `1password.com`) as phishing; that is a model limitation to address when Module 1 is retrained.

## 10. Report architecture
`investigation_report.html` renders only populated sections from the investigation JSON (header, executive summary, brief, key findings,
target, per-layer sections, detection evidence, fusion, DNA, graph, timeline, security evidence, found / not verified / what to do,
interaction decision tree, final assessment, evidence package, PDF/JSON/CSV export). The legacy URL report is unchanged.

## 11. Tests performed
- `tests/test_email_intelligence.py`: **29 passed** (all 17 §60.9 cases + auth, persistence, owner isolation, password hashing,
  capability registry, simulated-demo gating, SSRF incl. redirect-before-connect).
- Existing `test_module3.py`: 16/16 pass where DNS is available (1 test needs live DNS).
- Live Domain Intelligence on the sender/link domains verified in a DNS-capable environment.
- Visual review of e-mail page, report, dashboard, landing badges at desktop/tablet/mobile.

## 12. Known limitations
Rules-only e-mail risk until datasets are downloaded and a model is validated · English-only language patterns · SPF/DKIM/DMARC
read, not re-verified · no .msg support · Playwright fetcher not re-audited for SSRF · legacy pages still use unescaped innerHTML ·
no CSRF tokens · `domain_intelligence.html` overflows horizontally at 390 px (pre-existing).

## 13. NOT IMPLEMENTED (this pass)
QR Security, standalone Brand Impersonation, Adversarial Resilience Lab, Model Self-Audit, Security & Model Analytics,
Cybersecurity News, cross-investigation graph view, landing-page redesign/Three.js hero rework, migration of the URL report to the
universal renderer. The capability registry shows these honestly as Coming soon / In development.

## 14. Exact commands (macOS Terminal)
```bash
cd ~/Desktop/"C13_Project (1)"/C13_Project
bash RUN_MAC.command                                  # start app → http://127.0.0.1:5000
# datasets (from the project folder):
cd C13_Project/Code/Phishing-Detection-System
../../../.venv_mac/bin/python scripts/email_dataset/download_datasets.py
../../../.venv_mac/bin/python scripts/email_dataset/audit_datasets.py
# read datasets/email_intelligence/reports/*.md, confirm LABEL_MAPPING.md, then:
../../../.venv_mac/bin/python scripts/email_dataset/train_email_baseline.py
# tests
../../../.venv_mac/bin/python -m pip install pytest && ../../../.venv_mac/bin/python -m pytest tests/test_email_intelligence.py -q
```

## 15. Demo flow (e-mail)
Log in → Email Intel → upload `tests/fixtures/email/legit_authenticated.eml` (DEMO 7: no significant indicators, auth pass)
→ upload `phish_paypal.eml` (DEMO 8: DMARC fail, Reply-To diversion, deceptive link, disguised HTML attachment → high risk)
→ View full report → Threat DNA / graph / evidence package → Investigation Center lists both.
Fixtures are synthetic; say so when presenting.

## 16. Migration steps
None manual. Start the app once: new tables are created. Optionally set `NEURASHIELD_SECRET_KEY`. Existing users log in normally
(their passwords are upgraded to hashes). To show the old hard-coded `.demo` showcase, set `NEURASHIELD_SIMULATED_DEMOS=1`
— results are then labelled SIMULATED.
