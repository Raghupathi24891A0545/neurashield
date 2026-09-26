# NeuraShield — Implementation Map (Phase 1 audit)

Audit date: 2026-09-23. Audited before any change. A code backup was written to
`Desktop/C13_Project (1)/_neurashield_backups/code_before_module4_*.tgz`
(code + frontend + docs; excludes `data/`, `dataset/`, `.git`, `*.pkl`).

## Layout
| Path | What it is |
|---|---|
| `app.py` (repo root) | Vercel/root entry → imports `backend.app` |
| `backend/app.py` (2,640 lines) | Single Flask app: routes, DB init, investigation builder, report payload, auth |
| `model/feature_extraction.py`, `model/rule_engine.py`, `model/phishing_model.pkl` | Module 1 — URL features, rules, Random Forest (82 MB pickle, sklearn ≥ 1.8) |
| `model/domain_intelligence/*` | Module 2 — collector (DNS/RDAP/WHOIS/TLS), rules (DOM-xxx), features, LogisticRegression model, `risk_fusion.py` |
| `model/webpage_intelligence/*` | Module 3 — SSRF-guarded fetcher, optional Playwright fetcher, static analyzer, WEB rules, identity consistency |
| `frontend/*.html` + `neurashield.css` | Jinja-served static pages (landing, login, register, user/admin dashboards, domain, webpage, report, upload, warning) |
| `data/`, `dataset/` | Dataset 1 (URL CSV, 632k rows) and Dataset 2 (Tranco + PhishTank domain pipeline) |
| `scripts/dataset/*` | Dataset 2 build/clean/feature/validation scripts |
| `backend/database.db` | SQLite: `users`, `logs`, `domain_analyses`, `webpage_analyses` |

## Routes (before changes)
`/` landing · `/login` GET/POST · `/register` · `/logout` · `/dashboard` · `/admin` · `/upload` + `/api/bulk-scan` ·
`/domain-intelligence` + `/api/domain/analyze` · `/webpage-intelligence` + `/api/webpage/investigate` ·
`/api/scan` (= `/api/demo-scan`) · `/api/investigation/<id>` · `/report?id=` · `/warning`.

## Module status found
| Module | Status | Notes |
|---|---|---|
| 1 URL Intelligence | IMPLEMENTED | Rules + RF + composite risk. See issues U1–U3 |
| 2 Domain Intelligence | IMPLEMENTED | DNS/IP/RDAP/WHOIS/NS/TLS, DOM rules (DOM-006/008 already informational), LR model |
| 3 Webpage Intelligence | IMPLEMENTED | Existence pipeline + static analysis. See issues W1–W3 |
| 4 Email Intelligence | NOT IMPLEMENTED | Only disabled nav items / "Planned" cards |
| 5 QR, 6 Brand (standalone) | NOT IMPLEMENTED | Brand identity check exists only inside Module 3 (`identity_consistency.py`) |
| Risk fusion | PARTIAL | `domain_intelligence/risk_fusion.py` fuses URL+domain+webpage |
| Threat DNA | PARTIAL | Hash of evidence strings; no similarity search |
| Threat graph | PARTIAL | Built per investigation (`_generate_threat_relationship_graph`) |
| Investigation store | PARTIAL | In-memory LRU (50) only — lost on restart |
| Full report | IMPLEMENTED (URL-centric) | `report.html`, hard-wired to URL fields |
| Resilience Lab, Self-Audit, Analytics, News, Evidence workflow portal link | NOT IMPLEMENTED / partial export only |

## Issues found (violations of the master prompt)
| ID | Severity | Finding | Where |
|---|---|---|---|
| S1 | Critical | Passwords stored and compared in **plaintext** | `register()`, `login()` |
| S2 | High | Hard-coded Flask `secret_key = "secretkey"` | `backend/app.py` |
| F1 | Critical (Golden Rule §2) | **Hard-coded fabricated results** for `auth-portal-update.demo`, `support-login-apple.demo`, `icloud-session-check.demo`, `account-security-microsoft.demo`, `nonexistent-phishing-host.org` (fake HTML, fake verdicts, fake Threat DNA, judge scripts) returned by the real `/api/webpage/investigate` | `api_webpage_investigate()` + showcase cards in `webpage_intelligence.html` |
| F2 | Medium | `/warning` defaults to a fabricated target/threat when called without params | `warning_page()` |
| W1 | High (SSRF) | Redirects are followed by `requests` **before** each hop is validated, so an internal redirect target is contacted before the check runs; DNS is re-resolved after validation (rebinding window) | `webpage_intelligence/fetcher.py` |
| U1 | Medium (false positive) | Any digit in the domain → `"Phishing (rule match)"` and ML skipped (e.g. `1password.com`, `office365.com`) while composite risk stays low → contradictory verdict | `classify_url()` |
| U2 | Low | ML probability shown as `100.0` — reads as certainty | `classify_url()` |
| D1 | Medium (ML claims) | Domain model test set is 12 rows (6/6) with reported 100% metrics; UI text says "Calibrated via 5-fold cross-validation" | `training_report.json`, `api_scan()` |
| X1 | High (XSS) | `report.html` and module pages build HTML with unescaped `innerHTML` interpolation. Acceptable-ish for URL data; **unsafe for email data** (attacker controls subject/From/body) | frontend |
| C1 | Medium (stale status) | Landing shows Webpage as "Advanced Layer"/planned while it is implemented; status strings are hand-written in 3+ places, no single source of truth | `landing.html`, `user_dashboard.html` |
| R1 | Low | `report.html` hard-codes text like "All 18 deterministic checks passed" and fallback domain `target.com` | `report.html` |

## Environment notes
- The Linux shell used for this work has an HTTP proxy but **no DNS resolution**, so live DNS/RDAP/TLS/webpage retrieval could not be exercised here; those paths return truthful `DNS_FAILURE`/`NETWORK_ERROR`. They must be demo-verified on the Mac.
- Zenodo, Apache SpamAssassin and Hugging Face are **not reachable** from this environment (proxy refuses). GitHub is reachable.

## Plan executed in this pass
1. Module 4 Email Intelligence as a new package `model/email_intelligence/` that feeds the shared investigation store/report.
2. Central capability registry (`backend/capabilities.py`) + `/api/capabilities`; landing/dashboard read it.
3. Data-driven universal report renderer (`frontend/investigation_report.html`) used for email investigations; the existing URL report is kept unchanged.
4. Security fixes S1, S2, F1 (gated behind an explicit opt-in flag and labelled SIMULATED), F2, W1, U1.
5. Email dataset download/audit/training scripts with truthful status reporting.
