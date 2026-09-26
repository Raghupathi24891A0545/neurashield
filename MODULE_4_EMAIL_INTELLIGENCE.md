# MODULE 4 — Email Intelligence

Status (capability registry): **IN_DEVELOPMENT** until a validated e-mail text model exists
(`model/email_intelligence/email_text_model.pkl` + `email_model_card.json`). It flips to ACTIVE automatically when both exist.

## What it answers
Who **claims** to have sent the message · what **technical evidence** supports the claim · what the message **contains** ·
what could be **verified** now · what **cannot** be verified.

## Pipeline (each stage is recorded with real status and duration)
`validation → safe parsing → authentication evidence → header & sender-consistency → sender-domain DNS → content → URL extraction
→ URL Intelligence (Module 1, per link, ≤15) → Domain Intelligence (Module 2, sender + link domains, ≤5, parallel)
→ Webpage Intelligence (Module 3, opt-in, ≤3, SSRF-guarded) → attachment static analysis → rules (EML-001…032) → text model (if validated)
→ risk fusion → Threat DNA → relationship graph → explainability payload → persisted investigation → universal report`

## Files
| Path | Purpose |
|---|---|
| `model/email_intelligence/parser.py` | Size/format validation, RFC 5322/MIME parsing, Received parsing, body-only mode |
| `authentication.py` | Reads SPF/DKIM/DMARC from Authentication-Results / Received-SPF (never re-verified, never invented) |
| `identity.py` | Display name / From / Reply-To / Return-Path / Sender / Message-ID / DKIM d= comparison, brand claims |
| `sender_dns.py` | Live DNS: domain exists, MX, SPF record, DMARC policy. Mailbox existence is always NOT_VERIFIED |
| `content.py` | Language categories, static HTML inspection, URL extraction, anchor-text vs destination mismatch |
| `attachments.py` | Filename/extension/MIME/size/hashes, magic bytes, ZIP listing, VBA project, PDF markers — static only |
| `rules.py` | Rule catalog EML-001…032 with severity, evidence, contribution, limitation |
| `ml.py` | Loads a validated text model if (and only if) it exists |
| `analyzer.py` | Orchestration, fusion, coverage, confidence, Threat DNA, graph, timeline, recommendations, evidence package |
| `backend/email_routes.py` | `/email-intelligence`, `/api/email/investigate`, `/api/capabilities`, `/investigations`, `/api/investigations`, persistence |
| `backend/capabilities.py` | Single source of truth for module status |
| `frontend/email_intelligence.html`, `investigation_report.html`, `investigations.html`, `ns_investigation.{css,js}`, `ns_capabilities.js` | UI |

## API
`POST /api/email/investigate` (login required) — multipart `email_file` (.eml/.txt ≤ 10 MB) **or** `raw_email` (form/JSON);
options `domain_intel` (default on), `fetch_linked_pages` (default off). Errors: `{"error":{"code","message"}}` with
400 INVALID_INPUT · 401 AUTHENTICATION_REQUIRED · 413 CONTENT_TOO_LARGE · 415 UNSUPPORTED_FORMAT · 422 PARSER_ERROR ·
429 RATE_LIMITED (20 / 5 min / user) · 500 ANALYSIS_UNAVAILABLE.

## Scores (kept separate)
- **Risk score** — probabilistic OR of rule contributions `100·(1−Π(1−cᵢ/100))`; informational rules contribute 0.
  With a validated model: `0.75·rule_risk + 0.25·ML%`.
- **ML probability** — `null` + reason until a validated model exists.
- **Evidence coverage** — obtained ÷ applicable evidence sources (N/A and opt-in excluded).
- **Confidence** — `0.35 + 0.60·coverage`, −0.10 without headers, −0.10 if low risk but auth unknown, bounded 15–95%.

## Privacy
Raw messages are not stored. The persisted investigation keeps headers, extracted URLs, attachment hashes and a
≤1,500-character text excerpt. E-mail investigations are visible only to the user who ran them.
