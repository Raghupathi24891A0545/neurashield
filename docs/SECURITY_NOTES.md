# Security notes (changes made on 2026-09-23)

| Area | Before | After |
|---|---|---|
| Passwords | Stored & compared in plaintext | `werkzeug` scrypt hashes; legacy plaintext rows verified in constant time and upgraded on next login; min 8-char access code on register |
| Session key | `"secretkey"` | `NEURASHIELD_SECRET_KEY` env var, else random 256-bit key persisted as `.neurashield_secret_key` (0600) next to the DB; HttpOnly + SameSite=Lax cookies; session cleared on login |
| Flask debugger | `debug=True` in launchers | Only with `FLASK_DEBUG=1` |
| Webpage fetch redirects (SSRF) | `requests` followed redirects first, validated afterwards | Manual redirect loop: every hop validated **before** connecting; connected peer IP checked when no proxy is in use |
| Simulated demo results | `.demo` targets returned hard-coded fake analyses from the real API | Disabled unless `NEURASHIELD_SIMULATED_DEMOS=1`; responses carry `simulated: true` + banner; showcase cards hidden otherwise |
| `/warning` | Rendered a fabricated default target/threat | Redirects home unless a real target and threat are supplied |
| URL rule fast-path | Any digit in hostname ⇒ "Phishing (rule match)" | Only homograph or raw-IP host short-circuit; digits remain an ML feature |
| E-mail uploads | n/a | Login required, 10 MB cap, extension/binary checks, rate limit, filename never used as a path, nothing executed or rendered, all UI output HTML-escaped |
| E-mail report access | n/a | Owner-only (404 for other users) |

Known remaining risks: the Playwright "Deep Dynamic Sandbox" fetcher (`headless_fetcher.py`) was not re-audited for SSRF;
older pages (`report.html`, module pages) still build HTML with unescaped `innerHTML` for URL/domain data; no CSRF tokens on forms.
