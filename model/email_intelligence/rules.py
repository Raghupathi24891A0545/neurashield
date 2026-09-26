"""Deterministic Email Intelligence rules (EML-xxx).

Every rule carries: id, name, severity, layer, evidence, explanation,
risk contribution (0-100 scale, combined by fusion — NOT summed), and a
limitation statement. INFORMATIONAL rules contribute 0."""
from datetime import datetime, timezone, timedelta
from typing import Any, Dict, List

from .common import registered_domain

SEVERITY_ORDER = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFORMATIONAL": 0}

CATALOG: Dict[str, Dict[str, Any]] = {
    "EML-001": ("Reply-To points to a different organisation", "MEDIUM", "identity", 15,
                "Replies would go to a different domain than the visible sender. Common in phishing and payment-diversion fraud; also used legitimately by some ticketing/newsletter systems."),
    "EML-002": ("Display name claims a brand the sending domain does not belong to", "HIGH", "identity", 28,
                "The name shown to the reader claims a known brand, but the actual From domain is not one of that brand's domains."),
    "EML-003": ("Display name contains a different e-mail address", "HIGH", "identity", 22,
                "The display name shows an address that differs from the real sender address — a common trick to fool mail clients that hide the real address."),
    "EML-004": ("SPF did not pass", "MEDIUM", "authentication", 12,
                "The receiving server reported that the sending server is not authorised by the envelope domain's SPF policy."),
    "EML-005": ("DKIM did not pass", "MEDIUM", "authentication", 12,
                "The receiving server reported that the DKIM signature could not be verified, or the message was altered."),
    "EML-006": ("DMARC failed", "HIGH", "authentication", 22,
                "Neither an aligned SPF nor an aligned DKIM pass was found for the From domain. This is the strongest authentication signal that the From domain was not the real sender."),
    "EML-007": ("Authentication results not available", "INFORMATIONAL", "authentication", 0,
                "No Authentication-Results header was present, so SPF/DKIM/DMARC outcomes are unknown. This is missing evidence, not malicious evidence."),
    "EML-008": ("Return-Path domain differs from From domain", "LOW", "identity", 4,
                "The bounce address belongs to another domain. Very common for legitimate bulk-mail providers; weak on its own."),
    "EML-009": ("Sender domain does not exist", "HIGH", "identity", 30,
                "DNS returned NXDOMAIN for the From domain, so no legitimate organisation can be sending mail from it."),
    "EML-010": ("Sender domain publishes no mail exchanger", "LOW", "identity", 6,
                "The From domain has no MX records, so replies to it cannot be delivered normally."),
    "EML-011": ("Link text shows a different domain than its real destination", "HIGH", "links", 26,
                "A link displays one web address but actually opens a different domain — a classic deception technique."),
    "EML-012": ("Link to a raw IP address", "MEDIUM", "links", 14,
                "Legitimate organisations rarely link to bare IP addresses."),
    "EML-013": ("Shortened link", "LOW", "links", 6,
                "URL shorteners hide the final destination."),
    "EML-014": ("Linked URL rated high risk by URL Intelligence", "HIGH", "links", 0,
                "Module 1 (URL Intelligence) rated at least one link as high risk. Contribution equals a share of that URL's risk score."),
    "EML-015": ("Executable or script attachment", "CRITICAL", "attachments", 40,
                "The attachment can run code when opened. Legitimate senders almost never e-mail executables."),
    "EML-016": ("Macro-capable Office attachment", "MEDIUM", "attachments", 12,
                "Macro-enabled documents can run code if the reader enables content."),
    "EML-017": ("VBA macro project present in Office attachment", "HIGH", "attachments", 24,
                "The Office file contains a VBA project, i.e. embedded macro code."),
    "EML-018": ("Disguised file extension", "HIGH", "attachments", 26,
                "The filename shows a document extension but the real extension/content is executable or HTML."),
    "EML-019": ("Attachment content does not match its extension", "MEDIUM", "attachments", 14,
                "The file's content signature differs from what the extension claims."),
    "EML-020": ("HTML / SVG attachment", "MEDIUM", "attachments", 14,
                "HTML attachments open locally in a browser and are frequently used as offline credential-harvesting pages."),
    "EML-021": ("Password-protected archive", "MEDIUM", "attachments", 12,
                "Encryption prevents security scanning; attackers use it to smuggle malware past filters."),
    "EML-022": ("Archive contains executable / disk image / HTML", "HIGH", "attachments", 28,
                "The archive lists a file type that can run code or open a local web page."),
    "EML-023": ("PDF with active-content markers", "MEDIUM", "attachments", 12,
                "The PDF declares JavaScript, auto-actions, launch actions or embedded files."),
    "EML-024": ("Credential request combined with pressure", "HIGH", "content", 22,
                "The text asks for passwords/codes or account verification AND applies urgency or threatens consequences."),
    "EML-025": ("Payment or financial request", "MEDIUM", "content", 10,
                "The text requests payment, gift cards, crypto or a change of bank details."),
    "EML-026": ("Multiple social-engineering patterns", "MEDIUM", "content", 10,
                "Three or more distinct manipulation categories appear together."),
    "EML-027": ("Form embedded in e-mail body", "HIGH", "html", 22,
                "The e-mail contains an HTML form; legitimate senders do not collect data inside the message."),
    "EML-028": ("Script or event handlers in e-mail HTML", "MEDIUM", "html", 10,
                "Mail clients do not run scripts; their presence indicates crafted or evasive HTML."),
    "EML-029": ("Hidden text in e-mail HTML", "LOW", "html", 6,
                "Invisible text is used to poison spam filters and hide content from the reader."),
    "EML-030": ("Message-ID domain differs from From domain", "INFORMATIONAL", "identity", 0,
                "Many legitimate services generate Message-IDs on their own domain; recorded for correlation only."),
    "EML-031": ("Date header missing or implausible", "LOW", "identity", 4,
                "The Date header is missing, unparseable, or more than a day in the future."),
    "EML-032": ("Multiple From addresses", "MEDIUM", "identity", 10,
                "More than one From address is unusual and can confuse mail clients."),
}

LIMITATIONS = {
    "identity": "Header values are claims made by the sender and can be forged.",
    "authentication": "Read from the receiving server's Authentication-Results; not re-verified by NeuraShield.",
    "links": "Based on URL/Domain Intelligence of the link as written; the final destination was not visited unless linked-page retrieval was enabled.",
    "attachments": "Static inspection of bytes and archive listings only; nothing was opened or executed.",
    "content": "Phrase patterns in English; other languages and image-only e-mails are not covered.",
    "html": "Static HTML inspection; the message was not rendered.",
}


def _rule(rule_id: str, evidence: str, contribution=None) -> Dict[str, Any]:
    name, sev, layer, contrib, expl = CATALOG[rule_id]
    return {"rule_id": rule_id, "name": name, "severity": sev, "layer": layer,
            "risk_contribution": contrib if contribution is None else contribution,
            "evidence": evidence, "explanation": expl, "limitation": LIMITATIONS[layer]}


def evaluate_email_rules(parsed, identity, auth, sender_dns, language, html, urls, url_results, attachments) -> List[Dict[str, Any]]:
    hits: List[Dict[str, Any]] = []
    cs = identity.get("claimed_sender") or {}
    from_reg = cs.get("registered_domain") or ""

    # ── identity ──
    for c in identity.get("comparisons", []):
        if c["field"] == "Reply-To" and c["relation"] == "DIFFERENT_DOMAIN":
            hits.append(_rule("EML-001", f"From: {cs.get('address')} · Reply-To: {c['value']}"))
            break
    for b in identity.get("brand_claims", []):
        if b["state"] == "INCONSISTENT":
            hits.append(_rule("EML-002", f"Display name '{cs.get('display_name')}' claims '{b['brand']}', "
                                         f"but From domain is {b['from_domain']} (expected one of: {', '.join(b['official_domains'][:4])})"))
            break
    if identity.get("display_name_embedded_mismatch"):
        hits.append(_rule("EML-003", f"Display name shows {identity['display_name_embedded_mismatch'][0]} but the real address is {cs.get('address')}"))
    dmarc_pass = (auth.get("dmarc") or {}).get("result") == "pass"
    for c in identity.get("comparisons", []):
        if c["field"] == "Return-Path" and c["relation"] == "DIFFERENT_DOMAIN":
            r = _rule("EML-008", f"Return-Path {c['value']} vs From {cs.get('address')}", 0 if dmarc_pass else None)
            if dmarc_pass:
                r["severity"] = "INFORMATIONAL"
                r["evidence"] += " (DMARC passed, so the From domain was authenticated via DKIM alignment)"
            hits.append(r)
            break
    for c in identity.get("comparisons", []):
        if c["field"] == "Message-ID domain" and c["relation"] == "DIFFERENT_DOMAIN":
            hits.append(_rule("EML-030", f"Message-ID domain {c['value']} vs From domain {cs.get('domain')}"))
            break
    if cs.get("multiple_from"):
        hits.append(_rule("EML-032", f"{len(parsed.get('from') or [])} From addresses"))
    if parsed.get("input_mode") == "RAW_EMAIL":
        if not parsed.get("date_raw"):
            hits.append(_rule("EML-031", "Date header absent"))
        elif not parsed.get("date"):
            hits.append(_rule("EML-031", f"Unparseable Date header: {parsed.get('date_raw')[:80]}"))
        else:
            try:
                dt = datetime.fromisoformat(parsed["date"])
                if dt - datetime.now(timezone.utc) > timedelta(days=1):
                    hits.append(_rule("EML-031", f"Date header is in the future: {parsed['date']}"))
            except Exception:
                pass

    de = (sender_dns or {}).get("domain_exists") or {}
    if de.get("state") == "VERIFIED" and de.get("value") is False:
        hits.append(_rule("EML-009", f"{sender_dns.get('domain')}: {de.get('reason')}"))
    mx = (sender_dns or {}).get("mx") or {}
    if de.get("value") is True and mx.get("state") == "VERIFIED" and mx.get("value") == []:
        hits.append(_rule("EML-010", f"{sender_dns.get('domain')}: {mx.get('reason')}"))

    # ── authentication ──
    if parsed.get("input_mode") == "RAW_EMAIL":
        if not auth.get("authentication_results_present") and not parsed.get("received_spf"):
            hits.append(_rule("EML-007", "No Authentication-Results or Received-SPF header in the message"))
        spf = (auth.get("spf") or {}).get("result")
        if spf in ("fail", "softfail", "permerror"):
            contrib = 12 if spf == "fail" else 6
            r = _rule("EML-004", f"spf={spf} (reported by {auth.get('authserv_id') or 'receiving server'}; domain {(auth.get('spf') or {}).get('domain')})", contrib)
            if spf != "fail":
                r["severity"] = "LOW"
            hits.append(r)
        dk = (auth.get("dkim") or {}).get("result")
        if dk in ("fail", "permerror"):
            hits.append(_rule("EML-005", f"dkim={dk} (domain {(auth.get('dkim') or {}).get('domain')})"))
        dm = (auth.get("dmarc") or {}).get("result")
        if dm == "fail":
            pol = (auth.get("dmarc") or {}).get("policy")
            hits.append(_rule("EML-006", f"dmarc=fail for header.from={(auth.get('dmarc') or {}).get('domain') or cs.get('domain')}" + (f" (policy {pol})" if pol else "")))

    # ── links ──
    if urls.get("anchor_mismatches"):
        m = urls["anchor_mismatches"][0]
        hits.append(_rule("EML-011", f"Link text '{m['displayed']}' opens {m['actual_url'][:160]}"
                                     + (f" (+{len(urls['anchor_mismatches']) - 1} more)" if len(urls["anchor_mismatches"]) > 1 else "")))
    ip_links = [u for u in urls.get("urls", []) if u["ip_host"] and not u["resource_only"]]
    if ip_links:
        hits.append(_rule("EML-012", ", ".join(u["url"][:120] for u in ip_links[:3])))
    short = [u for u in urls.get("urls", []) if u["shortener"]]
    if short:
        hits.append(_rule("EML-013", ", ".join(u["url"][:120] for u in short[:3])))
    risky = [r for r in (url_results or []) if (r.get("risk_score") or 0) >= 60]
    if risky:
        top = max(risky, key=lambda r: r.get("risk_score") or 0)
        contrib = int(round(min(40, (top["risk_score"] or 0) * 0.4)))
        hits.append(_rule("EML-014", f"{top['url'][:160]} → URL risk {top['risk_score']}/100 ({top.get('risk_level')})"
                                     + (f"; {len(risky) - 1} more high-risk link(s)" if len(risky) > 1 else ""), contrib))

    # ── attachments ──
    seen = set()
    for a in attachments.get("items", []):
        fl = {f["flag"]: f["detail"] for f in a.get("flags", [])}
        name = a.get("filename") or "(unnamed attachment)"
        mapping = [
            ("EXECUTABLE_EXTENSION", "EML-015"), ("EXECUTABLE_CONTENT", "EML-015"), ("DISK_IMAGE", "EML-015"),
            ("DOUBLE_EXTENSION", "EML-018"), ("RTL_OVERRIDE", "EML-018"),
            ("VBA_MACRO_PRESENT", "EML-017"), ("MACRO_ENABLED_OFFICE", "EML-016"), ("LEGACY_OFFICE", "EML-016"),
            ("TYPE_MISMATCH", "EML-019"), ("HTML_ATTACHMENT", "EML-020"), ("ENCRYPTED_ARCHIVE", "EML-021"),
            ("ARCHIVE_CONTAINS_EXECUTABLE", "EML-022"), ("PDF_ACTIVE_CONTENT", "EML-023"),
        ]
        for flag, rid in mapping:
            if flag in fl and (rid, name) not in seen:
                if rid == "EML-016" and "VBA_MACRO_PRESENT" in fl:
                    continue
                seen.add((rid, name))
                hits.append(_rule(rid, f"{name}: {fl[flag]}"))

    # ── content (combinations, never a single keyword) ──
    keys = set(language.get("category_keys", []))
    cred = keys & {"credential_request", "account_verification"}
    pressure = keys & {"urgency", "threat_language"}
    if cred and pressure:
        hits.append(_rule("EML-024", f"Categories present: {', '.join(sorted(cred | pressure))}"))
    if "payment_request" in keys and (pressure or "suspicious_instructions" in keys or identity.get("comparisons") and any(
            c["field"] == "Reply-To" and c["relation"] == "DIFFERENT_DOMAIN" for c in identity["comparisons"])):
        hits.append(_rule("EML-025", "Payment language together with pressure, unusual instructions, or a diverted Reply-To"))
    manip = keys - {"generic_greeting"}
    if len(manip) >= 3:
        hits.append(_rule("EML-026", f"{len(manip)} categories: {', '.join(sorted(manip))}"))

    # ── html ──
    if html.get("analysed"):
        if html.get("form_count"):
            pw = " with a password field" if html.get("password_inputs") else ""
            hits.append(_rule("EML-027", f"{html['form_count']} form(s){pw}; action: {html['forms'][0]['action'] or '(none)'}"))
        if html.get("script_count") or html.get("event_handler_attributes"):
            hits.append(_rule("EML-028", f"{html.get('script_count', 0)} <script> element(s), {html.get('event_handler_attributes', 0)} on* handler attribute(s)"))
        if html.get("hidden_text_blocks"):
            hits.append(_rule("EML-029", f"{len(html['hidden_text_blocks'])} hidden text block(s), e.g. '{html['hidden_text_blocks'][0][:80]}'"))

    hits.sort(key=lambda r: (-SEVERITY_ORDER.get(r["severity"], 0), -r["risk_contribution"]))
    return hits
