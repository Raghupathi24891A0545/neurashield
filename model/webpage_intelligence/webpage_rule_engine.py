"""
NEURASHIELD — MODULE 3: WEBPAGE SECURITY RULE ENGINE
12 explainable security rules for webpage-level threat detection.
Each rule produces: ID, title, severity, description, evidence, why_it_matters, confidence.
"""

from typing import Dict, Any, List
from datetime import datetime


def evaluate_webpage_rules(
    webpage_analysis: Dict[str, Any],
    fetch_result: Dict[str, Any],
    page_url: str = "",
) -> Dict[str, Any]:
    """
    Evaluate all 12 webpage security rules against the analysis results.
    Returns structured rule evaluation with evidence and risk score.
    """
    # If webpage could not be retrieved, do NOT evaluate rules or generate fabricated findings
    if webpage_analysis.get("webpage_status") == "UNAVAILABLE" or webpage_analysis.get("status") == "UNAVAILABLE":
        return {
            "status": "UNAVAILABLE",
            "webpage_status": "UNAVAILABLE",
            "reason": webpage_analysis.get("reason", "FETCH_FAILURE"),
            "message": "Webpage could not be retrieved, so webpage-level analysis was not performed.",
            "rules_hit": [],
            "rule_count": 0,
            "rules_by_severity": {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0},
            "risk_score": 0,
            "webpage_risk_score": 0,
            "evidence": [],
            "top_signals": [],
            "confidence_adjustment": 0,
            "evaluation_count": 0,
        }

    rules_hit = []
    evidence = []
    top_signals = []
    risk_score = 0

    form_data = webpage_analysis.get("form_analysis") or {}
    script_data = webpage_analysis.get("script_analysis") or {}
    iframe_data = webpage_analysis.get("iframe_analysis") or {}
    resource_data = webpage_analysis.get("resource_analysis") or {}
    header_data = webpage_analysis.get("header_analysis") or {}
    content_data = webpage_analysis.get("content_analysis") or {}
    redirect_data = fetch_result.get("redirect_analysis") or {}

    # ── WEB-001: Password collection detected ────────────────────────────────
    if form_data.get("has_password_field"):
        rules_hit.append({
            "rule_id": "WEB-001",
            "title": "Password Collection Detected",
            "severity": "MEDIUM",
            "description": "The webpage contains one or more password input fields.",
            "evidence": f"{form_data.get('credential_field_count', 0)} credential field(s) detected across {form_data.get('form_count', 0)} form(s).",
            "why_it_matters": "Password fields on unfamiliar domains may be credential harvesting forms. Context is important — login forms on legitimate services are expected.",
            "confidence": "high",
        })
        evidence.append({
            "signal": "password_collection",
            "what": "Password input field detected on page",
            "where": "HTML form analysis",
            "why": "Credential harvesting is a primary phishing objective",
            "severity": "medium",
            "source": "Module 3 — Webpage Intelligence",
            "timestamp": datetime.now().isoformat(),
        })
        top_signals.append("Password collection form")
        risk_score += 15

    # ── WEB-002: Password form submits to another registered domain ──────────
    for form in form_data.get("forms", []):
        is_cred_form = form.get("has_credential_fields") or form.get("has_password") or form.get("has_password_field") or form_data.get("has_password_field")
        if is_cred_form and form.get("is_cross_domain"):
            action_domain = form.get("action_registered_domain") or form.get("action_domain", "unknown")
            rules_hit.append({
                "rule_id": "WEB-002",
                "title": "Cross-Domain Password Submission",
                "severity": "HIGH",
                "description": f"A password form submits credentials to a different registered domain: {action_domain}",
                "evidence": f"Form action points to {form.get('action_url', 'unknown')[:150]}",
                "why_it_matters": "Legitimate login forms typically submit to the same domain. Cross-domain credential submission is a strong indicator of credential exfiltration.",
                "confidence": "high",
            })
            evidence.append({
                "signal": "cross_domain_password",
                "what": f"Password form submits to different domain: {action_domain}",
                "where": "Form destination analysis",
                "why": "Credentials may be transmitted to an attacker-controlled domain",
                "severity": "high",
                "source": "Module 3 — Webpage Intelligence",
                "timestamp": datetime.now().isoformat(),
            })
            top_signals.append(f"Cross-domain password submission → {action_domain}")
            risk_score += 30
            break

    # ── WEB-003: Cross-domain credential submission (non-password) ────────────
    if form_data.get("has_cross_domain_action") and form_data.get("has_credential_fields") and not any(r["rule_id"] == "WEB-002" for r in rules_hit):
        rules_hit.append({
            "rule_id": "WEB-003",
            "title": "Cross-Domain Credential Submission",
            "severity": "HIGH",
            "description": "A form with credential fields submits data to a different registered domain.",
            "evidence": f"{form_data.get('credential_field_count', 0)} credential field(s) submit cross-domain.",
            "why_it_matters": "Sensitive information being sent to a different domain from the page origin is a credential theft indicator.",
            "confidence": "high",
        })
        evidence.append({
            "signal": "cross_domain_credentials",
            "what": "Credential form submits to different registered domain",
            "where": "Form destination analysis",
            "why": "Data may be collected by a domain unrelated to the page identity",
            "severity": "high",
            "source": "Module 3 — Webpage Intelligence",
            "timestamp": datetime.now().isoformat(),
        })
        top_signals.append("Cross-domain credential submission")
        risk_score += 25

    # ── WEB-004: Suspicious redirect chain ───────────────────────────────────
    if redirect_data.get("suspicious"):
        findings = redirect_data.get("findings", [])
        rules_hit.append({
            "rule_id": "WEB-004",
            "title": "Suspicious Redirect Chain",
            "severity": "MEDIUM",
            "description": "The redirect chain exhibits suspicious characteristics.",
            "evidence": "; ".join(findings) if findings else f"{redirect_data.get('count', 0)} redirects observed",
            "why_it_matters": "Suspicious redirect chains are used to evade detection and disguise the final destination.",
            "confidence": "medium",
        })
        evidence.append({
            "signal": "suspicious_redirects",
            "what": findings[0] if findings else "Suspicious redirect behavior",
            "where": "Redirect chain analysis",
            "why": "Redirect chains can hide the true destination of a URL",
            "severity": "medium",
            "source": "Module 3 — Webpage Intelligence",
            "timestamp": datetime.now().isoformat(),
        })
        top_signals.append("Suspicious redirect chain")
        risk_score += 15

    # ── WEB-005: Excessive redirects ─────────────────────────────────────────
    redirect_count = redirect_data.get("count", 0)
    if redirect_count > 3:
        rules_hit.append({
            "rule_id": "WEB-005",
            "title": "Excessive Redirects",
            "severity": "LOW",
            "description": f"The URL followed {redirect_count} redirects before reaching the final page.",
            "evidence": f"{redirect_count} redirects, {redirect_data.get('domain_changes', 0)} domain change(s)",
            "why_it_matters": "While some redirects are normal, excessive chains may indicate evasion attempts or tracking infrastructure.",
            "confidence": "medium",
        })
        evidence.append({
            "signal": "excessive_redirects",
            "what": f"{redirect_count} redirects observed",
            "where": "Redirect chain analysis",
            "why": "Excessive redirects may indicate evasion or tracking",
            "severity": "low",
            "source": "Module 3 — Webpage Intelligence",
            "timestamp": datetime.now().isoformat(),
        })
        risk_score += 8

    # ── WEB-006: Hidden credential field ─────────────────────────────────────
    hidden_cred_found = False
    for form in form_data.get("forms", []):
        for cred in form.get("credential_fields", []):
            if cred.get("hidden"):
                hidden_cred_found = True
                break
        if hidden_cred_found:
            break

    if hidden_cred_found:
        rules_hit.append({
            "rule_id": "WEB-006",
            "title": "Hidden Credential Field",
            "severity": "HIGH",
            "description": "A credential input field is hidden from the user's view.",
            "evidence": "A hidden input field with credential-type attributes was detected.",
            "why_it_matters": "Hidden credential fields may silently collect previously autofilled credentials without the user's knowledge.",
            "confidence": "high",
        })
        evidence.append({
            "signal": "hidden_credential_field",
            "what": "Hidden credential input field detected",
            "where": "Form structure analysis",
            "why": "May exploit browser autofill to steal credentials silently",
            "severity": "high",
            "source": "Module 3 — Webpage Intelligence",
            "timestamp": datetime.now().isoformat(),
        })
        top_signals.append("Hidden credential field")
        risk_score += 25

    # ── WEB-007: Suspicious iframe ───────────────────────────────────────────
    has_hid_iframe = iframe_data.get("has_hidden_iframe") or iframe_data.get("has_hidden_iframes")
    has_xdom_iframe = iframe_data.get("has_cross_domain_iframe") or iframe_data.get("has_cross_domain_iframes")
    if has_hid_iframe or (has_xdom_iframe and (iframe_data.get("count", 0) > 2 or iframe_data.get("total_count", 0) > 2)):
        desc_parts = []
        if has_hid_iframe:
            desc_parts.append("hidden iframe detected")
        if has_xdom_iframe:
            desc_parts.append("cross-domain iframe detected")
        rules_hit.append({
            "rule_id": "WEB-007",
            "title": "Suspicious Iframe",
            "severity": "MEDIUM",
            "description": f"Suspicious iframe behavior: {'; '.join(desc_parts)}.",
            "evidence": f"{iframe_data.get('count', 0)} iframe(s) on page",
            "why_it_matters": "Hidden or excessive cross-domain iframes can load content from attacker-controlled pages, enable clickjacking, or embed credential collection forms.",
            "confidence": "medium",
        })
        evidence.append({
            "signal": "suspicious_iframe",
            "what": "; ".join(desc_parts).capitalize(),
            "where": "Iframe analysis",
            "why": "Iframes can embed malicious content or credential collection forms",
            "severity": "medium",
            "source": "Module 3 — Webpage Intelligence",
            "timestamp": datetime.now().isoformat(),
        })
        top_signals.append("Suspicious iframe behavior")
        risk_score += 12

    # ── WEB-008: Potentially obfuscated JavaScript ───────────────────────────
    suspicious_patterns = script_data.get("suspicious_patterns", [])
    obfuscation_patterns = []
    target_pats = ("eval_usage", "function_constructor", "encoded_string", "obfuscation_indicator", "base64_pattern")
    for p in suspicious_patterns:
        pat_key = p.get("pattern") if isinstance(p, dict) else str(p)
        if pat_key in target_pats:
            desc = (p.get("description") or pat_key) if isinstance(p, dict) else pat_key.replace("_", " ").title()
            obfuscation_patterns.append(desc)
    if obfuscation_patterns:
        pattern_names = obfuscation_patterns[:3]
        rules_hit.append({
            "rule_id": "WEB-008",
            "title": "Potentially Obfuscated JavaScript",
            "severity": "MEDIUM",
            "description": f"JavaScript constructs commonly associated with obfuscation were detected: {', '.join(pattern_names)}.",
            "evidence": f"{len(obfuscation_patterns)} obfuscation-related pattern(s) identified",
            "why_it_matters": "Obfuscated JavaScript is used by both legitimate applications and malicious scripts. Its presence alongside other risk indicators strengthens the assessment.",
            "confidence": "low",
        })
        evidence.append({
            "signal": "obfuscated_javascript",
            "what": f"Obfuscation patterns detected: {', '.join(pattern_names)}",
            "where": "JavaScript static analysis",
            "why": "Obfuscated code may hide malicious behavior",
            "severity": "medium",
            "source": "Module 3 — Webpage Intelligence",
            "timestamp": datetime.now().isoformat(),
        })
        risk_score += 10

    # ── WEB-009: HTTP credential submission ──────────────────────────────────
    if form_data.get("has_http_action"):
        rules_hit.append({
            "rule_id": "WEB-009",
            "title": "HTTP Credential Submission",
            "severity": "HIGH",
            "description": "A form with credential fields submits data over unencrypted HTTP.",
            "evidence": "Form action uses HTTP protocol instead of HTTPS for credential transmission.",
            "why_it_matters": "Credentials sent over HTTP can be intercepted by anyone on the network path.",
            "confidence": "high",
        })
        evidence.append({
            "signal": "http_credentials",
            "what": "Credentials transmitted over unencrypted HTTP",
            "where": "Form destination analysis",
            "why": "Network interception of plaintext credentials is trivial",
            "severity": "high",
            "source": "Module 3 — Webpage Intelligence",
            "timestamp": datetime.now().isoformat(),
        })
        top_signals.append("HTTP credential submission")
        risk_score += 20

    # ── WEB-010: Unusual external resource concentration ─────────────────────
    ext_domain_count = resource_data.get("external_domain_count", 0)
    ext_ratio = resource_data.get("external_ratio", 0)
    if ext_domain_count > 10 or (ext_ratio > 0.7 and resource_data.get("total_resources", 0) > 5):
        rules_hit.append({
            "rule_id": "WEB-010",
            "title": "Unusual External Resource Concentration",
            "severity": "LOW",
            "description": f"The page loads resources from {ext_domain_count} external domains ({round(ext_ratio * 100)}% external).",
            "evidence": f"{resource_data.get('third_party', 0)} third-party resources from {ext_domain_count} domains",
            "why_it_matters": "High external resource concentration may indicate tracking, ad injection, or resources loaded from compromised CDNs.",
            "confidence": "low",
        })
        evidence.append({
            "signal": "external_resource_concentration",
            "what": f"Resources loaded from {ext_domain_count} external domains",
            "where": "External resource analysis",
            "why": "Excessive external resources may indicate tracking or compromised infrastructure",
            "severity": "low",
            "source": "Module 3 — Webpage Intelligence",
            "timestamp": datetime.now().isoformat(),
        })
        risk_score += 8

    # ── WEB-011: Urgent credential-verification language ──────────────────────
    has_urgency = content_data.get("has_urgency_language") or (content_data.get("urgency_matches_count", 0) > 0)
    has_creds_or_login = form_data.get("has_credential_fields") or form_data.get("has_password_field") or content_data.get("has_login_language")
    if has_urgency and has_creds_or_login:
        urgency_items = content_data.get("urgency_indicators", [])
        rules_hit.append({
            "rule_id": "WEB-011",
            "title": "Urgent Credential-Verification Language",
            "severity": "MEDIUM",
            "description": "The page contains urgency language combined with credential collection.",
            "evidence": f"Urgency patterns detected: {'; '.join(str(u)[:60] for u in urgency_items[:2])}",
            "why_it_matters": "Urgency combined with credential requests is a hallmark social engineering technique designed to bypass careful user judgment.",
            "confidence": "medium",
        })
        evidence.append({
            "signal": "urgency_with_credentials",
            "what": "Urgency language combined with credential collection",
            "where": "Page content analysis",
            "why": "Social engineering tactic to pressure users into entering credentials",
            "severity": "medium",
            "source": "Module 3 — Webpage Intelligence",
            "timestamp": datetime.now().isoformat(),
        })
        top_signals.append("Urgency language with credential collection")
        risk_score += 15

    # ── WEB-012: Page/form domain mismatch ───────────────────────────────────
    # Check if page claims one brand but forms go elsewhere
    detected_brands = content_data.get("detected_brands", [])
    if detected_brands and form_data.get("has_cross_domain_action"):
        rules_hit.append({
            "rule_id": "WEB-012",
            "title": "Page/Form Domain Mismatch",
            "severity": "HIGH",
            "description": f"The page references brand(s) '{', '.join(detected_brands[:3])}' but form actions point to a different domain.",
            "evidence": "Brand references on page do not match form submission destination.",
            "why_it_matters": "Pages that display one brand's identity but submit data to a different domain are a strong phishing indicator.",
            "confidence": "high",
        })
        evidence.append({
            "signal": "brand_form_mismatch",
            "what": f"Brand mentions ({', '.join(detected_brands[:2])}) but forms submit elsewhere",
            "where": "Content + form correlation",
            "why": "Impersonation combined with data exfiltration",
            "severity": "high",
            "source": "Module 3 — Webpage Intelligence",
            "timestamp": datetime.now().isoformat(),
        })
        top_signals.append("Brand/form domain mismatch")
        risk_score += 25

    # ── Clamp risk score ─────────────────────────────────────────────────────
    risk_score = max(0, min(100, risk_score))

    return {
        "triggered": len(rules_hit) > 0,
        "count": len(rules_hit),
        "rules_hit": rules_hit,
        "evidence": evidence,
        "top_signals": top_signals,
        "risk_score": risk_score,
        "severity": _max_severity(rules_hit),
        "risk_factors": [r["title"] for r in rules_hit],
    }


def _max_severity(rules: List[Dict]) -> str:
    """Return the highest severity from triggered rules."""
    order = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "NONE": 0}
    max_sev = "NONE"
    for r in rules:
        sev = r.get("severity", "NONE")
        if order.get(sev, 0) > order.get(max_sev, 0):
            max_sev = sev
    return max_sev
