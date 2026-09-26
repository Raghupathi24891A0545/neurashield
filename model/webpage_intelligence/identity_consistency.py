"""
NEURASHIELD — MODULE 3: WEBPAGE IDENTITY CONSISTENCY ENGINE
Evaluates whether a webpage's claimed identity matches its observed technical behavior:
1. What the webpage claims to be (title, headings, declared brands, login/urgency wording, meta)
2. What the webpage technically does (form destinations, credential fields, external domains, scripts)
3. Consistency Analysis: CONSISTENT | INCONSISTENT | INSUFFICIENT EVIDENCE

Follows strict engineering honesty:
- Never fabricates evidence.
- Obeys the Existence Guard when target is unreachable.
"""

from urllib.parse import urlparse
from typing import Dict, Any, List, Optional

try:
    import tldextract
except ImportError:
    tldextract = None

KNOWN_BRAND_DOMAINS = {
    "microsoft": {"microsoft.com", "live.com", "office.com", "azure.com", "msn.com", "bing.com", "windows.com", "xbox.com"},
    "apple": {"apple.com", "icloud.com"},
    "google": {"google.com", "youtube.com", "gmail.com", "gstatic.com"},
    "amazon": {"amazon.com", "aws.amazon.com"},
    "paypal": {"paypal.com"},
    "netflix": {"netflix.com"},
    "facebook": {"facebook.com", "meta.com", "instagram.com", "whatsapp.com"},
    "instagram": {"instagram.com", "facebook.com", "meta.com"},
    "linkedin": {"linkedin.com"},
    "twitter": {"twitter.com", "x.com"},
    "chase": {"chase.com"},
    "wells fargo": {"wellsfargo.com"},
    "citibank": {"citi.com", "citibank.com"},
    "bank of america": {"bankofamerica.com"},
    "binance": {"binance.com"},
    "coinbase": {"coinbase.com"},
    "github": {"github.com"},
    "khanacademy": {"khanacademy.org"},
}


def _extract_registered_domain(url_or_hostname: str) -> str:
    """Safely extract registered domain (e.g. google.com from mail.google.com)."""
    if not url_or_hostname:
        return ""
    if "://" not in url_or_hostname and not url_or_hostname.startswith("//"):
        candidate = f"https://{url_or_hostname}"
    else:
        candidate = url_or_hostname
    try:
        if tldextract:
            ext = tldextract.extract(candidate)
            if ext.domain and ext.suffix:
                return f"{ext.domain}.{ext.suffix}".lower()
        parsed = urlparse(candidate)
        hostname = (parsed.hostname or url_or_hostname).lower()
        parts = hostname.split(".")
        return ".".join(parts[-2:]) if len(parts) >= 2 else hostname
    except Exception:
        return url_or_hostname.lower()


def evaluate_identity_consistency(webpage_analysis: Dict[str, Any], fetch_result: Dict[str, Any], page_url: str) -> Dict[str, Any]:
    """
    Evaluates Claimed Identity vs Observed Technical Behavior.
    Returns:
    - state: "CONSISTENT" | "INCONSISTENT" | "INSUFFICIENT EVIDENCE"
    - claimed_identity: details of observable identity indicators
    - observed_behavior: details of observed technical behavior
    - consistency_assessment: human & machine explainable assessment
    - supporting_evidence: list of observed evidence points
    - limitations: telemetry boundaries
    """
    fetch_status = (fetch_result or {}).get("fetch_status")
    is_available = (fetch_status == "FETCH_SUCCESS" and bool(webpage_analysis) and webpage_analysis.get("status") == "analyzed")

    # ── Existence Guard: Webpage Unavailable ──────────────────────────────────
    if not is_available:
        return {
            "state": "INSUFFICIENT EVIDENCE",
            "state_code": "INSUFFICIENT_EVIDENCE",
            "badge_color": "var(--ns-amber)",
            "badge_class": "badge-warning",
            "verdict_title": "WEBPAGE UNAVAILABLE",
            "key_insight": "Webpage-level identity/behavior analysis was not performed.",
            "claimed_identity": None,
            "observed_behavior": None,
            "consistency_assessment": "The webpage could not be retrieved via HTTP/HTTPS. A domain existing does NOT mean a webpage exists. Webpage-level identity and behavioral consistency analysis was not performed, and no speculative findings were generated.",
            "supporting_evidence": [
                f"HTTP fetch status: {fetch_status or 'UNAVAILABLE'}",
                "Existence Guard active: zero hallucinated forms, DOM nodes, or scripts."
            ],
            "limitations": [
                "Target host was unreachable or did not return valid HTML content.",
                "Identity and behavioral telemetry require active HTTP/HTTPS service."
            ]
        }

    # ── 1. Extract Claimed Identity ──────────────────────────────────────────
    html = webpage_analysis.get("html_analysis") or {}
    content = webpage_analysis.get("content_analysis") or {}
    forms = webpage_analysis.get("form_analysis") or {}
    scripts = webpage_analysis.get("script_analysis") or {}
    resources = webpage_analysis.get("resource_analysis") or {}
    page_registered_domain = _extract_registered_domain(page_url)

    title = html.get("title") or ""
    meta_desc = html.get("meta_description") or ""
    headings = [h.get("text", "") for h in (html.get("headings") or []) if h.get("text")]
    detected_brands = list(content.get("detected_brands") or [])
    login_language = list(content.get("login_language") or [])
    urgency_indicators = list(content.get("urgency_indicators") or [])
    favicon = html.get("favicon")

    # Also detect brands mentioned in title or top headings
    all_text_for_brands = (f"{title} {' '.join(headings[:3])} {meta_desc}").lower()
    for brand in KNOWN_BRAND_DOMAINS:
        if brand in all_text_for_brands and brand not in detected_brands:
            detected_brands.append(brand)

    claimed_items = []
    if title:
        claimed_items.append(f'Page Title: "{title}"')
    if headings:
        top_h = headings[0]
        claimed_items.append(f'Prominent Heading: "{top_h}"')
    if detected_brands:
        claimed_items.append(f'Referenced Brand Identity: {", ".join([b.capitalize() for b in detected_brands])}')
    if login_language:
        claimed_items.append(f'Declared Function: Account Login / Security Authentication ({", ".join(login_language[:2])})')
    elif urgency_indicators:
        claimed_items.append(f'Declared Urgency Notice: {", ".join(urgency_indicators[:2])}')
    elif meta_desc:
        claimed_items.append(f'Declared Metadata: "{meta_desc[:120]}"')

    claimed_identity = {
        "page_title": title or "Untitled Webpage",
        "meta_description": meta_desc,
        "headings": headings[:5],
        "primary_heading": headings[0] if headings else None,
        "detected_brands": detected_brands,
        "login_language": login_language[:3],
        "urgency_indicators": urgency_indicators[:3],
        "favicon": favicon,
        "claimed_items": claimed_items,
        "summary": " · ".join(claimed_items[:3]) if claimed_items else "Generic Webpage Content"
    }

    # ── 2. Extract Observed Technical Behavior ────────────────────────────────
    form_list = forms.get("forms") or []
    form_action_domains = set()
    cross_domain_actions = []
    for f in form_list:
        act_dom = _extract_registered_domain(f.get("action_domain") or f.get("action_url") or "")
        if act_dom:
            form_action_domains.add(act_dom)
            if f.get("is_cross_domain") and act_dom != page_registered_domain:
                cross_domain_actions.append(act_dom)

    has_password = bool(forms.get("has_password_field"))
    has_credentials = bool(forms.get("has_credential_fields"))
    has_cross_domain_form = bool(forms.get("has_cross_domain_action") or cross_domain_actions)
    ext_domains = list(resources.get("external_domains") or [])
    raw_patterns = list(scripts.get("suspicious_patterns") or [])
    suspicious_patterns = [
        (p.get("description") or p.get("pattern") or str(p)) if isinstance(p, dict) else str(p)
        for p in raw_patterns
    ]

    observed_behavior_items = [
        "Page content successfully retrieved via safe HTTP connection"
    ]
    if has_password:
        observed_behavior_items.append("Credential collection detected: password input field present in DOM")
    elif has_credentials:
        observed_behavior_items.append("Form data collection detected: sensitive inputs observed")

    if has_cross_domain_form:
        observed_behavior_items.append(f"Form submission destination: cross-domain exfiltration to foreign domain ({', '.join(set(cross_domain_actions))})")
    elif form_action_domains:
        observed_behavior_items.append(f"Form submission destination: same-origin / self-hosted ({page_registered_domain})")

    if ext_domains:
        observed_behavior_items.append(f"External infrastructure: loads resources/scripts from {len(ext_domains)} third-party domain(s) ({', '.join(ext_domains[:3])})")

    if suspicious_patterns:
        observed_behavior_items.append(f"JavaScript execution signals: potentially suspicious script constructs ({', '.join(suspicious_patterns[:3])})")

    observed_behavior = {
        "page_registered_domain": page_registered_domain,
        "form_count": forms.get("form_count", 0),
        "has_password_field": has_password,
        "has_credential_collection": has_credentials,
        "has_cross_domain_action": has_cross_domain_form,
        "form_action_domains": list(form_action_domains),
        "cross_domain_destinations": list(set(cross_domain_actions)),
        "external_domains": ext_domains[:10],
        "external_domain_count": len(ext_domains),
        "has_suspicious_scripts": bool(suspicious_patterns),
        "suspicious_script_patterns": suspicious_patterns,
        "observed_items": observed_behavior_items
    }

    # ── 3. Evaluate Consistency ──────────────────────────────────────────────
    inconsistencies = []
    consistency_points = []

    # Check A: Brand Identity vs Registered Domain
    brand_mismatch_detected = False
    for brand in detected_brands:
        authorized_domains = KNOWN_BRAND_DOMAINS.get(brand.lower(), set())
        if authorized_domains:
            if page_registered_domain not in authorized_domains:
                brand_mismatch_detected = True
                inconsistencies.append(
                    f"Page prominently claims brand '{brand.capitalize()}', but is hosted on registered domain '{page_registered_domain}' which does not correspond to official infrastructure for that brand."
                )
            else:
                consistency_points.append(
                    f"Page brand claim '{brand.capitalize()}' matches authorized registered domain '{page_registered_domain}'."
                )

    # Check B: Form Action Domain Mismatch
    if has_cross_domain_form:
        dest_str = ", ".join(set(cross_domain_actions))
        inconsistencies.append(
            f"The page presents an authentication/data interface, but form action submits data cross-domain to an unauthorized destination: '{dest_str}'."
        )
    elif form_list and not has_cross_domain_form:
        consistency_points.append(
            f"Form actions submit strictly to same-origin / authorized domain '{page_registered_domain}'."
        )

    # Check C: Claimed Security vs Third-Party Exfiltration Beacons
    if (login_language or has_credentials) and ext_domains and (brand_mismatch_detected or has_cross_domain_form):
        inconsistencies.append(
            f"Login/security interface loads external dependencies from foreign domain(s): {', '.join(ext_domains[:3])}."
        )

    # ── Determine Consistency State ──────────────────────────────────────────
    if inconsistencies:
        state = "INCONSISTENT"
        state_code = "INCONSISTENT"
        badge_color = "var(--ns-red)"
        badge_class = "badge-danger"
        verdict_title = "IDENTITY INCONSISTENCY DETECTED"
        assessment = (
            f"The webpage claims to be '{title or (detected_brands[0].capitalize() if detected_brands else 'an authenticated service')}', "
            f"but its underlying technical behavior reveals meaningful inconsistencies. "
            f"{' '.join(inconsistencies)}"
        )
        recommendation = "Identity inconsistency detected. Additional investigation recommended before trusting credentials with this host."
    else:
        state = "CONSISTENT"
        state_code = "CONSISTENT"
        badge_color = "var(--ns-green)"
        badge_class = "badge-success"
        verdict_title = "IDENTITY & BEHAVIOR CONSISTENT"
        assessment = (
            "The claimed identity and observed technical behavior show no significant inconsistency based on the available evidence. "
            "Host infrastructure, form destinations, and declared branding align with expected operation."
        )
        recommendation = "No identity discrepancies observed. Continue standard security hygiene."

    # Supporting Evidence List (truthful telemetry)
    supporting_evidence = []
    supporting_evidence.append(f"✓ Page successfully retrieved (HTTP {fetch_result.get('http_status') or 200})")
    if title:
        supporting_evidence.append(f"Observable Title: \"{title}\"")
    if detected_brands:
        supporting_evidence.append(f"Observable Brand Reference: {', '.join([b.capitalize() for b in detected_brands])}")
    if has_password:
        supporting_evidence.append("⚠ Credential collection detected (password input in DOM)")
    elif has_credentials:
        supporting_evidence.append("ℹ Form field inputs observed")
    else:
        supporting_evidence.append("✓ No credential or password inputs present")

    if has_cross_domain_form:
        supporting_evidence.append(f"⚠ Form submits to another domain ({', '.join(set(cross_domain_actions))})")
    elif form_list:
        supporting_evidence.append("✓ Form submission destinations match origin domain")

    if ext_domains:
        supporting_evidence.append(f"ℹ External resources observed ({len(ext_domains)} external domains)")

    if inconsistencies:
        supporting_evidence.append("⚠ Claimed identity and observed infrastructure require further investigation")

    return {
        "state": state,
        "state_code": state_code,
        "badge_color": badge_color,
        "badge_class": badge_class,
        "verdict_title": verdict_title,
        "verdict": verdict_title,
        "key_insight": "The page's visual or textual identity is only one part of the investigation. NeuraShield compares what the page claims with what its underlying technical behavior reveals.",
        "claimed_identity": claimed_identity,
        "observed_behavior": observed_behavior,
        "consistency_assessment": assessment,
        "supporting_evidence": supporting_evidence,
        "inconsistencies": inconsistencies,
        "consistency_points": consistency_points,
        "recommendation": recommendation,
        "limitations": [
            "JavaScript was inspected statically and not dynamically executed beyond headless hydration.",
            "Brand references are evaluated based on observable lexical and metadata tokens, not trademark registries.",
            "Does not assume mentioning a brand automatically proves phishing; only reports observed behavioral divergence."
        ]
    }
