"""
NEURASHIELD — MODULE 3: WEBPAGE ANALYZER
Performs safe static analysis of webpage HTML content including:
- HTML/DOM structure analysis
- Form intelligence & credential collection detection
- JavaScript static analysis
- Iframe analysis
- External resource analysis
- Security header analysis
- Page content intelligence
"""

import re
import hashlib
from urllib.parse import urlparse, urljoin
from typing import Dict, Any, List, Optional
from collections import Counter

try:
    from bs4 import BeautifulSoup
except ImportError:
    BeautifulSoup = None

try:
    import tldextract
except ImportError:
    tldextract = None


# ── Credential Field Detection ───────────────────────────────────────────────

CREDENTIAL_FIELD_PATTERNS = {
    "password": re.compile(r"pass(word)?|pwd|passcode|secret|pin_code", re.I),
    "email": re.compile(r"e[\-_]?mail|user[\-_]?mail", re.I),
    "username": re.compile(r"user([\-_]?name)?|login|acct|account[\-_]?id|userid", re.I),
    "otp": re.compile(r"otp|one[\-_]?time|verification[\-_]?code|verify[\-_]?code|token|2fa|mfa", re.I),
    "card_number": re.compile(r"card[\-_]?(num|number)|cc[\-_]?num|credit[\-_]?card|pan", re.I),
    "cvv": re.compile(r"cvv|cvc|security[\-_]?code|card[\-_]?code", re.I),
    "ssn": re.compile(r"ssn|social[\-_]?security", re.I),
    "pin": re.compile(r"\bpin\b|pin[\-_]?code|atm[\-_]?pin", re.I),
    "account_number": re.compile(r"account[\-_]?(num|number)|acct[\-_]?no", re.I),
}

SUSPICIOUS_JS_PATTERNS = {
    "eval_usage": re.compile(r"\beval\s*\(", re.I),
    "function_constructor": re.compile(r"\bnew\s+Function\s*\(", re.I),
    "document_write": re.compile(r"document\s*\.\s*write\s*\(", re.I),
    "location_manipulation": re.compile(r"(window\s*\.\s*)?location\s*(\.\s*(href|replace|assign)|=)", re.I),
    "base64_pattern": re.compile(r"atob\s*\(|btoa\s*\(", re.I),
    "encoded_string": re.compile(r"\\x[0-9a-f]{2}|\\u[0-9a-f]{4}|String\.fromCharCode", re.I),
    "clipboard_access": re.compile(r"navigator\s*\.\s*clipboard|document\s*\.\s*execCommand\s*\(\s*['\"]copy", re.I),
    "credential_dom": re.compile(r"getElementById\s*\(\s*['\"].*?(pass|pwd|login|email|user).*?['\"]\s*\)", re.I),
    "dynamic_iframe": re.compile(r"createElement\s*\(\s*['\"]iframe['\"]", re.I),
    "hidden_form": re.compile(r"\.style\s*\.\s*display\s*=\s*['\"]none['\"]|\.hidden\s*=\s*true|visibility\s*:\s*hidden", re.I),
    "obfuscation_indicator": re.compile(r"unescape\s*\(|decodeURIComponent\s*\(|String\s*\.\s*fromCharCode\s*\.\s*apply", re.I),
}

URGENCY_PATTERNS = [
    re.compile(r"your\s+account\s+(will\s+be|has\s+been|is)\s+(suspend|block|deactivat|restrict|lock|terminat|close)", re.I),
    re.compile(r"verify\s+(your\s+)?(identity|account|information)\s+(immediately|now|within)", re.I),
    re.compile(r"confirm\s+(your\s+)?password", re.I),
    re.compile(r"(urgent|immediate)\s+(action|attention|verification)\s+(required|needed)", re.I),
    re.compile(r"(click|act)\s+(here\s+)?(immediately|now|within\s+\d+)", re.I),
    re.compile(r"unauthorized\s+(access|activity|login)\s+(detect|found|notice)", re.I),
    re.compile(r"security\s+(alert|warning|notice)\s*[:\-]", re.I),
    re.compile(r"update\s+your\s+(payment|billing|card)\s+information", re.I),
    re.compile(r"failure\s+to\s+(verify|confirm|update)\s+will\s+result", re.I),
]


def _extract_registered_domain(url_or_hostname: str) -> str:
    """Extract registered domain from URL or hostname."""
    if tldextract:
        ext = tldextract.extract(url_or_hostname)
        if ext.domain and ext.suffix:
            return f"{ext.domain}.{ext.suffix}"
    # Fallback
    parsed = urlparse(url_or_hostname if "://" in url_or_hostname else f"https://{url_or_hostname}")
    hostname = parsed.hostname or url_or_hostname
    parts = hostname.split(".")
    return ".".join(parts[-2:]) if len(parts) >= 2 else hostname


def _is_same_origin(base_url: str, target_url: str) -> bool:
    """Check if two URLs have the same origin."""
    parsed_base = urlparse(base_url)
    parsed_target = urlparse(target_url)
    return (parsed_base.scheme == parsed_target.scheme and
            parsed_base.hostname == parsed_target.hostname and
            (parsed_base.port or 443 if parsed_base.scheme == 'https' else 80) ==
            (parsed_target.port or 443 if parsed_target.scheme == 'https' else 80))


def _is_same_registered_domain(domain1: str, domain2: str) -> bool:
    """Check if two domains share the same registered domain."""
    return _extract_registered_domain(domain1).lower() == _extract_registered_domain(domain2).lower()


# ── HTML/DOM Analysis ────────────────────────────────────────────────────────

def analyze_html_structure(html: str, page_url: str) -> Dict[str, Any]:
    """Analyze HTML structure and extract key elements."""
    if not BeautifulSoup or not html:
        return {"status": "unavailable", "reason": "HTML parser not available or no content"}

    soup = BeautifulSoup(html, "html.parser")

    # Basic metadata
    title_tag = soup.find("title")
    title = title_tag.get_text(strip=True) if title_tag else None

    meta_desc = None
    meta_tag = soup.find("meta", attrs={"name": "description"})
    if meta_tag:
        meta_desc = meta_tag.get("content", "")

    canonical = None
    canonical_tag = soup.find("link", rel="canonical")
    if canonical_tag:
        canonical = canonical_tag.get("href", "")

    lang = soup.find("html")
    language = lang.get("lang", None) if lang else None

    # Headings
    headings = []
    for level in range(1, 7):
        for h in soup.find_all(f"h{level}"):
            headings.append({"level": level, "text": h.get_text(strip=True)[:200]})

    # Element counts
    all_elements = soup.find_all()
    forms = soup.find_all("form")
    links = soup.find_all("a", href=True)
    scripts = soup.find_all("script")
    iframes = soup.find_all("iframe")
    images = soup.find_all("img")
    stylesheets = soup.find_all("link", rel="stylesheet")

    # Hidden elements
    hidden_elements = []
    for el in all_elements:
        style = el.get("style", "")
        if el.get("type") == "hidden" or el.get("hidden") is not None:
            hidden_elements.append({"tag": el.name, "type": "attribute"})
        elif "display:none" in style.replace(" ", "").lower() or "visibility:hidden" in style.replace(" ", "").lower():
            hidden_elements.append({"tag": el.name, "type": "css"})

    # Meta refresh
    meta_refresh = None
    meta_ref = soup.find("meta", attrs={"http-equiv": re.compile(r"refresh", re.I)})
    if meta_ref:
        meta_refresh = meta_ref.get("content", "")

    # Favicon
    favicon = None
    fav_link = soup.find("link", rel=re.compile(r"icon", re.I))
    if fav_link:
        favicon = fav_link.get("href", "")

    return {
        "status": "analyzed",
        "title": title,
        "meta_description": meta_desc,
        "canonical": canonical,
        "language": language,
        "headings": headings[:20],
        "meta_refresh": meta_refresh,
        "favicon": favicon,
        "counts": {
            "total_elements": len(all_elements),
            "forms": len(forms),
            "links": len(links),
            "scripts": len(scripts),
            "iframes": len(iframes),
            "images": len(images),
            "stylesheets": len(stylesheets),
            "hidden_elements": len(hidden_elements),
        },
        "html_size": len(html),
        "hidden_elements": hidden_elements[:20],
    }


# ── Form Intelligence ────────────────────────────────────────────────────────

def analyze_forms(html: str, page_url: str) -> Dict[str, Any]:
    """Analyze all forms for credential collection and suspicious destinations."""
    if not BeautifulSoup or not html:
        return {"status": "unavailable", "forms": [], "has_credential_fields": False}

    soup = BeautifulSoup(html, "html.parser")
    forms = soup.find_all("form")
    page_domain = urlparse(page_url).hostname or ""
    page_registered = _extract_registered_domain(page_url)

    analyzed_forms = []
    has_credential_fields = False
    has_password_field = False
    has_cross_domain_action = False
    has_http_action = False
    credential_field_count = 0

    for idx, form in enumerate(forms):
        action = form.get("action", "")
        method = (form.get("method", "GET")).upper()
        enctype = form.get("enctype", "")

        # Resolve action URL
        if action and not action.startswith(("#", "javascript:")):
            action_url = urljoin(page_url, action)
        elif not action:
            action_url = page_url
        else:
            action_url = action

        action_parsed = urlparse(action_url)
        action_domain = action_parsed.hostname or ""
        action_registered = _extract_registered_domain(action_url) if action_domain else page_registered

        same_origin = _is_same_origin(page_url, action_url) if action_domain else True
        same_registered = _is_same_registered_domain(page_domain, action_domain) if action_domain else True

        # Analyze inputs
        inputs = form.find_all(["input", "textarea", "select"])
        input_analysis = []
        form_credential_fields = []

        for inp in inputs:
            inp_type = (inp.get("type", "text")).lower()
            inp_name = inp.get("name", "") or inp.get("id", "")
            inp_placeholder = inp.get("placeholder", "")
            inp_autocomplete = inp.get("autocomplete", "")

            # Check if credential field
            is_credential = False
            credential_type = None

            if inp_type == "password":
                is_credential = True
                credential_type = "password"
                has_password_field = True
            elif inp_type == "email":
                is_credential = True
                credential_type = "email"
            elif inp_type == "hidden" and any(CREDENTIAL_FIELD_PATTERNS["password"].search(s) for s in [inp_name, inp_placeholder] if s):
                is_credential = True
                credential_type = "hidden_password"

            if not is_credential:
                for cred_type, pattern in CREDENTIAL_FIELD_PATTERNS.items():
                    if any(pattern.search(s) for s in [inp_name, inp_placeholder, inp_autocomplete] if s):
                        is_credential = True
                        credential_type = cred_type
                        break

            if is_credential:
                has_credential_fields = True
                credential_field_count += 1
                form_credential_fields.append({
                    "type": credential_type,
                    "input_type": inp_type,
                    "name": inp_name[:50],
                    "hidden": inp_type == "hidden" or inp.get("hidden") is not None,
                })

            input_analysis.append({
                "type": inp_type,
                "name": inp_name[:50],
                "is_credential": is_credential,
                "credential_type": credential_type,
            })

        is_cross_domain = not same_registered and action_domain and action_domain != page_domain
        is_http_action = action_parsed.scheme == "http" and len(form_credential_fields) > 0

        if is_cross_domain:
            has_cross_domain_action = True
        if is_http_action:
            has_http_action = True

        analyzed_forms.append({
            "index": idx,
            "method": method,
            "action": action[:200],
            "action_url": action_url[:300],
            "action_domain": action_domain,
            "action_registered_domain": action_registered,
            "same_origin": same_origin,
            "same_registered_domain": same_registered,
            "is_cross_domain": is_cross_domain,
            "is_http_action": is_http_action,
            "enctype": enctype,
            "input_count": len(inputs),
            "credential_fields": form_credential_fields,
            "has_credential_fields": len(form_credential_fields) > 0,
            "inputs": input_analysis[:20],
        })

    has_email_field = any(f.get("type") == "email" for form in analyzed_forms for f in form.get("credential_fields", []))
    has_otp_field = any(f.get("type") == "otp" for form in analyzed_forms for f in form.get("credential_fields", []))
    has_card_field = any(f.get("type") in ("card_number", "cvv") for form in analyzed_forms for f in form.get("credential_fields", []))

    return {
        "status": "analyzed",
        "form_count": len(analyzed_forms),
        "forms": analyzed_forms,
        "has_credential_fields": has_credential_fields,
        "has_password_field": has_password_field,
        "has_email_field": has_email_field,
        "has_otp_field": has_otp_field,
        "has_card_field": has_card_field,
        "has_cross_domain_action": has_cross_domain_action,
        "has_http_action": has_http_action,
        "credential_field_count": credential_field_count,
    }


# ── JavaScript Static Analysis ──────────────────────────────────────────────

def analyze_scripts(html: str, page_url: str) -> Dict[str, Any]:
    """Statically analyze JavaScript for suspicious patterns."""
    if not BeautifulSoup or not html:
        return {"status": "unavailable", "scripts": [], "findings": []}

    soup = BeautifulSoup(html, "html.parser")
    scripts = soup.find_all("script")
    page_domain = urlparse(page_url).hostname or ""
    page_registered = _extract_registered_domain(page_url)

    inline_scripts = []
    external_scripts = []
    findings = []
    suspicious_patterns = []
    external_domains = set()

    for script in scripts:
        src = script.get("src", "")
        if src:
            abs_src = urljoin(page_url, src)
            src_domain = urlparse(abs_src).hostname or ""
            src_registered = _extract_registered_domain(abs_src) if src_domain else ""
            is_external = not _is_same_registered_domain(page_domain, src_domain) if src_domain else False
            if is_external:
                external_domains.add(src_registered)
            external_scripts.append({
                "src": abs_src[:300],
                "domain": src_domain,
                "registered_domain": src_registered,
                "is_external": is_external,
            })
        else:
            content = script.get_text()
            if content.strip():
                # Scan for suspicious patterns
                for pattern_name, pattern in SUSPICIOUS_JS_PATTERNS.items():
                    matches = pattern.findall(content)
                    if matches:
                        suspicious_patterns.append({
                            "pattern": pattern_name,
                            "match_count": len(matches),
                            "context": pattern_name.replace("_", " ").title(),
                        })

                inline_scripts.append({
                    "length": len(content),
                    "has_suspicious_patterns": any(p.search(content) for p in SUSPICIOUS_JS_PATTERNS.values()),
                })

    # Deduplicate pattern findings
    pattern_counts = Counter(p["pattern"] for p in suspicious_patterns)
    unique_findings = []
    for pattern_name, count in pattern_counts.items():
        unique_findings.append({
            "pattern": pattern_name,
            "occurrences": count,
            "description": pattern_name.replace("_", " ").title(),
        })

    return {
        "status": "analyzed",
        "inline_count": len(inline_scripts),
        "external_count": len(external_scripts),
        "total_count": len(scripts),
        "inline_scripts": inline_scripts[:10],
        "external_scripts": external_scripts[:20],
        "external_script_domains": list(external_domains),
        "suspicious_patterns": unique_findings,
        "has_suspicious_patterns": len(unique_findings) > 0,
        "analysis_method": "static_only",
        "limitation": "JavaScript was inspected statically and not executed.",
    }


# ── Iframe Analysis ──────────────────────────────────────────────────────────

def analyze_iframes(html: str, page_url: str) -> Dict[str, Any]:
    """Analyze iframes for suspicious sources and hidden frames."""
    if not BeautifulSoup or not html:
        return {"status": "unavailable", "iframes": []}

    soup = BeautifulSoup(html, "html.parser")
    iframes = soup.find_all("iframe")
    page_domain = urlparse(page_url).hostname or ""

    analyzed = []
    has_hidden = False
    has_cross_domain = False

    for iframe in iframes:
        src = iframe.get("src", "")
        abs_src = urljoin(page_url, src) if src else ""
        src_domain = urlparse(abs_src).hostname if abs_src and "://" in abs_src else ""
        is_cross_domain = src_domain and not _is_same_registered_domain(page_domain, src_domain)
        sandbox = iframe.get("sandbox", None)

        # Check visibility
        style = iframe.get("style", "")
        width = iframe.get("width", "")
        height = iframe.get("height", "")
        is_hidden = (
            "display:none" in style.replace(" ", "").lower() or
            "visibility:hidden" in style.replace(" ", "").lower() or
            width in ("0", "0px", "1", "1px") or
            height in ("0", "0px", "1", "1px") or
            iframe.get("hidden") is not None
        )

        if is_hidden:
            has_hidden = True
        if is_cross_domain:
            has_cross_domain = True

        analyzed.append({
            "src": abs_src[:300] if abs_src else "(no src)",
            "domain": src_domain or "(same-origin or inline)",
            "is_cross_domain": is_cross_domain,
            "is_hidden": is_hidden,
            "sandbox": sandbox,
            "width": width,
            "height": height,
        })

    return {
        "status": "analyzed",
        "count": len(analyzed),
        "total_count": len(analyzed),
        "iframes": analyzed[:15],
        "has_hidden_iframe": has_hidden,
        "has_hidden_iframes": has_hidden,
        "has_cross_domain_iframe": has_cross_domain,
        "has_cross_domain_iframes": has_cross_domain,
        "hidden_count": sum(1 for i in analyzed if i.get("is_hidden")),
        "cross_domain_count": sum(1 for i in analyzed if i.get("is_cross_domain")),
        "sandboxed_count": sum(1 for i in analyzed if i.get("sandbox")),
    }


# ── External Resource Analysis ───────────────────────────────────────────────

def analyze_external_resources(html: str, page_url: str) -> Dict[str, Any]:
    """Analyze external resources loaded by the page."""
    if not BeautifulSoup or not html:
        return {"status": "unavailable"}

    soup = BeautifulSoup(html, "html.parser")
    page_domain = urlparse(page_url).hostname or ""
    page_registered = _extract_registered_domain(page_url)

    resources = []
    domain_counts = Counter()

    # Scripts
    for tag in soup.find_all("script", src=True):
        url = urljoin(page_url, tag["src"])
        domain = urlparse(url).hostname or ""
        reg_domain = _extract_registered_domain(url) if domain else ""
        is_external = not _is_same_registered_domain(page_domain, domain) if domain else False
        resources.append({"type": "script", "url": url[:300], "domain": domain, "registered_domain": reg_domain, "is_external": is_external})
        if is_external and reg_domain:
            domain_counts[reg_domain] += 1

    # Stylesheets
    for tag in soup.find_all("link", rel="stylesheet"):
        href = tag.get("href", "")
        if href:
            url = urljoin(page_url, href)
            domain = urlparse(url).hostname or ""
            reg_domain = _extract_registered_domain(url) if domain else ""
            is_external = not _is_same_registered_domain(page_domain, domain) if domain else False
            resources.append({"type": "stylesheet", "url": url[:300], "domain": domain, "registered_domain": reg_domain, "is_external": is_external})
            if is_external and reg_domain:
                domain_counts[reg_domain] += 1

    # Images
    for tag in soup.find_all("img", src=True):
        url = urljoin(page_url, tag["src"])
        domain = urlparse(url).hostname or ""
        reg_domain = _extract_registered_domain(url) if domain else ""
        is_external = not _is_same_registered_domain(page_domain, domain) if domain else False
        resources.append({"type": "image", "url": url[:300], "domain": domain, "registered_domain": reg_domain, "is_external": is_external})
        if is_external and reg_domain:
            domain_counts[reg_domain] += 1

    # Fonts/preconnect/prefetch
    for tag in soup.find_all("link", href=True):
        rel = " ".join(tag.get("rel", []))
        if any(r in rel for r in ["preconnect", "prefetch", "dns-prefetch", "preload"]):
            url = urljoin(page_url, tag["href"])
            domain = urlparse(url).hostname or ""
            reg_domain = _extract_registered_domain(url) if domain else ""
            is_external = not _is_same_registered_domain(page_domain, domain) if domain else False
            resources.append({"type": rel, "url": url[:300], "domain": domain, "registered_domain": reg_domain, "is_external": is_external})
            if is_external and reg_domain:
                domain_counts[reg_domain] += 1

    total = len(resources)
    external = sum(1 for r in resources if r.get("is_external"))
    first_party = total - external

    return {
        "status": "analyzed",
        "total_resources": total,
        "first_party": first_party,
        "third_party": external,
        "internal_resources": first_party,
        "external_resources": external,
        "external_domain_count": len(domain_counts),
        "external_domains": list(domain_counts.keys())[:20],
        "external_domains_counts": dict(domain_counts.most_common(20)),
        "external_ratio": round(external / total, 3) if total > 0 else 0,
        "resources_by_type": dict(Counter(r["type"] for r in resources)),
        "resources": resources[:30],
    }


# ── Security Header Analysis ────────────────────────────────────────────────

def analyze_security_headers(security_headers: Dict[str, str], response_headers: Dict[str, str]) -> Dict[str, Any]:
    """Analyze security-related HTTP headers."""
    sec_hdrs = {(k.lower() if isinstance(k, str) else str(k)): v for k, v in (security_headers or {}).items()}
    resp_hdrs = {(k.lower() if isinstance(k, str) else str(k)): v for k, v in (response_headers or {}).items()}
    for k, v in resp_hdrs.items():
        if k not in sec_hdrs:
            sec_hdrs[k] = v

    expected_headers = {
        "Content-Security-Policy": {
            "present": False,
            "description": "Controls which resources the browser can load",
            "impact": "Without CSP, the page is more susceptible to XSS attacks",
        },
        "Strict-Transport-Security": {
            "present": False,
            "description": "Enforces HTTPS connections",
            "impact": "Without HSTS, the connection may be downgraded to HTTP",
        },
        "X-Frame-Options": {
            "present": False,
            "description": "Prevents the page from being loaded in iframes",
            "impact": "Without X-Frame-Options, the page may be vulnerable to clickjacking",
        },
        "X-Content-Type-Options": {
            "present": False,
            "description": "Prevents MIME-type sniffing",
            "impact": "Without nosniff, browsers may misinterpret file types",
        },
        "Referrer-Policy": {
            "present": False,
            "description": "Controls how much referrer information is sent",
            "impact": "Without a referrer policy, sensitive URLs may leak to third parties",
        },
        "Permissions-Policy": {
            "present": False,
            "description": "Controls browser feature access (camera, mic, etc.)",
            "impact": "Without permissions policy, all browser features are accessible to scripts",
        },
    }

    present_count = 0
    for header_name in expected_headers:
        h_lower = header_name.lower()
        if h_lower in sec_hdrs:
            expected_headers[header_name]["present"] = True
            expected_headers[header_name]["value"] = str(sec_hdrs[h_lower])[:300]
            present_count += 1

    total_expected = len(expected_headers)
    coverage = round(present_count / total_expected * 100) if total_expected > 0 else 0

    # Additional response metadata
    server = resp_hdrs.get("server") or sec_hdrs.get("server")
    powered_by = resp_hdrs.get("x-powered-by") or sec_hdrs.get("x-powered-by")

    missing = [name for name, info in expected_headers.items() if not info["present"]]

    headers_audit = {
        name.lower(): {
            "present": info["present"],
            "value": info.get("value", ""),
            "description": info.get("description", ""),
            "impact": info.get("impact", ""),
        }
        for name, info in expected_headers.items()
    }

    return {
        "status": "analyzed",
        "headers": expected_headers,
        "headers_audit": headers_audit,
        "raw_headers": sec_hdrs,
        "present_count": present_count,
        "total_expected": total_expected,
        "coverage_percent": coverage,
        "missing_headers": missing,
        "server": server,
        "powered_by": powered_by,
        "has_csp": expected_headers["Content-Security-Policy"]["present"],
        "has_hsts": expected_headers["Strict-Transport-Security"]["present"],
        "has_x_frame_options": expected_headers["X-Frame-Options"]["present"],
        "grade": "A" if coverage >= 80 else "B" if coverage >= 60 else "C" if coverage >= 40 else "D" if coverage >= 20 else "F",
    }


# ── Page Content Intelligence ────────────────────────────────────────────────

def analyze_page_content(html: str, page_url: str) -> Dict[str, Any]:
    """Analyze visible page content for suspicious patterns."""
    if not BeautifulSoup or not html:
        return {"status": "unavailable"}

    soup = BeautifulSoup(html, "html.parser")

    # Remove script/style content
    for tag in soup.find_all(["script", "style"]):
        tag.decompose()

    visible_text = soup.get_text(separator=" ", strip=True)
    visible_text_lower = visible_text.lower()

    # Detect urgency patterns
    urgency_matches = []
    for pattern in URGENCY_PATTERNS:
        matches = pattern.findall(visible_text)
        if matches:
            for m in matches[:2]:
                urgency_matches.append(m if isinstance(m, str) else " ".join(m) if isinstance(m, tuple) else str(m))

    # Detect brand mentions
    brand_keywords = [
        "paypal", "microsoft", "apple", "google", "amazon", "netflix",
        "facebook", "instagram", "linkedin", "twitter", "whatsapp",
        "bank", "wells fargo", "chase", "citibank", "hsbc",
        "binance", "coinbase", "metamask", "blockchain",
    ]
    detected_brands = [b for b in brand_keywords if b in visible_text_lower]

    # Login/auth language
    login_keywords = ["sign in", "log in", "login", "sign on", "authenticate", "enter your password",
                       "enter your credentials", "verify your identity", "confirm your account"]
    login_matches = [kw for kw in login_keywords if kw in visible_text_lower]

    # Payment language
    payment_keywords = ["credit card", "debit card", "card number", "expiry date", "cvv",
                         "billing address", "payment method", "bank account", "wire transfer"]
    payment_matches = [kw for kw in payment_keywords if kw in visible_text_lower]

    return {
        "status": "analyzed",
        "text_length": len(visible_text),
        "urgency_indicators": urgency_matches[:5],
        "has_urgency_language": len(urgency_matches) > 0,
        "detected_brands": detected_brands[:5],
        "login_language": login_matches[:5],
        "has_login_language": len(login_matches) > 0,
        "payment_language": payment_matches[:5],
        "has_payment_language": len(payment_matches) > 0,
    }


# ── Master Analysis Function ────────────────────────────────────────────────

def analyze_webpage(fetch_result: Dict[str, Any]) -> Dict[str, Any]:
    """
    Run the complete webpage analysis pipeline ONLY if webpage content was
    successfully retrieved via HTTP/HTTPS.
    
    If fetching failed, strictly returns WEBPAGE STATUS: UNAVAILABLE with the
    actual failure reason and ZERO generated/fabricated webpage findings.
    """
    fetch_status = fetch_result.get("fetch_status")
    html = (fetch_result.get("html_content") or fetch_result.get("html", "") or "").strip()

    # Strictly enforce pipeline: fetch MUST be FETCH_SUCCESS and content must be present
    if fetch_status != "FETCH_SUCCESS" or not html:
        reason = fetch_status or "NETWORK_ERROR"
        detail = fetch_result.get("fetch_status_detail") or "Webpage could not be retrieved"
        return {
            "status": "UNAVAILABLE",
            "webpage_status": "UNAVAILABLE",
            "reason": reason,
            "reason_detail": detail,
            "message": "Webpage could not be retrieved, so webpage-level analysis was not performed.",
            "fetch_status": reason,
            "http_status": fetch_result.get("http_status"),
            "target_url": fetch_result.get("target_url"),
            "final_url": fetch_result.get("final_url"),
            "html_analysis": None,
            "form_analysis": None,
            "script_analysis": None,
            "iframe_analysis": None,
            "resource_analysis": None,
            "header_analysis": None,
            "content_analysis": None,
        }

    page_url = fetch_result.get("final_url") or fetch_result.get("normalized_url") or fetch_result.get("target_url", "")
    security_hdrs = fetch_result.get("security_headers") or fetch_result.get("headers", {})
    response_hdrs = fetch_result.get("response_headers") or fetch_result.get("headers", {})

    return {
        "status": "analyzed",
        "webpage_status": "AVAILABLE",
        "fetch_status": "FETCH_SUCCESS",
        "html_analysis": analyze_html_structure(html, page_url),
        "form_analysis": analyze_forms(html, page_url),
        "script_analysis": analyze_scripts(html, page_url),
        "iframe_analysis": analyze_iframes(html, page_url),
        "resource_analysis": analyze_external_resources(html, page_url),
        "header_analysis": analyze_security_headers(security_hdrs, response_hdrs),
        "content_analysis": analyze_page_content(html, page_url),
    }
