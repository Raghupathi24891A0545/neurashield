"""
NEURASHIELD — MODULE 1: SECURITY RULE ENGINE
Traceable deterministic security rules for URL Intelligence.
Produces structured findings with category, severity, evidence, and confidence.
"""

from typing import Dict, Any, List

RULE_CATALOG = {
    'HOMO-001': {
        'rule_id': 'HOMO-001',
        'category': 'Unicode / Homoglyph',
        'severity': 'CRITICAL',
        'title': 'Homoglyph / Visual Confusable Attack',
        'description': 'Hostname contains character substitutions designed to spoof trusted entity domains.',
        'confidence': 0.95
    },
    'BRAND-001': {
        'rule_id': 'BRAND-001',
        'category': 'Brand Impersonation Signal',
        'severity': 'CRITICAL',
        'title': 'Targeted Brand Impersonation',
        'description': 'A recognized high-value brand name appears in the subdomain or host but is not the root domain.',
        'confidence': 0.92
    },
    'SSRF-001': {
        'rule_id': 'SSRF-001',
        'category': 'Private Network / SSRF Risk',
        'severity': 'CRITICAL',
        'title': 'Localhost / Loopback Target (SSRF Risk)',
        'description': 'Destination points to a local loopback address (localhost / 127.0.0.1 / ::1 / 0.0.0.0). Poses severe Server-Side Request Forgery and internal system exposure risks.',
        'confidence': 0.98
    },
    'STRUC-001': {
        'rule_id': 'STRUC-001',
        'category': 'IP Host',
        'severity': 'HIGH',
        'title': 'Direct IP Address Hostname',
        'description': 'URL uses an IPv4 address instead of a registered domain name, bypassing DNS reputation.',
        'confidence': 0.90
    },
    'IDN-001': {
        'rule_id': 'IDN-001',
        'category': 'Unicode / Punycode',
        'severity': 'HIGH',
        'title': 'Punycode / IDN Encoded Domain',
        'description': 'Hostname uses Internationalized Domain Name (xn--) encoding, commonly used in deceptive lookalikes.',
        'confidence': 0.85
    },
    'ENCOD-001': {
        'rule_id': 'ENCOD-001',
        'category': 'Encoding & Obfuscation',
        'severity': 'HIGH',
        'title': 'Double URL Percent-Encoding',
        'description': 'URL contains nested percent-encoding (%25) to evade heuristic boundary filters.',
        'confidence': 0.88
    },
    'REDIR-002': {
        'rule_id': 'REDIR-002',
        'category': 'Redirect / Nesting',
        'severity': 'HIGH',
        'title': 'Open Redirect Parameter Pattern',
        'description': 'Query contains parameter names and targets associated with open redirect chains.',
        'confidence': 0.80
    },
    'REDIR-003': {
        'rule_id': 'REDIR-003',
        'category': 'Redirect / Nesting',
        'severity': 'HIGH',
        'title': 'Nested Destination URL in Query',
        'description': 'URL query string embeds a secondary full protocol URI (nested target payload).',
        'confidence': 0.85
    },
    'STRUC-002': {
        'rule_id': 'STRUC-002',
        'category': 'Credential Targeting',
        'severity': 'HIGH',
        'title': 'Credential Delimiter (@ Symbol)',
        'description': 'URL contains @ symbol which browsers may interpret as username/authority separator.',
        'confidence': 0.88
    },
    'LEXI-002': {
        'rule_id': 'LEXI-002',
        'category': 'Domain Syntax',
        'severity': 'HIGH',
        'title': 'Digit Substitution in Hostname',
        'description': 'Hostname embeds digits in domain labels resembling alphanumeric replacement tactics.',
        'confidence': 0.78
    },
    'KW-001': {
        'rule_id': 'KW-001',
        'category': 'Credential Targeting',
        'severity': 'HIGH',
        'title': 'Suspicious Keyword Cluster',
        'description': 'Multiple high-risk authentication/financial tokens identified across URL path and query.',
        'confidence': 0.82
    },
    'KW-002': {
        'rule_id': 'KW-002',
        'category': 'Keyword Anomaly',
        'severity': 'MEDIUM',
        'title': 'Suspicious Keyword Present',
        'description': 'High-risk security or credential keyword detected in URL path.',
        'confidence': 0.65
    },
    'TLD-001': {
        'rule_id': 'TLD-001',
        'category': 'Domain Syntax',
        'severity': 'MEDIUM',
        'title': 'High-Abuse Top-Level Domain (TLD)',
        'description': 'URL is registered under a TLD statistically correlated with high abuse and disposable campaigns.',
        'confidence': 0.70
    },
    'REDIR-001': {
        'rule_id': 'REDIR-001',
        'category': 'Redirect / Nesting',
        'severity': 'MEDIUM',
        'title': 'URL Shortener Intermediary',
        'description': 'URL uses a public URL shortening service that conceals the ultimate landing destination.',
        'confidence': 0.65
    },
    'STRUC-003': {
        'rule_id': 'STRUC-003',
        'category': 'URL Structure',
        'severity': 'MEDIUM',
        'title': 'Excessive Subdomain Depth',
        'description': 'Hostname contains 3 or more nested subdomains, often used to simulate legitimate structures.',
        'confidence': 0.72
    },
    'STRUC-004': {
        'rule_id': 'STRUC-004',
        'category': 'Suspicious Port',
        'severity': 'MEDIUM',
        'title': 'Non-Standard Web Service Port',
        'description': 'URL specifies an explicit non-standard port instead of 80/443.',
        'confidence': 0.75
    },
    'ENCOD-002': {
        'rule_id': 'ENCOD-002',
        'category': 'Encoding & Obfuscation',
        'severity': 'MEDIUM',
        'title': 'Obfuscated Path Separators',
        'description': 'Path contains percent-encoded slashes (%2F) or colons (%3A) to obscure URI hierarchy.',
        'confidence': 0.75
    },
    'LEXI-006': {
        'rule_id': 'LEXI-006',
        'category': 'Anomaly',
        'severity': 'MEDIUM',
        'title': 'Elevated Domain Character Entropy',
        'description': 'High Shannon entropy in domain name suggests machine-generated DGA or random hashing.',
        'confidence': 0.68
    },
    'STRUC-005': {
        'rule_id': 'STRUC-005',
        'category': 'URL Structure',
        'severity': 'LOW',
        'title': 'Elevated URL Length',
        'description': 'URL length exceeds 75 characters, often used in complex payload delivery or token padding.',
        'confidence': 0.50
    },
    'STRUC-006': {
        'rule_id': 'STRUC-006',
        'category': 'URL Structure',
        'severity': 'LOW',
        'title': 'Deep Path Segment Hierarchy',
        'description': 'URL path contains more than 4 hierarchy levels.',
        'confidence': 0.50
    },
    'LEXI-007': {
        'rule_id': 'LEXI-007',
        'category': 'Domain Syntax',
        'severity': 'LOW',
        'title': 'Excessive Domain Hyphenation',
        'description': 'Domain label contains 2 or more hyphens, common in brand keyword concatenation.',
        'confidence': 0.55
    }
}

SEVERITY_WEIGHTS = {
    'CRITICAL': 4,
    'HIGH': 3,
    'MEDIUM': 2,
    'LOW': 1,
    'NONE': 0
}


def evaluate_security_rules(url: str, features: Dict[str, Any]) -> Dict[str, Any]:
    """
    Evaluates all deterministic security rules against the extracted URL features.
    Returns structured rule findings, evidence items, and rule score.
    """
    import re
    rules_hit: List[Dict[str, Any]] = []
    evidence: List[Dict[str, Any]] = []

    # 0. Localhost / Loopback / SSRF Check
    host_raw = (features.get('domain') or '').lower().strip().split(':')[0]
    is_lh = bool(
        features.get('is_localhost', 0) or
        host_raw in ('localhost', 'localhost.localdomain', '127.0.0.1', '::1', '0.0.0.0') or
        host_raw.endswith('.localhost') or
        re.match(r'^127\.\d{1,3}\.\d{1,3}\.\d{1,3}$', host_raw)
    )
    if is_lh:
        r = dict(RULE_CATALOG['SSRF-001'])
        r['evidence'] = f"Destination host '{host_raw}' is an internal loopback / localhost target (SSRF vector)."
        rules_hit.append(r)
        evidence.append({
            'signal': 'localhost_loopback_target',
            'severity': 'critical',
            'source': 'url_intelligence',
            'what': 'Localhost / Loopback target detected.',
            'where': f"Host: {host_raw}",
            'why': 'Localhost and 127.0.0.1 are strictly for internal system operations. External links targeting localhost are commonly leveraged for Server-Side Request Forgery (SSRF), internal port scanning, or evading reputation filters.'
        })

    # 1. Unicode Homograph
    if features.get('homograph', 0):
        r = dict(RULE_CATALOG['HOMO-001'])
        r['evidence'] = f"Hostname '{features.get('domain', '')}' matches known homoglyph or visual confusable pattern."
        rules_hit.append(r)
        evidence.append({
            'signal': 'unicode_homoglyph',
            'severity': 'critical',
            'source': 'url_intelligence',
            'what': 'Visual homoglyph / character substitution detected in hostname.',
            'where': f"Host: {features.get('domain', '')}",
            'why': 'Attackers use visually identical characters from other alphabets or numbers to spoof legitimate domains.'
        })

    # 2. Brand Impersonation
    brand_imp = features.get('brand_impersonation', 0)
    brand_list = features.get('brand_list', [])
    if brand_imp and brand_list:
        r = dict(RULE_CATALOG['BRAND-001'])
        r['evidence'] = f"Brand token '{brand_list[0]}' found in host '{features.get('domain', '')}' without matching registered domain."
        rules_hit.append(r)
        evidence.append({
            'signal': 'brand_impersonation',
            'severity': 'critical',
            'source': 'url_intelligence',
            'what': f"High-profile brand '{brand_list[0]}' detected outside registered domain.",
            'where': f"Domain: {features.get('domain', '')}",
            'why': 'Deceptive placement of brand names in subdomains or misleading hosts is a primary phishing technique.'
        })

    # 3. IP Host
    if features.get('has_ip', 0):
        r = dict(RULE_CATALOG['STRUC-001'])
        r['evidence'] = f"Hostname '{features.get('domain', '')}' is a raw IP address."
        rules_hit.append(r)
        evidence.append({
            'signal': 'ip_as_host',
            'severity': 'high',
            'source': 'url_intelligence',
            'what': 'Raw IPv4 address used as destination host.',
            'where': f"Host: {features.get('domain', '')}",
            'why': 'Legitimate organizations rarely use bare IP addresses for customer-facing services.'
        })

    # 4. Punycode IDN
    if features.get('punycode', 0) or 'xn--' in features.get('domain', ''):
        r = dict(RULE_CATALOG['IDN-001'])
        r['evidence'] = f"Hostname contains Punycode prefix 'xn--'."
        rules_hit.append(r)
        evidence.append({
            'signal': 'punycode_domain',
            'severity': 'high',
            'source': 'url_intelligence',
            'what': 'Internationalized Domain Name (Punycode) detected.',
            'where': f"Host: {features.get('domain', '')}",
            'why': 'Punycode allows international characters that look identical to ASCII characters (IDN homograph attack).'
        })

    # 5. Double Encoding
    if features.get('double_encoding', 0):
        r = dict(RULE_CATALOG['ENCOD-001'])
        r['evidence'] = "Found nested percent-encoding '%25' sequence in URL."
        rules_hit.append(r)
        evidence.append({
            'signal': 'double_url_encoding',
            'severity': 'high',
            'source': 'url_intelligence',
            'what': 'Double percent-encoding (%25) present in target URL.',
            'where': 'URL string / query parameters',
            'why': 'Double encoding is often used to bypass Web Application Firewalls and boundary inspection filters.'
        })

    # 6. Nested URL / Redirect
    if features.get('nested_url', 0):
        r = dict(RULE_CATALOG['REDIR-003'])
        r['evidence'] = "Secondary URL scheme embedded inside query or path payload."
        rules_hit.append(r)
        evidence.append({
            'signal': 'nested_destination_url',
            'severity': 'high',
            'source': 'url_intelligence',
            'what': 'Nested URL payload embedded within query string.',
            'where': 'Query string payload',
            'why': 'Nested URLs can be used for open redirect exploitation or stealthy redirection to phishing landing kits.'
        })
    elif features.get('has_redirect', 0):
        r = dict(RULE_CATALOG['REDIR-002'])
        r['evidence'] = "Query parameters contain known open redirect parameter names (e.g. redirect=, url=, next=)."
        rules_hit.append(r)
        evidence.append({
            'signal': 'open_redirect_parameter',
            'severity': 'high',
            'source': 'url_intelligence',
            'what': 'Open redirect parameter detected.',
            'where': 'Query parameters',
            'why': 'Open redirects enable attackers to abuse reputable domains to bounce users to fraudulent sites.'
        })

    # 7. @ Symbol
    if features.get('at_count', 0) > 0:
        r = dict(RULE_CATALOG['STRUC-002'])
        r['evidence'] = f"Found {features.get('at_count')} '@' symbol(s) in URL."
        rules_hit.append(r)
        evidence.append({
            'signal': 'at_symbol_credential',
            'severity': 'high',
            'source': 'url_intelligence',
            'what': 'URL contains "@" character in authority/path structure.',
            'where': 'URL authority / path',
            'why': 'The "@" character in URLs can trick browsers into treating preceding text as credentials, obscuring real destination.'
        })

    # 8. Digit substitution in domain
    if features.get('digit_in_domain', 0) and not features.get('has_ip', 0):
        r = dict(RULE_CATALOG['LEXI-002'])
        r['evidence'] = f"Domain label contains digits: '{features.get('domain_name', '')}'."
        rules_hit.append(r)
        evidence.append({
            'signal': 'digit_in_domain_label',
            'severity': 'high',
            'source': 'url_intelligence',
            'what': 'Numeric characters detected inside domain label.',
            'where': f"Domain: {features.get('domain_name', '')}",
            'why': 'Replacing letters with visually similar numbers (e.g. 0 for o, 1 for l) is a standard typosquatting technique.'
        })

    # 9. Suspicious Keywords
    sw_list = features.get('suspicious_word_list', [])
    if len(sw_list) >= 2:
        r = dict(RULE_CATALOG['KW-001'])
        r['evidence'] = f"Multiple authentication/security keywords detected: {', '.join(sw_list[:4])}."
        rules_hit.append(r)
        evidence.append({
            'signal': 'suspicious_keyword_cluster',
            'severity': 'high',
            'source': 'url_intelligence',
            'what': f"High-risk keyword cluster: {', '.join(sw_list[:4])}.",
            'where': 'Path & Query parameters',
            'why': 'Phishing lures frequently combine security/urgency terms such as verify, account, update, and secure.'
        })
    elif len(sw_list) == 1:
        r = dict(RULE_CATALOG['KW-002'])
        r['evidence'] = f"Suspicious keyword identified: '{sw_list[0]}'."
        rules_hit.append(r)
        evidence.append({
            'signal': 'suspicious_keyword_present',
            'severity': 'medium',
            'source': 'url_intelligence',
            'what': f"Security/authentication keyword '{sw_list[0]}' found in URL.",
            'where': 'Path / Query',
            'why': 'Authentication keywords in untrusted domains provide a contextual lure indicator.'
        })

    # 10. Suspicious TLD
    if features.get('suspicious_tld', 0):
        r = dict(RULE_CATALOG['TLD-001'])
        r['evidence'] = f"URL registered under high-abuse TLD '{features.get('tld', '')}'."
        rules_hit.append(r)
        evidence.append({
            'signal': 'high_abuse_tld',
            'severity': 'medium',
            'source': 'url_intelligence',
            'what': f"Abuse-prone TLD extension {features.get('tld', '')}.",
            'where': f"TLD: {features.get('tld', '')}",
            'why': 'Certain low-cost or unmoderated top-level domains are heavily leveraged for disposable phishing campaigns.'
        })

    # 11. URL Shortener
    if features.get('is_url_shortener', 0):
        r = dict(RULE_CATALOG['REDIR-001'])
        r['evidence'] = f"Known link shortener service domain '{features.get('domain', '')}'."
        rules_hit.append(r)
        evidence.append({
            'signal': 'url_shortener_hiding',
            'severity': 'medium',
            'source': 'url_intelligence',
            'what': 'Link shortening service detected.',
            'where': f"Domain: {features.get('domain', '')}",
            'why': 'Shortened links mask the true destination domain, preventing inspection prior to resolution.'
        })

    # 12. Excessive Subdomains
    sub_count = features.get('subdomain_count', 0)
    if sub_count >= 3:
        r = dict(RULE_CATALOG['STRUC-003'])
        r['evidence'] = f"{sub_count} nested subdomains found ('{features.get('subdomain', '')}')."
        rules_hit.append(r)
        evidence.append({
            'signal': 'excessive_subdomain_depth',
            'severity': 'medium',
            'source': 'url_intelligence',
            'what': f"Deep subdomain hierarchy ({sub_count} subdomains).",
            'where': f"Subdomains: {features.get('subdomain', '')}",
            'why': 'Phishers use multiple subdomains to mimic genuine host hierarchies or hide behind wildcard DNS.'
        })

    # 13. Non-Standard Port
    if features.get('has_port', 0):
        r = dict(RULE_CATALOG['STRUC-004'])
        r['evidence'] = "URL specifies an explicit non-standard port."
        rules_hit.append(r)
        evidence.append({
            'signal': 'non_standard_port',
            'severity': 'medium',
            'source': 'url_intelligence',
            'what': 'Non-standard port number declared in URL.',
            'where': 'Authority component',
            'why': 'Services running on arbitrary non-standard ports often evade standard enterprise egress filtering.'
        })

    # 14. Encoded Path Separators
    if features.get('encoded_separators', 0):
        r = dict(RULE_CATALOG['ENCOD-002'])
        r['evidence'] = "Encoded path separators (%2F or %3A) detected in URL."
        rules_hit.append(r)
        evidence.append({
            'signal': 'encoded_path_separators',
            'severity': 'medium',
            'source': 'url_intelligence',
            'what': 'Percent-encoded path separators (%2F, %3A) detected.',
            'where': 'URL path / query',
            'why': 'Encoding slashes hides actual path boundaries from signature-based intrusion detection systems.'
        })

    # 15. Domain Entropy
    dom_entropy = features.get('domain_entropy', 0)
    if dom_entropy > 3.6:
        r = dict(RULE_CATALOG['LEXI-006'])
        r['evidence'] = f"Domain entropy is {dom_entropy} (threshold: 3.6)."
        rules_hit.append(r)
        evidence.append({
            'signal': 'elevated_domain_entropy',
            'severity': 'medium',
            'source': 'url_intelligence',
            'what': f"High Shannon entropy ({dom_entropy}) in domain label.",
            'where': f"Domain: {features.get('domain_name', '')}",
            'why': 'Unusually randomized character distributions can indicate Domain Generation Algorithms (DGA) or fast-flux.'
        })

    # 16. URL Length
    url_len = features.get('url_length', 0)
    if url_len > 75:
        r = dict(RULE_CATALOG['STRUC-005'])
        r['evidence'] = f"URL length is {url_len} characters (threshold: 75)."
        rules_hit.append(r)

    # 17. Path Depth
    url_depth = features.get('url_depth', 0)
    if url_depth > 4:
        r = dict(RULE_CATALOG['STRUC-006'])
        r['evidence'] = f"Path hierarchy is {url_depth} levels deep."
        rules_hit.append(r)

    # 18. Excessive Hyphens in Domain
    hyphen_domain = features.get('hyphen_in_domain', 0)
    if hyphen_domain >= 2:
        r = dict(RULE_CATALOG['LEXI-007'])
        r['evidence'] = f"Domain contains {hyphen_domain} hyphens."
        rules_hit.append(r)

    # Sort rules by severity
    rules_hit.sort(key=lambda x: SEVERITY_WEIGHTS.get(x['severity'], 0), reverse=True)

    # Highest severity
    top_sev = 'NONE'
    if any(r['severity'] == 'CRITICAL' for r in rules_hit):
        top_sev = 'CRITICAL'
    elif any(r['severity'] == 'HIGH' for r in rules_hit):
        top_sev = 'HIGH'
    elif any(r['severity'] == 'MEDIUM' for r in rules_hit):
        top_sev = 'MEDIUM'
    elif any(r['severity'] == 'LOW' for r in rules_hit):
        top_sev = 'LOW'

    # Compute Rule Score (0-100)
    score = 0
    for r in rules_hit:
        sev = r['severity']
        if sev == 'CRITICAL':
            score += 35
        elif sev == 'HIGH':
            score += 22
        elif sev == 'MEDIUM':
            score += 12
        elif sev == 'LOW':
            score += 5
    score = min(100, score)
    if top_sev == 'CRITICAL':
        score = max(score, 75)
    elif top_sev == 'HIGH':
        score = max(score, 50)

    # Top contributing signals
    top_signals = [e['what'] for e in evidence[:4]]

    return {
        'triggered': len(rules_hit) > 0,
        'rules_hit': rules_hit,
        'count': len(rules_hit),
        'severity': top_sev,
        'risk_score': score,
        'evidence': evidence,
        'top_signals': top_signals
    }
