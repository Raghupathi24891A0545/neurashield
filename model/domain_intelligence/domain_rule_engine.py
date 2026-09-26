"""
NEURASHIELD - MODULE 2: DOMAIN INTELLIGENCE RULE ENGINE
Domain-specific security rules. Each rule has: ID, title, severity,
explanation, evidence, source, confidence.
A single signal does NOT automatically mean malicious.
"""

from typing import Dict, Any, List


DOMAIN_RULE_CATALOG = {
    'DOM-001': {
        'rule_id': 'DOM-001',
        'category': 'Domain Age',
        'severity': 'HIGH',
        'title': 'Extremely Young Domain',
        'description': 'Domain was registered very recently (less than 30 days ago).',
        'confidence': 0.75,
    },
    'DOM-002': {
        'rule_id': 'DOM-002',
        'category': 'Registration',
        'severity': 'MEDIUM',
        'title': 'No Registrar Information Available',
        'description': 'WHOIS registrar information could not be retrieved for this domain.',
        'confidence': 0.50,
    },
    'DOM-003': {
        'rule_id': 'DOM-003',
        'category': 'DNS',
        'severity': 'MEDIUM',
        'title': 'No MX Records',
        'description': 'Domain has no MX records configured, suggesting it cannot receive email.',
        'confidence': 0.45,
    },
    'DOM-004': {
        'rule_id': 'DOM-004',
        'category': 'SSL/TLS',
        'severity': 'HIGH',
        'title': 'Certificate Hostname Mismatch',
        'description': 'SSL/TLS certificate does not cover this domain name.',
        'confidence': 0.80,
    },
    'DOM-005': {
        'rule_id': 'DOM-005',
        'category': 'SSL/TLS',
        'severity': 'MEDIUM',
        'title': 'Invalid or Expired Certificate',
        'description': 'SSL/TLS certificate failed validation (expired, self-signed, or chain error).',
        'confidence': 0.65,
    },
    'DOM-006': {
        'rule_id': 'DOM-006',
        'category': 'Domain Lifecycle',
        'severity': 'INFORMATIONAL',
        'title': 'Near Registration Expiry',
        'description': "The domain's current registration period expires within the configured observation window. This is a domain lifecycle observation and is not independently indicative of malicious activity.",
        'confidence': 0.30,
        'security_significance': 'LOW',
        'risk_contribution': 0,
    },
    'DOM-007': {
        'rule_id': 'DOM-007',
        'category': 'DNS',
        'severity': 'HIGH',
        'title': 'DNS Resolution Failed',
        'description': 'Domain does not resolve to any IP address via DNS.',
        'confidence': 0.70,
    },
    'DOM-008': {
        'rule_id': 'DOM-008',
        'category': 'DNS Infrastructure',
        'severity': 'INFORMATIONAL',
        'title': 'Nameserver Provider Concentration',
        'description': 'All authoritative nameservers belong to the same provider domain. This is an infrastructure characteristic and is not independently indicative of malicious activity.',
        'confidence': 0.25,
        'security_significance': 'LOW',
        'risk_contribution': 0,
    },
    'DOM-009': {
        'rule_id': 'DOM-009',
        'category': 'SSL/TLS',
        'severity': 'MEDIUM',
        'title': 'No SSL/TLS Certificate Available',
        'description': 'Domain does not present an SSL/TLS certificate on port 443.',
        'confidence': 0.50,
    },
    'DOM-010': {
        'rule_id': 'DOM-010',
        'category': 'Domain Age',
        'severity': 'MEDIUM',
        'title': 'Young Domain with Free TLS',
        'description': 'Domain was registered less than 90 days ago and uses a free certificate issuer.',
        'confidence': 0.60,
    },
}

FREE_CA_ISSUERS = [
    "let's encrypt", "letsencrypt", "r3", "r10", "r11", "e5", "e6",
    "zerossl", "buypass", "cloudflare",
    "sectigo", "comodo",  # Some free tiers
]

SEVERITY_WEIGHTS = {'CRITICAL': 4, 'HIGH': 3, 'MEDIUM': 2, 'LOW': 1, 'INFORMATIONAL': 0, 'NONE': 0}


def evaluate_domain_rules(domain_analysis: Dict[str, Any]) -> Dict[str, Any]:
    """
    Evaluate domain-specific security rules against collected intelligence.
    Returns structured rule findings with evidence.
    """
    rules_hit: List[Dict[str, Any]] = []
    evidence: List[Dict[str, Any]] = []

    dns = domain_analysis.get('dns', {})
    reg = domain_analysis.get('registration', {})
    ssl_data = domain_analysis.get('ssl', {})
    ns = domain_analysis.get('nameservers', {})
    domain = domain_analysis.get('domain', '')

    # DOM-001: Extremely young domain (< 30 days)
    domain_age = reg.get('domain_age_days')
    if domain_age is not None and domain_age < 30:
        r = dict(DOMAIN_RULE_CATALOG['DOM-001'])
        r['evidence'] = f"Domain '{domain}' is only {domain_age} days old."
        rules_hit.append(r)
        evidence.append({
            'signal': 'young_domain',
            'severity': 'high',
            'source': 'domain_intelligence',
            'what': f'Domain registered {domain_age} days ago.',
            'where': 'WHOIS registration data',
            'why': 'Very recently registered domains are frequently used in disposable phishing campaigns.',
        })

    # DOM-002: No registrar info
    if reg.get('collection_status') == 'success' and not reg.get('registrar_present', False):
        r = dict(DOMAIN_RULE_CATALOG['DOM-002'])
        r['evidence'] = f"No registrar information found for '{domain}'."
        rules_hit.append(r)
        evidence.append({
            'signal': 'no_registrar',
            'severity': 'medium',
            'source': 'domain_intelligence',
            'what': 'WHOIS registrar information unavailable.',
            'where': 'WHOIS data',
            'why': 'Privacy-protected or missing registration data limits accountability assessment.',
        })

    # DOM-003: No MX records
    if dns.get('collection_status') == 'success' and dns.get('mx_record_count', 0) == 0:
        r = dict(DOMAIN_RULE_CATALOG['DOM-003'])
        r['evidence'] = f"No MX records found for '{domain}'."
        rules_hit.append(r)
        evidence.append({
            'signal': 'no_mx_records',
            'severity': 'medium',
            'source': 'domain_intelligence',
            'what': 'No mail exchange (MX) records configured.',
            'where': 'DNS records',
            'why': 'Legitimate organizations typically configure email capability on their domains.',
        })

    # DOM-004: Certificate hostname mismatch
    if ssl_data.get('ssl_available') and not ssl_data.get('certificate_hostname_match', True):
        r = dict(DOMAIN_RULE_CATALOG['DOM-004'])
        r['evidence'] = f"Certificate does not cover '{domain}'. Subject: {ssl_data.get('certificate_subject', 'unknown')}"
        rules_hit.append(r)
        evidence.append({
            'signal': 'cert_mismatch',
            'severity': 'high',
            'source': 'domain_intelligence',
            'what': f"SSL certificate does not match domain '{domain}'.",
            'where': 'SSL/TLS certificate',
            'why': 'Certificate mismatch may indicate shared hosting misconfiguration or domain spoofing.',
        })

    # DOM-005: Invalid certificate
    if ssl_data.get('ssl_available') and not ssl_data.get('ssl_valid', True):
        r = dict(DOMAIN_RULE_CATALOG['DOM-005'])
        r['evidence'] = f"Certificate validation failed for '{domain}'."
        rules_hit.append(r)
        evidence.append({
            'signal': 'invalid_certificate',
            'severity': 'medium',
            'source': 'domain_intelligence',
            'what': 'SSL/TLS certificate failed validation.',
            'where': 'SSL/TLS certificate',
            'why': 'Invalid certificates indicate expired, self-signed, or improperly chained certificates.',
        })

    # DOM-006: Near Registration Expiry (< 90 days remaining)
    remaining = reg.get('remaining_lifetime_days')
    if remaining is not None and 0 < remaining < 90:
        r = dict(DOMAIN_RULE_CATALOG['DOM-006'])
        r['evidence'] = f"Current registration expires in approximately {remaining} days."
        r['observation'] = f"Domain expires in approximately {remaining} days."
        r['interpretation'] = "This describes the current registration lifecycle."
        r['security_significance'] = "LOW"
        r['risk_contribution'] = 0
        rules_hit.append(r)
        evidence.append({
            'signal': 'near_registration_expiry',
            'severity': 'informational',
            'source': 'domain_intelligence',
            'what': f'Current registration expires in approximately {remaining} days.',
            'where': 'WHOIS expiration lifecycle',
            'why': "The domain's current registration period expires within the configured observation window. This is a domain lifecycle observation and is not independently indicative of malicious activity.",
            'observation': f'Domain expires in approximately {remaining} days.',
            'interpretation': 'This describes the current registration lifecycle.',
            'security_significance': 'LOW',
            'risk_contribution': 0,
        })

    # DOM-007: DNS resolution failed
    if not dns.get('dns_resolution', True) and dns.get('collection_status') not in ('unavailable', 'library_unavailable'):
        r = dict(DOMAIN_RULE_CATALOG['DOM-007'])
        r['evidence'] = f"DNS resolution failed for '{domain}'. Status: {dns.get('collection_status')}"
        rules_hit.append(r)
        evidence.append({
            'signal': 'dns_failure',
            'severity': 'high',
            'source': 'domain_intelligence',
            'what': 'Domain does not resolve via DNS.',
            'where': 'DNS resolution',
            'why': 'Domains that cannot be resolved may be recently expired, suspended, or misconfigured.',
        })

    # DOM-008: Nameserver Provider Concentration (only 1 NS provider)
    ns_diversity = ns.get('nameserver_diversity', 0)
    ns_count = ns.get('nameserver_count', 0)
    if ns_count > 1 and ns_diversity <= 1:
        r = dict(DOMAIN_RULE_CATALOG['DOM-008'])
        obs_text = f"Both authoritative nameservers belong to the same provider domain." if ns_count == 2 else f"All {ns_count} authoritative nameservers belong to the same provider domain."
        r['evidence'] = f"All {ns_count} authoritative nameservers belong to the same provider domain."
        r['observation'] = obs_text
        r['interpretation'] = "The domain uses a single nameserver provider."
        r['security_significance'] = "LOW"
        r['risk_contribution'] = 0
        rules_hit.append(r)
        evidence.append({
            'signal': 'ns_provider_concentration',
            'severity': 'informational',
            'source': 'domain_intelligence',
            'what': f'All {ns_count} authoritative nameservers belong to the same provider domain.',
            'where': 'Authoritative nameserver records',
            'why': 'All authoritative nameservers belong to the same provider domain. This is an infrastructure characteristic and is not independently indicative of malicious activity.',
            'observation': obs_text,
            'interpretation': 'The domain uses a single nameserver provider.',
            'security_significance': 'LOW',
            'risk_contribution': 0,
        })

    # DOM-009: No SSL/TLS
    if not ssl_data.get('ssl_available', False) and ssl_data.get('collection_status') not in ('unavailable', 'library_unavailable'):
        r = dict(DOMAIN_RULE_CATALOG['DOM-009'])
        r['evidence'] = f"No SSL/TLS certificate on port 443. Status: {ssl_data.get('collection_status')}"
        rules_hit.append(r)
        evidence.append({
            'signal': 'no_ssl',
            'severity': 'medium',
            'source': 'domain_intelligence',
            'what': 'No SSL/TLS certificate available.',
            'where': 'Port 443',
            'why': 'While HTTPS alone does not prove legitimacy, its absence is increasingly unusual for active websites.',
        })

    # DOM-010: Young domain + free CA
    issuer = (ssl_data.get('certificate_issuer') or '').lower()
    is_free_ca = any(ca in issuer for ca in FREE_CA_ISSUERS)
    if domain_age is not None and domain_age < 90 and is_free_ca:
        r = dict(DOMAIN_RULE_CATALOG['DOM-010'])
        r['evidence'] = f"Domain is {domain_age} days old with free CA issuer: {ssl_data.get('certificate_issuer', '')}"
        rules_hit.append(r)
        evidence.append({
            'signal': 'young_domain_free_cert',
            'severity': 'medium',
            'source': 'domain_intelligence',
            'what': f'Young domain ({domain_age}d) with free certificate ({ssl_data.get("certificate_issuer", "")}).',
            'where': 'WHOIS + SSL/TLS',
            'why': 'Phishing domains often combine recent registration with free automated certificates.',
        })

    # Sort by severity
    rules_hit.sort(key=lambda x: SEVERITY_WEIGHTS.get(x.get('severity', 'NONE'), 0), reverse=True)

    # Compute domain rule score (only threat rules contribute to malicious risk score)
    score = 0
    for r in rules_hit:
        sev = r.get('severity', 'NONE').upper()
        if sev == 'CRITICAL': score += 35
        elif sev == 'HIGH': score += 22
        elif sev == 'MEDIUM': score += 12
        elif sev == 'LOW': score += 5
        elif sev == 'INFORMATIONAL': score += 0
    score = min(100, score)

    threat_rules = [r for r in rules_hit if r.get('severity') != 'INFORMATIONAL']
    info_rules = [r for r in rules_hit if r.get('severity') == 'INFORMATIONAL']

    top_sev = 'NONE'
    for sev in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']:
        if any(r.get('severity', '').upper() == sev for r in threat_rules):
            top_sev = sev
            break
    if top_sev == 'NONE' and info_rules:
        top_sev = 'INFORMATIONAL'

    risk_factors = []
    if domain_age is not None:
        if domain_age < 30:
            risk_factors.append(f"Domain age: high concern ({domain_age} days old)")
        elif domain_age < 180:
            risk_factors.append(f"Domain age: moderate concern ({domain_age} days old)")
        else:
            risk_factors.append(f"Domain age: established ({domain_age} days old / ~{round(domain_age/365.25, 1)} yrs)")
    else:
        risk_factors.append("Domain age: unverified (WHOIS registration date unavailable)")

    if ssl_data.get('ssl_available'):
        if ssl_data.get('ssl_valid'):
            risk_factors.append("TLS: valid transport encryption (Note: does not verify site legitimacy)")
        else:
            risk_factors.append("TLS: invalid or untrusted certificate")
    else:
        risk_factors.append("TLS: no certificate present on port 443")

    if dns.get('dns_resolution'):
        risk_factors.append(f"DNS: resolved ({dns.get('a_record_count', 0)} IPv4 address(es))")
    else:
        risk_factors.append(f"DNS: unresolved ({dns.get('collection_status', 'failed')})")

    if reg.get('registrar_present'):
        risk_factors.append(f"Registration: registrar verified ({reg.get('registrar', '')})")
    else:
        risk_factors.append("Registration: registrar not verified")

    return {
        'triggered': len(threat_rules) > 0,
        'rules_hit': rules_hit,
        'threat_rules_hit': threat_rules,
        'info_rules_hit': info_rules,
        'count': len(rules_hit),
        'threat_count': len(threat_rules),
        'observation_count': len(info_rules),
        'severity': top_sev,
        'risk_score': score,
        'evidence': evidence,
        'top_signals': [e['what'] for e in evidence if e.get('severity') != 'informational'][:4] or [e['what'] for e in evidence[:2]],
        'risk_factors': risk_factors,
    }
