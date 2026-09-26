"""
NEURASHIELD - MODULE 2: DOMAIN FEATURE EXTRACTION
Extracts numerical and structural features from domain intelligence results
for real-time ML inference and model evaluation.
"""

import math
from typing import Dict, Any, List, Optional
import numpy as np
import pandas as pd


DOMAIN_MODEL_FEATURES = [
    'dns_resolution', 'a_record_count', 'aaaa_record_count',
    'mx_record_count', 'ns_record_count', 'txt_record_count',
    'ip_count', 'has_mx', 'has_multiple_ips',
    'domain_age_days', 'domain_remaining_days',
    'registrar_present', 'expiration_available',
    'nameserver_count', 'nameserver_diversity',
    'ssl_available', 'ssl_valid',
    'certificate_age_days', 'certificate_remaining_days',
    'certificate_san_count', 'certificate_hostname_match',
    'certificate_is_wildcard',
    'tld_length', 'domain_name_length', 'domain_name_entropy',
    'domain_has_digits', 'domain_digit_ratio', 'domain_hyphen_count',
    'dns_collection_success', 'whois_collection_success', 'ssl_collection_success',
    'evidence_coverage',
]


def _shannon_entropy(s: str) -> float:
    """Calculate Shannon entropy of a string."""
    if not s:
        return 0.0
    freq = {}
    for c in s:
        freq[c] = freq.get(c, 0) + 1
    n = len(s)
    return round(-sum((v / n) * math.log2(v / n) for v in freq.values()), 4)


def _extract_tld(domain: str) -> str:
    """Extract top-level domain suffix."""
    parts = domain.rsplit('.', 1)
    return parts[-1] if len(parts) > 1 else ''


def _extract_domain_name(domain: str) -> str:
    """Extract domain name without TLD."""
    parts = domain.rsplit('.', 1)
    return parts[0] if len(parts) > 1 else domain


def extract_domain_features(analysis: Dict[str, Any]) -> Dict[str, Any]:
    """
    Transforms domain intelligence analysis output into a feature dictionary
    matching the training schema DOMAIN_MODEL_FEATURES.
    """
    domain = analysis.get('domain', '')
    dns_data = analysis.get('dns', {})
    ip_data = analysis.get('ip', {})
    reg_data = analysis.get('registration', {})
    ssl_data = analysis.get('ssl', {})
    ns_data = analysis.get('nameservers', {})

    features: Dict[str, Any] = {'domain': domain}

    # DNS features
    features['dns_resolution'] = 1 if dns_data.get('dns_resolution', False) else 0
    features['a_record_count'] = dns_data.get('a_record_count', 0)
    features['aaaa_record_count'] = dns_data.get('aaaa_record_count', 0)
    features['mx_record_count'] = dns_data.get('mx_record_count', 0)
    features['ns_record_count'] = dns_data.get('ns_record_count', 0)
    features['txt_record_count'] = dns_data.get('txt_record_count', 0)
    features['has_mx'] = 1 if features['mx_record_count'] > 0 else 0
    features['dns_collection_success'] = 1 if dns_data.get('collection_status') == 'success' else 0

    # IP features
    features['ip_count'] = ip_data.get('ip_count', 0)
    features['has_multiple_ips'] = 1 if features['ip_count'] > 1 else 0

    # Registration features
    features['domain_age_days'] = float(reg_data['domain_age_days']) if reg_data.get('domain_age_days') is not None else None
    features['domain_remaining_days'] = float(reg_data['remaining_lifetime_days']) if reg_data.get('remaining_lifetime_days') is not None else None
    features['registrar_present'] = 1 if reg_data.get('registrar_present', False) else 0
    features['expiration_available'] = 1 if reg_data.get('expiration_available', False) else 0
    features['whois_collection_success'] = 1 if reg_data.get('collection_status') == 'success' else 0

    # Nameservers
    features['nameserver_count'] = ns_data.get('nameserver_count', 0)
    features['nameserver_diversity'] = ns_data.get('nameserver_diversity', 0)

    # SSL / TLS
    features['ssl_available'] = 1 if ssl_data.get('ssl_available', False) else 0
    features['ssl_valid'] = 1 if ssl_data.get('ssl_valid', False) else 0
    features['certificate_age_days'] = float(ssl_data['certificate_age_days']) if ssl_data.get('certificate_age_days') is not None else None
    features['certificate_remaining_days'] = float(ssl_data['certificate_remaining_days']) if ssl_data.get('certificate_remaining_days') is not None else None
    features['certificate_san_count'] = ssl_data.get('certificate_san_count', 0)
    features['certificate_hostname_match'] = 1 if ssl_data.get('certificate_hostname_match', False) else 0
    features['certificate_is_wildcard'] = 1 if ssl_data.get('certificate_is_wildcard', False) else 0
    features['ssl_collection_success'] = 1 if ssl_data.get('collection_status') == 'success' else 0

    # Lexical / Domain Name
    tld = _extract_tld(domain)
    domain_name = _extract_domain_name(domain)
    features['tld_length'] = len(tld)
    features['domain_name_length'] = len(domain_name)
    features['domain_name_entropy'] = _shannon_entropy(domain_name)
    features['domain_has_digits'] = 1 if any(c.isdigit() for c in domain_name) else 0
    features['domain_digit_ratio'] = round(
        sum(1 for c in domain_name if c.isdigit()) / max(len(domain_name), 1), 4
    )
    features['domain_hyphen_count'] = domain_name.count('-')

    # Evidence coverage
    features['evidence_coverage'] = analysis.get('evidence_coverage', 0)

    return features


def features_to_vector(features: Dict[str, Any], feature_names: Optional[List[str]] = None) -> pd.DataFrame:
    """
    Converts a features dictionary into a single-row DataFrame ordered by feature_names.
    Ensures missing values are properly cast as np.nan.
    """
    if feature_names is None:
        feature_names = DOMAIN_MODEL_FEATURES

    row = {}
    for col in feature_names:
        val = features.get(col, np.nan)
        if val is None:
            val = np.nan
        row[col] = [val]

    return pd.DataFrame(row)
