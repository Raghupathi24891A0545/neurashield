"""
NEURASHIELD - EXTENSIBLE RISK FUSION ENGINE
Combines multiple intelligence layers (URL Structure, Lexical, Rules, ML, Domain Intelligence, Webpage Intelligence)
into a unified composite threat risk score with dynamic weight redistribution.
"""

from typing import Dict, Any, List, Optional


def calculate_risk_level(score: float) -> str:
    """Classify numerical risk score into standard risk tier."""
    if score >= 70:
        return 'CRITICAL'
    if score >= 45:
        return 'HIGH'
    if score >= 20:
        return 'MEDIUM'
    return 'LOW'


def fuse_threat_layers(
    url_intelligence: Dict[str, Any],
    domain_intelligence: Optional[Dict[str, Any]] = None,
    domain_rules: Optional[Dict[str, Any]] = None,
    domain_ml: Optional[Dict[str, Any]] = None,
    webpage_rules: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """
    Perform multi-layer risk fusion across URL, Domain, and Webpage intelligence.
    Dynamically redistributes weights depending on active layers.
    """
    structural = url_intelligence.get('structural', {})
    lexical = url_intelligence.get('lexical', {})
    security_rules = url_intelligence.get('security_rules', {})
    ml = url_intelligence.get('ml_classifier', {})

    s_score = float(structural.get('risk_score', 0))
    l_score = float(lexical.get('risk_score', 0))
    r_score = float(security_rules.get('risk_score', 0))
    m_score = float(ml.get('risk_score', 0))

    has_domain = domain_intelligence is not None and domain_intelligence.get('overall_status') != 'failed'
    has_webpage = (
        webpage_rules is not None and
        webpage_rules.get('status') not in ('UNAVAILABLE', 'unavailable', 'not_active', 'failed') and
        webpage_rules.get('webpage_status') != 'UNAVAILABLE' and
        (webpage_rules.get('rules_hit') is not None or webpage_rules.get('triggered') is not None)
    )

    wp_reason = (webpage_rules.get('reason') or webpage_rules.get('fetch_status')) if webpage_rules else 'Webpage not retrieved'

    # Compute domain score
    d_score = 0.0
    if has_domain:
        d_rules_score = float(domain_rules.get('risk_score', 0)) if domain_rules else 0.0
        d_ml_score = float(domain_ml.get('risk_score', 0)) if domain_ml else 0.0
        if domain_ml and domain_ml.get('status') == 'success':
            d_score = round(0.50 * d_rules_score + 0.50 * d_ml_score)
        else:
            d_score = round(d_rules_score)

    # Compute webpage score
    w_score = 0.0
    if has_webpage:
        w_score = float(webpage_rules.get('risk_score', 0))

    # ── Weight distribution based on active layers ───────────────────────────

    if has_domain and has_webpage:
        # ALL 3 MODULES ACTIVE
        w_s, w_l, w_r, w_m, w_d, w_w = 0.10, 0.12, 0.13, 0.10, 0.25, 0.30
        composite_score = round(
            s_score * w_s + l_score * w_l + r_score * w_r +
            m_score * w_m + d_score * w_d + w_score * w_w
        )
        composite_score = max(0, min(100, composite_score))

        layers = [
            {'name': 'URL Structure', 'score': int(s_score), 'weight': w_s,
             'level': calculate_risk_level(s_score).lower(), 'status': 'complete', 'module': 'Module 1'},
            {'name': 'Lexical Intelligence', 'score': int(l_score), 'weight': w_l,
             'level': calculate_risk_level(l_score).lower(), 'status': 'complete', 'module': 'Module 1'},
            {'name': 'Security Rule Engine', 'score': int(r_score), 'weight': w_r,
             'level': calculate_risk_level(r_score).lower(), 'status': 'complete', 'module': 'Module 1'},
            {'name': 'ML Classifier', 'score': int(m_score), 'weight': w_m,
             'level': calculate_risk_level(m_score).lower(), 'status': 'complete', 'module': 'Module 1'},
            {'name': 'Domain Intelligence', 'score': int(d_score), 'weight': w_d,
             'level': calculate_risk_level(d_score).lower(), 'status': 'complete', 'module': 'Module 2'},
            {'name': 'Webpage Intelligence', 'score': int(w_score), 'weight': w_w,
             'level': calculate_risk_level(w_score).lower(), 'status': 'complete', 'module': 'Module 3'},
        ]

        explanation = (
            f"The composite risk score of {composite_score} was calculated using adaptive multi-layer fusion "
            f"across 6 active analytical layers: URL Structure (10%), Lexical Intelligence (12%), "
            f"Security Rule Engine (13%), URL ML Classifier (10%), Domain Intelligence (25%), "
            f"and Webpage Intelligence (30%). All three intelligence modules are actively integrated."
        )
        active_count = 6

    elif has_domain:
        w_s, w_l, w_r, w_m, w_d = 0.15, 0.20, 0.20, 0.15, 0.30
        composite_score = round(
            s_score * w_s + l_score * w_l + r_score * w_r +
            m_score * w_m + d_score * w_d
        )
        composite_score = max(0, min(100, composite_score))

        layers = [
            {'name': 'URL Structure', 'score': int(s_score), 'weight': w_s,
             'level': calculate_risk_level(s_score).lower(), 'status': 'complete', 'module': 'Module 1'},
            {'name': 'Lexical Intelligence', 'score': int(l_score), 'weight': w_l,
             'level': calculate_risk_level(l_score).lower(), 'status': 'complete', 'module': 'Module 1'},
            {'name': 'Security Rule Engine', 'score': int(r_score), 'weight': w_r,
             'level': calculate_risk_level(r_score).lower(), 'status': 'complete', 'module': 'Module 1'},
            {'name': 'ML Classifier', 'score': int(m_score), 'weight': w_m,
             'level': calculate_risk_level(m_score).lower(), 'status': 'complete', 'module': 'Module 1'},
            {'name': 'Domain Intelligence', 'score': int(d_score), 'weight': w_d,
             'level': calculate_risk_level(d_score).lower(), 'status': 'complete', 'module': 'Module 2'},
            {'name': 'Webpage Intelligence', 'score': None, 'weight': 0.0,
             'level': 'unavailable', 'status': 'UNAVAILABLE', 'reason': wp_reason,
             'coverage': 'Reduced', 'module': 'Module 3'},
        ]

        explanation = (
            f"The composite risk score of {composite_score} was calculated using adaptive multi-layer fusion "
            f"across 5 active analytical layers: URL Structure (15%), Lexical Intelligence (20%), "
            f"Security Rule Engine (20%), URL ML Classifier (15%), and Domain Intelligence (30%). "
            f"Webpage Intelligence is UNAVAILABLE ({wp_reason}) with Reduced evidence coverage; weights have been adaptively redistributed."
        )
        active_count = 5

    elif has_webpage:
        w_s, w_l, w_r, w_m, w_w = 0.12, 0.18, 0.18, 0.12, 0.40
        composite_score = round(
            s_score * w_s + l_score * w_l + r_score * w_r +
            m_score * w_m + w_score * w_w
        )
        composite_score = max(0, min(100, composite_score))

        layers = [
            {'name': 'URL Structure', 'score': int(s_score), 'weight': w_s,
             'level': calculate_risk_level(s_score).lower(), 'status': 'complete', 'module': 'Module 1'},
            {'name': 'Lexical Intelligence', 'score': int(l_score), 'weight': w_l,
             'level': calculate_risk_level(l_score).lower(), 'status': 'complete', 'module': 'Module 1'},
            {'name': 'Security Rule Engine', 'score': int(r_score), 'weight': w_r,
             'level': calculate_risk_level(r_score).lower(), 'status': 'complete', 'module': 'Module 1'},
            {'name': 'ML Classifier', 'score': int(m_score), 'weight': w_m,
             'level': calculate_risk_level(m_score).lower(), 'status': 'complete', 'module': 'Module 1'},
            {'name': 'Domain Intelligence', 'score': None, 'weight': 0.0,
             'level': 'unavailable', 'status': 'not_active', 'module': 'Module 2'},
            {'name': 'Webpage Intelligence', 'score': int(w_score), 'weight': w_w,
             'level': calculate_risk_level(w_score).lower(), 'status': 'complete', 'module': 'Module 3'},
        ]

        explanation = (
            f"The composite risk score of {composite_score} was calculated using adaptive multi-layer fusion "
            f"across 5 active analytical layers: URL Structure (12%), Lexical Intelligence (18%), "
            f"Security Rule Engine (18%), URL ML Classifier (12%), and Webpage Intelligence (40%)."
        )
        active_count = 5

    else:
        w_s, w_l, w_r, w_m = 0.20, 0.30, 0.25, 0.25
        composite_score = round(s_score * w_s + l_score * w_l + r_score * w_r + m_score * w_m)
        composite_score = max(0, min(100, composite_score))

        layers = [
            {'name': 'URL Structure', 'score': int(s_score), 'weight': w_s,
             'level': calculate_risk_level(s_score).lower(), 'status': 'complete', 'module': 'Module 1'},
            {'name': 'Lexical Intelligence', 'score': int(l_score), 'weight': w_l,
             'level': calculate_risk_level(l_score).lower(), 'status': 'complete', 'module': 'Module 1'},
            {'name': 'Security Rule Engine', 'score': int(r_score), 'weight': w_r,
             'level': calculate_risk_level(r_score).lower(), 'status': 'complete', 'module': 'Module 1'},
            {'name': 'ML Classifier', 'score': int(m_score), 'weight': w_m,
             'level': calculate_risk_level(m_score).lower(), 'status': 'complete', 'module': 'Module 1'},
            {'name': 'Domain Intelligence', 'score': None, 'weight': 0.0,
             'level': 'unavailable', 'status': 'not_implemented', 'module': 'Module 2'},
            {'name': 'Webpage Intelligence', 'score': None, 'weight': 0.0,
             'level': 'unavailable', 'status': 'not_implemented', 'module': 'Module 3'},
        ]

        explanation = (
            f"The composite risk score of {composite_score} was calculated as a weighted sum of "
            f"4 active analysis layers: URL Structure (20%), Lexical Intelligence (30%), "
            f"Security Rule Engine (25%), and ML Classifier (25%)."
        )
        active_count = 4

    # Critical deterministic rule floor: Critical rules (e.g. SSRF-001 localhost, HOMO-001)
    # must never be diluted by neutral or unavailable auxiliary layers.
    if r_score >= 75:
        composite_score = max(composite_score, int(r_score))

    return {
        'layers': layers,
        'composite': composite_score,
        'composite_level': calculate_risk_level(composite_score),
        'explanation': explanation,
        'active_layers': active_count,
        'active_layers_count': active_count,
        'total_layers': 6,
        'has_domain_layer': has_domain,
        'has_webpage_layer': has_webpage,
    }
