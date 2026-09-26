import re
import math
import pandas as pd
from urllib.parse import urlparse, parse_qs, unquote

URL_FEATURE_SCHEMA_VERSION = "url-v2"
MODULE_VERSION = "1.0.0"

# ── Brand list for impersonation detection ──
BRAND_LIST = [
    'paypal', 'google', 'microsoft', 'apple', 'amazon', 'facebook', 'instagram',
    'twitter', 'netflix', 'bank', 'chase', 'wellsfargo', 'citibank', 'hsbc',
    'ebay', 'yahoo', 'linkedin', 'dropbox', 'adobe', 'steam', 'discord',
    'outlook', 'office', 'onedrive', 'whatsapp', 'tiktok', 'coinbase',
    'binance', 'blockchain', 'crypto', 'wallet', 'visa', 'mastercard'
]

# ── Suspicious keywords ──
SUSPICIOUS_WORDS = [
    'login', 'signin', 'verify', 'account', 'secure', 'update', 'confirm',
    'password', 'banking', 'credential', 'wallet', 'authentication',
    'validate', 'recover', 'unlock', 'alert', 'urgent', 'suspended',
    'limited', 'access', 'identity', 'support', 'helpdesk', 'webscr',
    'cmd=_s-xclick', 'token', 'submit', 'redirect'
]

# ── High-risk TLDs commonly used by phishers ──
SUSPICIOUS_TLDS = {
    '.xyz', '.tk', '.ml', '.ga', '.cf', '.gq', '.top', '.club',
    '.online', '.site', '.info', '.biz', '.cc', '.pw', '.ws',
    '.ru', '.cn', '.icu', '.buzz', '.fun', '.vip'
}

# ── Known URL shorteners ──
URL_SHORTENERS = {
    'bit.ly', 'tinyurl.com', 't.co', 'goo.gl', 'ow.ly', 'is.gd',
    'buff.ly', 'adf.ly', 'tiny.cc', 'shorte.st', 'cutt.ly', 'rb.gy'
}

# ── Common open-redirect parameters ──
REDIRECT_PARAMS = {
    'redirect', 'url', 'next', 'target', 'dest', 'destination',
    'continue', 'return', 'returnurl', 'r', 'goto', 'link', 'out', 'view'
}

# ── Original model-trained feature keys (MUST remain identical for sklearn compat) ──
MODEL_FEATURE_KEYS = [
    'url_length', 'dot_count', 'hyphen_count', 'at_count', 'question_count',
    'equal_count', 'digit_count', 'https', 'has_ip', 'suspicious_word',
    'homograph', 'digit_in_domain'
]


# ── HSTS preloaded and authoritative HTTPS-enforcing domains ──
HSTS_PRELOADED_DOMAINS = {
    'google.com', 'gmail.com', 'google.co.in', 'google.co.uk',
    'microsoft.com', 'live.com', 'office.com', 'outlook.com',
    'apple.com', 'icloud.com', 'amazon.com', 'github.com',
    'linkedin.com', 'twitter.com', 'x.com', 'facebook.com',
    'instagram.com', 'paypal.com', 'tkrcet.ac.in', 'tkrec.ac.in'
}

MULTI_PART_TLDS = {
    '.co.uk', '.co.in', '.ac.in', '.gov.in', '.edu.in',
    '.com.au', '.net.au', '.org.uk', '.co.nz', '.co.za', '.com.br'
}


def _shannon_entropy(s):
    """Shannon entropy — higher = more random/suspicious."""
    if not s:
        return 0.0
    freq = {}
    for c in s:
        freq[c] = freq.get(c, 0) + 1
    n = len(s)
    return round(-sum((v / n) * math.log2(v / n) for v in freq.values()), 4)


def normalize_url(url: str) -> str:
    """
    Safely and deterministically normalize URL for analysis without losing signals.
    Does not destroy original URL.
    """
    if not isinstance(url, str):
        return ""
    url = url.strip()
    if not url:
        return ""

    # Unwrap Google redirect proxy if present (e.g. https://www.google.com/url?q=...)
    if 'google.com/url?' in url.lower() or ('google.co' in url.lower() and '/url?' in url.lower()):
        try:
            parsed_redir = urlparse(url)
            query_params = parse_qs(parsed_redir.query)
            target_q = query_params.get('q') or query_params.get('url')
            if target_q and target_q[0]:
                url = unquote(target_q[0]).strip()
        except Exception:
            pass

    # Ensure scheme: modern web standard default is https://
    if '://' not in url:
        url = 'https://' + url
    elif url.startswith('http://'):
        try:
            check_host = urlparse(url).netloc.lower().split(':')[0].replace('www.', '')
            if check_host in HSTS_PRELOADED_DOMAINS or any(check_host.endswith('.' + d) for d in HSTS_PRELOADED_DOMAINS):
                url = 'https://' + url[7:]
        except Exception:
            pass

    try:
        parsed = urlparse(url)
        norm_scheme = parsed.scheme.lower()
        norm_netloc = parsed.netloc.lower()
        norm_url = f"{norm_scheme}://{norm_netloc}{parsed.path}"
        if parsed.query:
            norm_url += f"?{parsed.query}"
        if parsed.fragment:
            norm_url += f"#{parsed.fragment}"
        return norm_url
    except Exception:
        return url


def extract_features(url):
    """
    Extract URL features.
    Returns a dict with:
      - All original MODEL_FEATURE_KEYS (used by sklearn model — DO NOT rename/remove)
      - Rich extended keys (used for MODULE 1 intelligence display and security rule engine)
    """
    if not isinstance(url, str):
        url = "" if pd.isna(url) else str(url)

    url = url.strip()
    features = {}

    # Unwrap Google redirect if present
    if 'google.com/url?' in url.lower() or ('google.co' in url.lower() and '/url?' in url.lower()):
        try:
            parsed_redir = urlparse(url)
            query_params = parse_qs(parsed_redir.query)
            target_q = query_params.get('q') or query_params.get('url')
            if target_q and target_q[0]:
                url = unquote(target_q[0]).strip()
        except Exception:
            pass

    # Ensure scheme - default to https:// for modern URLs without scheme
    had_scheme = '://' in url
    if not had_scheme:
        url_canonical = 'https://' + url
    else:
        url_canonical = url

    # ─── Parse URL ───────────────────────────────────────────────────────────
    try:
        parsed = urlparse(url_canonical)
    except Exception:
        parsed = urlparse('')

    host       = parsed.netloc.lower()
    hostname   = host.split(':')[0]          # strip port
    path       = parsed.path or ''
    query      = parsed.query or ''
    fragment   = parsed.fragment or ''
    clean_host = hostname.replace('www.', '')
    parts      = clean_host.split('.')

    # Accurate TLD and domain_name extraction handling multi-part ccTLDs (.co.uk, .co.in, .ac.in)
    if len(parts) >= 3 and ('.' + parts[-2] + '.' + parts[-1]) in MULTI_PART_TLDS:
        tld         = '.' + parts[-2] + '.' + parts[-1]
        domain_name = parts[-3]
        subdomains  = parts[:-3]
    else:
        tld         = ('.' + parts[-1]) if len(parts) >= 1 else ''
        domain_name = parts[-2] if len(parts) >= 2 else clean_host
        subdomains  = parts[:-2] if len(parts) > 2 else []

    is_hsts_domain = clean_host in HSTS_PRELOADED_DOMAINS or any(clean_host.endswith('.' + d) for d in HSTS_PRELOADED_DOMAINS)

    if not had_scheme or is_hsts_domain:
        protocol_effective = 'https'
    else:
        protocol_effective = parsed.scheme.lower() if parsed.scheme else 'http'

    url_lower = url_canonical.lower()

    # ═══════════════════════════════════════════════
    #  ORIGINAL MODEL FEATURES (backward compat)
    # ═══════════════════════════════════════════════

    # Length of URL
    features['url_length'] = len(url_canonical)

    # Count of dots
    features['dot_count'] = url_canonical.count('.')

    # Count of hyphen
    features['hyphen_count'] = url_canonical.count('-')

    # Count of @
    features['at_count'] = url_canonical.count('@')

    # Count of question mark
    features['question_count'] = url_canonical.count('?')

    # Count of equal sign
    features['equal_count'] = url_canonical.count('=')

    # Count of digits
    features['digit_count'] = sum(c.isdigit() for c in url_canonical)

    # HTTPS presence: 1 if effective protocol is HTTPS or domain enforces HTTPS
    features['https'] = 1 if protocol_effective == 'https' else 0

    # IP address presence
    features['has_ip'] = 1 if re.search(r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b', hostname) else 0

    # Localhost / Loopback address presence (SSRF vector)
    _host_clean = hostname.lower().strip().split(':')[0]
    features['is_localhost'] = 1 if (
        _host_clean in ('localhost', 'localhost.localdomain', '127.0.0.1', '::1', '0.0.0.0') or
        _host_clean.endswith('.localhost') or
        bool(re.match(r'^127\.\d{1,3}\.\d{1,3}\.\d{1,3}$', _host_clean))
    ) else 0

    # Suspicious words (binary — model was trained on 0/1)
    _sw_hits = [w for w in SUSPICIOUS_WORDS if w in url_lower]
    features['suspicious_word'] = 1 if _sw_hits else 0

    # Homograph / digit-substitution checks in hostname
    _homograph_pats = [r'c0m$', r'goog1e', r'faceb00k', r'on1ine', r'paypa1',
                       r'micros0ft', r'app1e', r'amaz0n']
    features['homograph'] = 1 if any(re.search(p, hostname) for p in _homograph_pats) else 0

    # Digit in domain portion
    features['digit_in_domain'] = 1 if re.search(r'[0-9]', hostname.split(':')[0]) else 0

    # ═══════════════════════════════════════════════
    #  EXTENDED INTELLIGENCE FEATURES (MODULE 1)
    # ═══════════════════════════════════════════════

    # --- Structural Components ---
    features['protocol']        = protocol_effective
    features['domain']          = hostname
    features['subdomain']       = '.'.join(subdomains) if subdomains else ''
    features['tld']             = tld
    features['domain_name']     = domain_name
    features['domain_length']   = len(hostname)
    features['path']            = path
    features['path_length']     = len(path)
    features['query']           = query
    features['query_length']    = len(query)
    features['fragment']        = fragment
    features['url_depth']       = len([p for p in path.split('/') if p])
    features['subdomain_count'] = len(subdomains)
    features['has_port']        = 1 if re.search(r':\d{2,5}$', host) else 0

    # Extract port number if non-standard
    port_match = re.search(r':(\d{2,5})$', host)
    features['port_number']     = int(port_match.group(1)) if port_match else (443 if parsed.scheme == 'https' else 80)

    # --- Lexical / Character ---
    features['ampersand_count']      = url.count('&')
    features['slash_count']          = url.count('/')
    special_chars = sum(1 for c in url if not c.isalnum() and c not in ':/.-_')
    features['special_char_density'] = round(special_chars / max(len(url), 1), 4)
    features['digit_ratio']          = round(features['digit_count'] / max(len(url), 1), 4)

    # --- Entropy ---
    features['url_entropy']    = _shannon_entropy(url_canonical)
    features['domain_entropy'] = _shannon_entropy(domain_name)
    features['path_entropy']   = _shannon_entropy(path)
    features['query_entropy']  = _shannon_entropy(query)

    # --- Brand impersonation ---
    _found_brands = [b for b in BRAND_LIST if b in clean_host]
    features['brand_in_domain']   = len(_found_brands)
    features['brand_list']        = _found_brands[:4]
    if _found_brands:
        _legit = any(b == domain_name for b in _found_brands)
        features['brand_impersonation'] = 0 if _legit else 1
    else:
        features['brand_impersonation'] = 0

    # --- Suspicious keyword detail ---
    features['suspicious_word_count'] = len(_sw_hits)
    features['suspicious_word_list']  = _sw_hits[:6]

    # --- Encoding & Obfuscation Detection ---
    features['percent_count']     = url.count('%')
    features['double_encoding']   = 1 if re.search(r'%25[0-9a-fA-F]{2}', url) else 0
    features['encoded_separators'] = 1 if any(x in url.upper() for x in ['%2F', '%3A', '%40', '%23', '%3F']) else 0
    features['nested_url']        = 1 if re.search(r'https?%3A%2F%2F|https?://.+https?://', url, re.IGNORECASE) else 0

    # --- Unicode / Punycode / Homoglyph Analysis ---
    features['punycode']         = 1 if 'xn--' in hostname else 0
    non_ascii = [c for c in url if ord(c) > 127]
    features['non_ascii_count']  = len(non_ascii)

    # Cyrillic / visually confusable substitution detection
    confusable_pats = [r'[\u0400-\u04FF]', r'[\u0370-\u03FF]']
    has_confusable = any(re.search(cp, hostname) for cp in confusable_pats)
    if has_confusable:
        features['homograph'] = 1  # upgrade homograph signal

    # --- TLD risk ---
    features['suspicious_tld'] = 1 if tld in SUSPICIOUS_TLDS else 0

    # --- URL shortener ---
    features['is_url_shortener'] = 1 if any(s in hostname for s in URL_SHORTENERS) else 0

    # --- Query Parameter Analysis ---
    parsed_query = parse_qs(query)
    features['param_count']  = len(parsed_query)
    features['query_params'] = list(parsed_query.keys())[:10]

    # Detect redirect parameters
    has_redir_param = any(k.lower() in REDIRECT_PARAMS for k in parsed_query.keys())
    has_redir_val   = any(any(val.startswith(('http://', 'https://', 'www.')) for val in vals)
                          for vals in parsed_query.values())
    features['has_redirect'] = 1 if (has_redir_param or has_redir_val) else 0

    # --- Hyphen density in domain name ---
    features['hyphen_in_domain'] = domain_name.count('-')

    return features
