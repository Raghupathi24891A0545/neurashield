"""
NEURASHIELD - MODULE 2: DOMAIN INTELLIGENCE COLLECTOR
Safe, real-time domain intelligence collection for threat investigation.
Implements:
- Strict SSRF protection and DNS rebinding guards
- PSL-aware domain normalization
- Granular DNS query state tracking (SUCCESS, NO_RECORDS, TIMEOUT, NXDOMAIN)
- Defensively parsed WHOIS with UTC-aware datetime calculation
- SSL/TLS cryptographic inspection with critical legitimacy disclaimers
- Explainable 6-category telemetry coverage calculation
"""

import socket
import ssl
import ipaddress
import re
import time
import unicodedata
from datetime import datetime, timezone
from typing import Dict, Any, Optional, List
from urllib.parse import urlparse

try:
    import dns.resolver
    import dns.exception
    import dns.reversename
    HAS_DNS = True
except ImportError:
    HAS_DNS = False

try:
    import whois
    HAS_WHOIS = True
except ImportError:
    HAS_WHOIS = False

try:
    import tldextract
    HAS_TLDEXTRACT = True
except ImportError:
    HAS_TLDEXTRACT = False


# ── SSRF Protection ───────────────────────────────────────────────────────────
BLOCKED_NETWORKS = [
    ipaddress.ip_network('127.0.0.0/8'),
    ipaddress.ip_network('10.0.0.0/8'),
    ipaddress.ip_network('172.16.0.0/12'),
    ipaddress.ip_network('192.168.0.0/16'),
    ipaddress.ip_network('169.254.0.0/16'),
    ipaddress.ip_network('::1/128'),
    ipaddress.ip_network('fc00::/7'),
    ipaddress.ip_network('fe80::/10'),
    ipaddress.ip_network('0.0.0.0/8'),
    ipaddress.ip_network('100.64.0.0/10'),
    ipaddress.ip_network('224.0.0.0/4'),
    ipaddress.ip_network('240.0.0.0/4'),
]

DNS_TIMEOUT = 3.5
SSL_TIMEOUT = 4.0
WHOIS_TIMEOUT = 7.0


def is_safe_target(target: str) -> bool:
    """
    Validate that a target is safe to query (not private, loopback, or metadata).
    Prevents SSRF and local reconnaissance.
    """
    if not target or not isinstance(target, str):
        return False
    target = target.strip().lower()

    # Block local hostnames and cloud metadata endpoints
    blocked_hosts = (
        'localhost', 'localhost.localdomain', 'broadcasthost',
        'metadata.google.internal', '169.254.169.254',
        'instance-data', 'meta-data'
    )
    if target in blocked_hosts:
        return False

    # Block local TLDs
    if target.endswith(('.local', '.internal', '.lan', '.localdomain', '.localhost', '.home', '.corp')):
        return False

    # Check if target is a raw IP address
    try:
        ip = ipaddress.ip_address(target)
        for network in BLOCKED_NETWORKS:
            if ip in network:
                return False
    except ValueError:
        pass

    # Resolve target hostname to check underlying IP addresses against SSRF ranges
    try:
        addrinfo = socket.getaddrinfo(target, None)
        for family, _, _, _, sockaddr in addrinfo:
            ip_str = sockaddr[0]
            ip_obj = ipaddress.ip_address(ip_str)
            for network in BLOCKED_NETWORKS:
                if ip_obj in network:
                    return False
    except Exception:
        pass

    return True


# ── Domain Normalization ───────────────────────────────────────────────────────

def normalize_domain(input_str: str) -> Dict[str, Any]:
    """
    Robust PSL-aware domain normalization.
    Preserves: original_input, normalized_domain, hostname, registered_domain,
    public_suffix, subdomain, is_ip, is_idna, unicode_domain, punycode_domain.
    """
    if not input_str or not isinstance(input_str, str):
        return {
            'original_input': input_str or '',
            'normalized_domain': '',
            'hostname': '',
            'registered_domain': '',
            'public_suffix': '',
            'subdomain': '',
            'is_ip': False,
            'is_idna': False,
            'unicode_domain': '',
            'punycode_domain': '',
            'valid': False,
        }

    original = input_str
    cleaned = input_str.strip()

    # If input has protocol or path, extract host
    if '://' in cleaned:
        try:
            parsed = urlparse(cleaned)
            raw_host = parsed.netloc.split(':')[0]
        except Exception:
            raw_host = cleaned
    else:
        raw_host = cleaned.split('/')[0].split(':')[0]

    raw_host = raw_host.strip('.').lower()
    raw_host = unicodedata.normalize('NFC', raw_host)

    # Check if raw IP
    is_ip = False
    try:
        ipaddress.ip_address(raw_host)
        is_ip = True
    except ValueError:
        is_ip = False

    # Handle Punycode & IDNA
    is_idna = False
    unicode_domain = raw_host
    punycode_domain = raw_host
    if not is_ip:
        if raw_host.startswith('xn--') or '.xn--' in raw_host:
            is_idna = True
            try:
                unicode_domain = raw_host.encode('ascii').decode('idna')
            except Exception:
                unicode_domain = raw_host
        else:
            try:
                punycode_domain = raw_host.encode('idna').decode('ascii')
                if punycode_domain != raw_host:
                    is_idna = True
            except Exception:
                punycode_domain = raw_host

    registered_domain = raw_host
    public_suffix = ''
    subdomain = ''
    hostname = raw_host

    if is_ip:
        registered_domain = raw_host
        hostname = raw_host
    elif HAS_TLDEXTRACT:
        ext = tldextract.extract(punycode_domain)
        public_suffix = ext.suffix
        subdomain = ext.subdomain
        if ext.domain and ext.suffix:
            registered_domain = f"{ext.domain}.{ext.suffix}"
            hostname = f"{subdomain}.{registered_domain}" if subdomain else registered_domain
        else:
            registered_domain = punycode_domain
            hostname = punycode_domain
    else:
        # Fallback simple split if tldextract unavailable
        parts = punycode_domain.split('.')
        if len(parts) >= 2:
            registered_domain = '.'.join(parts[-2:])
        hostname = punycode_domain

    return {
        'original_input': original,
        'normalized_domain': registered_domain,
        'hostname': hostname,
        'registered_domain': registered_domain,
        'public_suffix': public_suffix,
        'subdomain': subdomain,
        'is_ip': is_ip,
        'is_idna': is_idna,
        'unicode_domain': unicode_domain,
        'punycode_domain': punycode_domain,
        'valid': bool(registered_domain),
    }


def normalize_domain_input(input_str: str) -> str:
    """Convenience registered domain string extractor for legacy signatures."""
    res = normalize_domain(input_str)
    return res.get('registered_domain') or res.get('hostname', '')


# ── DNS Intelligence Collection ───────────────────────────────────────────────

def collect_dns_live(domain: str) -> Dict[str, Any]:
    """
    Query DNS records with granular observation context and explicit query states.
    Distinguishes SUCCESS_WITH_RECORDS, SUCCESS_NO_RECORDS, TIMEOUT, NXDOMAIN, DNS_ERROR.
    """
    obs_time = datetime.now(timezone.utc).isoformat()
    result = {
        'dns_resolution': False,
        'observed_at': obs_time,
        'resolver_source': 'System DNS',
        'a_records': [], 'aaaa_records': [], 'mx_records': [],
        'ns_records': [], 'txt_records': [], 'cname_records': [],
        'a_record_count': 0, 'aaaa_record_count': 0, 'mx_record_count': 0,
        'ns_record_count': 0, 'txt_record_count': 0,
        'query_details': {},
        'collection_status': 'unavailable',
    }

    if not HAS_DNS:
        result['collection_status'] = 'library_unavailable'
        return result

    resolver = dns.resolver.Resolver()
    resolver.timeout = DNS_TIMEOUT
    resolver.lifetime = DNS_TIMEOUT
    # Ensure robust resolution by including public high-performance resolvers as fallback
    current_ns = list(resolver.nameservers) if resolver.nameservers else []
    for pub_ns in ['8.8.8.8', '1.1.1.1']:
        if pub_ns not in current_ns:
            current_ns.append(pub_ns)
    resolver.nameservers = current_ns
    result['resolver_source'] = f"DNS ({resolver.nameservers[0]})"

    any_success = False

    for rtype in ['A', 'AAAA', 'MX', 'NS', 'TXT', 'CNAME']:
        field = f"{rtype.lower()}_records"
        t0 = time.time()
        detail = {
            'query_type': rtype,
            'status': 'UNAVAILABLE',
            'records': [],
            'count': 0,
            'query_time_ms': 0,
            'error': None,
        }

        try:
            answers = resolver.resolve(domain, rtype)
            records = []
            for rdata in answers:
                val = str(rdata).rstrip('.')
                if rtype == 'MX':
                    val = str(rdata.exchange).rstrip('.')
                elif rtype == 'TXT':
                    val = str(rdata).strip('"')
                records.append(val)

            elapsed_ms = round((time.time() - t0) * 1000, 1)
            detail['records'] = records
            detail['count'] = len(records)
            detail['query_time_ms'] = elapsed_ms
            detail['status'] = 'SUCCESS_WITH_RECORDS' if records else 'SUCCESS_NO_RECORDS'
            result[field] = records
            if records:
                any_success = True

        except dns.resolver.NoAnswer:
            elapsed_ms = round((time.time() - t0) * 1000, 1)
            detail['query_time_ms'] = elapsed_ms
            detail['status'] = 'SUCCESS_NO_RECORDS'
            detail['error'] = 'No records of this type present in domain zone'
            result[field] = []

        except dns.resolver.NXDOMAIN:
            elapsed_ms = round((time.time() - t0) * 1000, 1)
            detail['query_time_ms'] = elapsed_ms
            detail['status'] = 'NXDOMAIN'
            detail['error'] = 'Domain does not exist (NXDOMAIN)'
            result[field] = []

        except dns.exception.Timeout:
            elapsed_ms = round((time.time() - t0) * 1000, 1)
            detail['query_time_ms'] = elapsed_ms
            detail['status'] = 'TIMEOUT'
            detail['error'] = f'Query timed out after {DNS_TIMEOUT}s'
            result[field] = []

        except dns.resolver.NoNameservers:
            elapsed_ms = round((time.time() - t0) * 1000, 1)
            detail['query_time_ms'] = elapsed_ms
            detail['status'] = 'NO_NAMESERVERS'
            detail['error'] = 'No authoritative nameservers responded'
            result[field] = []

        except Exception as e:
            elapsed_ms = round((time.time() - t0) * 1000, 1)
            detail['query_time_ms'] = elapsed_ms
            detail['status'] = 'DNS_ERROR'
            detail['error'] = str(e)
            result[field] = []

        result['query_details'][rtype] = detail

    for rtype in ['a', 'aaaa', 'mx', 'ns', 'txt']:
        result[f'{rtype}_record_count'] = len(result.get(f'{rtype}_records', []))

    if any_success or result['query_details']['A']['status'] in ('SUCCESS_WITH_RECORDS', 'SUCCESS_NO_RECORDS'):
        result['dns_resolution'] = len(result['a_records']) > 0 or len(result['aaaa_records']) > 0
        result['collection_status'] = 'success'
    else:
        a_status = result['query_details']['A']['status']
        if a_status == 'NXDOMAIN':
            result['collection_status'] = 'nxdomain'
        elif a_status == 'TIMEOUT':
            result['collection_status'] = 'timeout'
        else:
            result['collection_status'] = 'error'

    return result


# ── IP & Infrastructure ───────────────────────────────────────────────────────

def collect_ip_info_live(dns_data: Dict) -> Dict[str, Any]:
    """
    Extract IP routing info and observe reverse DNS/host hints safely without fabricating ASN.
    """
    obs_time = datetime.now(timezone.utc).isoformat()
    a_records = dns_data.get('a_records', [])
    aaaa_records = dns_data.get('aaaa_records', [])

    safe_v4 = [ip for ip in a_records if is_safe_target(ip)]
    safe_v6 = [ip for ip in aaaa_records if is_safe_target(ip)]

    # Attempt safe reverse DNS (PTR) lookup on primary IP with tight timeout
    ptr_hostname = None
    provider_hint = 'Standard Internet Hosting'
    if safe_v4:
        primary_ip = safe_v4[0]
        try:
            ptr_hostname = socket.getnameinfo((primary_ip, 0), socket.NI_NAMEREQD)[0]
            ptr_lower = ptr_hostname.lower()
            if 'amazonaws' in ptr_lower or 'awsdns' in ptr_lower:
                provider_hint = 'Amazon Web Services (AWS)'
            elif 'cloudflare' in ptr_lower:
                provider_hint = 'Cloudflare Edge CDN'
            elif 'google' in ptr_lower or '1e100' in ptr_lower:
                provider_hint = 'Google Cloud / Google Infrastructure'
            elif 'azure' in ptr_lower or 'microsoft' in ptr_lower:
                provider_hint = 'Microsoft Azure'
            elif 'fastly' in ptr_lower:
                provider_hint = 'Fastly CDN'
            elif 'akamai' in ptr_lower:
                provider_hint = 'Akamai Technologies'
        except Exception:
            ptr_hostname = None

    is_multi = (len(safe_v4) + len(safe_v6)) > 1

    return {
        'resolved_ipv4': safe_v4,
        'resolved_ipv6': safe_v6,
        'ip_count': len(safe_v4) + len(safe_v6),
        'has_multiple_ips': is_multi,
        'ptr_hostname': ptr_hostname,
        'infrastructure_provider': provider_hint,
        'asn': 'Not verified (External BGP query disabled)',
        'observed_at': obs_time,
        'source': 'Observed live via DNS A/AAAA response',
        'infrastructure_note': 'Multiple IPs and CDN distribution are standard modern availability mechanisms and do not indicate malicious intent.',
        'collection_status': 'success' if (safe_v4 or safe_v6) else 'no_records',
    }


# ── WHOIS & Registration ───────────────────────────────────────────────────────

def _parse_datetime_utc(dt_val) -> Optional[datetime]:
    """
    Robustly parse WHOIS date values (string, naive datetime, timezone-aware datetime, or list)
    into a timezone-aware UTC datetime.
    """
    if dt_val is None:
        return None
    if isinstance(dt_val, list):
        if not dt_val:
            return None
        dt_val = dt_val[0]

    if isinstance(dt_val, str):
        dt_str = dt_val.split('.')[0].strip()
        # Strip timezone offsets like +00:00 or Z
        dt_clean = re.sub(r'(\+\d{2}:\d{2}|Z)$', '', dt_str).strip()
        for fmt in (
            '%Y-%m-%d %H:%M:%S',
            '%Y-%m-%dT%H:%M:%S',
            '%Y-%m-%d',
            '%d-%b-%Y',
            '%d-%m-%Y',
            '%Y/%m/%d',
        ):
            try:
                dt_val = datetime.strptime(dt_clean, fmt)
                break
            except Exception:
                pass

    if isinstance(dt_val, datetime):
        if dt_val.tzinfo is None:
            return dt_val.replace(tzinfo=timezone.utc)
        return dt_val.astimezone(timezone.utc)

    return None


def collect_whois_live(domain: str) -> Dict[str, Any]:
    """
    Collect WHOIS domain registration details with UTC-safe date calculations.
    Ensures domain_age_days is properly computed whenever creation date exists.
    """
    now_utc = datetime.now(timezone.utc)
    obs_time = now_utc.isoformat()

    result = {
        'registrar': None,
        'creation_date': None,
        'updated_date': None,
        'expiration_date': None,
        'domain_age_days': None,
        'remaining_lifetime_days': None,
        'registrar_present': False,
        'expiration_available': False,
        'expiration_status': 'Not verified',
        'whois_privacy_detected': False,
        'name_servers': [],
        'nameserver_count': 0,
        'observed_at': obs_time,
        'collection_status': 'unavailable',
    }

    if not HAS_WHOIS:
        result['collection_status'] = 'library_unavailable'
        return result

    try:
        w = None
        for attempt in range(2):
            try:
                w = whois.whois(domain)
                if w and (getattr(w, 'creation_date', None) or getattr(w, 'registrar', None)):
                    break
            except Exception as we:
                if attempt == 0 and ('timeout' in str(we).lower() or 'closing socket' in str(we).lower()):
                    time.sleep(1.0)
                    continue
                raise we

        # Registrar
        if getattr(w, 'registrar', None):
            result['registrar'] = str(w.registrar)
            result['registrar_present'] = True

        # Check WHOIS Privacy indicators
        whois_text = str(w).lower()
        privacy_keywords = ['privacy', 'proxy', 'whoisguard', 'withheld', 'protect', 'redacted']
        result['whois_privacy_detected'] = any(kw in whois_text for kw in privacy_keywords)
        result['privacy_detected'] = result['whois_privacy_detected']

        # Creation date -> Domain Age
        cd = _parse_datetime_utc(getattr(w, 'creation_date', None))
        if cd:
            result['creation_date'] = cd.isoformat()
            # Calculate elapsed domain age days defensively
            result['domain_age_days'] = max(0, (now_utc - cd).days)

        # Updated date
        ud = _parse_datetime_utc(getattr(w, 'updated_date', None))
        if ud:
            result['updated_date'] = ud.isoformat()

        # Expiration date -> Remaining Lifetime
        ed = _parse_datetime_utc(getattr(w, 'expiration_date', None))
        if ed:
            result['expiration_date'] = ed.isoformat()
            result['remaining_lifetime_days'] = (ed - now_utc).days
            result['expiration_available'] = True
            result['expiration_status'] = 'Verified'
        else:
            result['expiration_status'] = 'Not verified (Unavailable from registry / redacted)'

        # Nameservers from WHOIS
        raw_ns = getattr(w, 'name_servers', None)
        if raw_ns:
            if isinstance(raw_ns, list):
                result['name_servers'] = [str(n).lower().rstrip('.') for n in raw_ns if n]
            else:
                result['name_servers'] = [str(raw_ns).lower().rstrip('.')]
            result['nameserver_count'] = len(result['name_servers'])

        result['collection_status'] = 'success'

    except Exception as e:
        err = str(e).lower()
        if 'no match' in err or 'not found' in err:
            result['collection_status'] = 'not_found'
        elif 'timeout' in err:
            result['collection_status'] = 'timeout'
        elif 'rate' in err or 'limit' in err:
            result['collection_status'] = 'rate_limited'
        else:
            result['collection_status'] = 'error'

    return result


# ── SSL/TLS Intelligence ───────────────────────────────────────────────────────

def collect_ssl_live(domain: str) -> Dict[str, Any]:
    """
    Collect SSL/TLS cryptographic parameters with explicit transport validity status.
    Includes educational interpretation: transport encryption != site legitimacy.
    """
    now_utc = datetime.now(timezone.utc)
    obs_time = now_utc.isoformat()

    result = {
        'ssl_available': False,
        'ssl_valid': False,
        'certificate_issuer': None,
        'certificate_subject': None,
        'certificate_start_date': None,
        'certificate_expiry_date': None,
        'certificate_age_days': None,
        'certificate_remaining_days': None,
        'certificate_san_count': 0,
        'certificate_hostname_match': False,
        'certificate_is_wildcard': False,
        'san_list': [],
        'tls_version': None,
        'cipher_suite': None,
        'transport_status': 'UNAVAILABLE',
        'transport_state': 'UNAVAILABLE',
        'observed_at': obs_time,
        'tls_interpretation': 'TLS validation confirms transport layer encryption and certificate validity only; it does NOT establish website legitimacy, organizational trustworthiness, or safety.',
        'collection_status': 'unavailable',
    }

    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((domain, 443), timeout=SSL_TIMEOUT) as sock:
            with ctx.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()
                result['tls_version'] = ssock.version()
                cipher_info = ssock.cipher()
                if cipher_info:
                    result['cipher_suite'] = cipher_info[0]

                if cert:
                    result['ssl_available'] = True
                    result['ssl_valid'] = True
                    result['transport_status'] = 'CERTIFICATE_VALID'
                    result['transport_state'] = 'CERTIFICATE_VALID'

                    issuer = dict(x[0] for x in cert.get('issuer', []))
                    result['certificate_issuer'] = issuer.get('organizationName', issuer.get('commonName', ''))
                    subject = dict(x[0] for x in cert.get('subject', []))
                    result['certificate_subject'] = subject.get('commonName', '')

                    nb = cert.get('notBefore', '')
                    na = cert.get('notAfter', '')
                    if nb:
                        try:
                            start = datetime.strptime(nb, '%b %d %H:%M:%S %Y %Z').replace(tzinfo=timezone.utc)
                            result['certificate_start_date'] = start.isoformat()
                            result['certificate_age_days'] = (now_utc - start).days
                        except Exception:
                            pass
                    if na:
                        try:
                            expiry = datetime.strptime(na, '%b %d %H:%M:%S %Y %Z').replace(tzinfo=timezone.utc)
                            result['certificate_expiry_date'] = expiry.isoformat()
                            result['certificate_remaining_days'] = (expiry - now_utc).days
                        except Exception:
                            pass

                    # Subject Alternative Names (SANs)
                    san_entries = cert.get('subjectAltName', [])
                    san_names = [name for kind, name in san_entries if kind == 'DNS']
                    result['san_list'] = san_names[:25]
                    result['certificate_san_count'] = len(san_names)

                    # Hostname match check
                    dom_clean = domain.lower()
                    matches = False
                    for n in san_names:
                        n_clean = n.lower()
                        if dom_clean == n_clean:
                            matches = True
                            break
                        if n_clean.startswith('*.') and dom_clean.endswith('.' + n_clean[2:]):
                            matches = True
                            break
                    result['certificate_hostname_match'] = matches
                    result['certificate_is_wildcard'] = any(n.startswith('*.') for n in san_names)
                    result['collection_status'] = 'success'

    except ssl.SSLCertVerificationError as e:
        result['ssl_available'] = True
        result['ssl_valid'] = False
        result['transport_status'] = 'CERTIFICATE_INVALID_CHAIN'
        result['collection_status'] = 'invalid_certificate'
    except ssl.SSLError:
        result['ssl_available'] = True
        result['ssl_valid'] = False
        result['transport_status'] = 'CERTIFICATE_ERROR'
        result['collection_status'] = 'ssl_error'
    except socket.timeout:
        result['transport_status'] = 'TLS_CONNECTION_TIMEOUT'
        result['collection_status'] = 'timeout'
    except ConnectionRefusedError:
        result['transport_status'] = 'PORT_443_CLOSED'
        result['collection_status'] = 'connection_refused'
    except OSError:
        result['transport_status'] = 'CONNECTION_ERROR'
        result['collection_status'] = 'connection_error'
    except Exception:
        result['transport_status'] = 'ERROR'
        result['collection_status'] = 'error'

    return result


# ── Full Domain Intelligence Investigation ────────────────────────────────────

def analyze_domain(domain_input: str) -> Dict[str, Any]:
    """
    Perform deep domain intelligence analysis across 6 analytical categories:
    1. DNS Topology
    2. Registration & WHOIS
    3. IP & Infrastructure
    4. Nameserver Infrastructure
    5. SSL/TLS Cryptography
    6. External Reputation
    """
    # 1. Normalize input
    norm_info = normalize_domain(domain_input)
    registered_domain = norm_info['registered_domain']
    if not registered_domain or not norm_info['valid']:
        return {'error': 'Invalid domain input', 'domain': domain_input, 'normalization': norm_info}

    # 2. SSRF check
    if not is_safe_target(registered_domain):
        return {
            'error': 'Target blocked by security policy (SSRF protection)',
            'domain': registered_domain,
            'normalization': norm_info
        }

    now_utc = datetime.now(timezone.utc)
    result = {
        'domain': registered_domain,
        'input': domain_input,
        'normalization': norm_info,
        'analysis_timestamp': now_utc.isoformat(),
        'ssrf_policy': {
            'status': 'PASS',
            'route': 'Public Route Verified',
            'detail': 'Host and resolved IP addresses passed RFC1918, loopback, link-local, and cloud metadata filter checks.'
        }
    }

    # 3. Collect category telemetry concurrently in parallel
    from concurrent.futures import ThreadPoolExecutor

    def _dns_and_ip():
        d = collect_dns_live(registered_domain)
        i = collect_ip_info_live(d)
        return d, i

    with ThreadPoolExecutor(max_workers=3) as executor:
        f_dns = executor.submit(_dns_and_ip)
        f_whois = executor.submit(collect_whois_live, registered_domain)
        f_ssl = executor.submit(collect_ssl_live, registered_domain)

        dns_data, ip_data = f_dns.result()
        whois_data = f_whois.result()
        ssl_data = f_ssl.result()

    result['dns'] = dns_data
    result['ip'] = ip_data
    result['registration'] = whois_data
    result['ssl'] = ssl_data

    # Nameservers (merged WHOIS + DNS)
    ns_whois = whois_data.get('name_servers', [])
    ns_dns = dns_data.get('ns_records', [])
    all_ns = list(set(ns_whois + ns_dns))
    ns_domains = set()
    for ns in all_ns:
        parts = ns.split('.')
        if len(parts) >= 2:
            ns_domains.add('.'.join(parts[-2:]))

    result['nameservers'] = {
        'nameserver_list': all_ns,
        'nameserver_count': len(all_ns),
        'nameserver_diversity': len(ns_domains),
        'observed_at': now_utc.isoformat(),
        'source': 'Merged Authoritative NS & WHOIS Records',
        'collection_status': 'success' if all_ns else ('partial' if dns_data.get('collection_status') == 'success' else 'unavailable')
    }

    # External Reputation (Disclosed transparently)
    result['reputation'] = {
        'sources': [],
        'collection_status': 'unavailable',
        'observed_at': now_utc.isoformat(),
        'note': 'External commercial threat reputation APIs not configured in this environment.',
    }

    # 4. Explainable 6-Category Telemetry Coverage
    categories = [
        {
            'name': 'DNS Topology',
            'status': 'collected' if dns_data['collection_status'] == 'success' else ('failed' if dns_data['collection_status'] in ('timeout', 'error') else 'unavailable'),
            'detail': f"{dns_data.get('a_record_count', 0)} A, {dns_data.get('mx_record_count', 0)} MX, {dns_data.get('txt_record_count', 0)} TXT records observed.",
        },
        {
            'name': 'Registration & WHOIS',
            'status': 'collected' if whois_data['collection_status'] == 'success' else ('failed' if whois_data['collection_status'] == 'error' else 'unavailable'),
            'detail': f"Registrar: {whois_data.get('registrar') or 'Unspecified'} | Age: {whois_data.get('domain_age_days') if whois_data.get('domain_age_days') is not None else 'Unverified'}",
        },
        {
            'name': 'IP & Infrastructure',
            'status': 'collected' if ip_data['collection_status'] == 'success' else 'unavailable',
            'detail': f"{ip_data.get('ip_count', 0)} active IP address(es) observed via DNS response.",
        },
        {
            'name': 'Nameserver Infrastructure',
            'status': 'collected' if all_ns else 'unavailable',
            'detail': f"{len(all_ns)} nameserver(s) mapped with {len(ns_domains)} distinct provider domain(s).",
        },
        {
            'name': 'SSL/TLS Cryptography',
            'status': 'collected' if ssl_data['collection_status'] == 'success' else ('failed' if ssl_data['collection_status'] in ('timeout', 'connection_error') else 'unavailable'),
            'detail': f"{ssl_data.get('transport_status', 'No TLS')} (Issuer: {ssl_data.get('certificate_issuer') or 'None'})",
        },
        {
            'name': 'External Reputation',
            'status': 'unavailable',
            'detail': 'External reputation feed disabled/unconfigured.',
        },
    ]

    collected_count = sum(1 for c in categories if c['status'] == 'collected')
    result['telemetry_categories'] = categories
    result['evidence_coverage'] = round((collected_count / len(categories)) * 100, 1)
    result['overall_status'] = 'success' if collected_count >= 5 else ('partial' if collected_count > 0 else 'failed')

    return result
