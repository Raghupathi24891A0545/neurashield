"""
NEURASHIELD — MODULE 3: SAFE WEBPAGE FETCHER
Fetches webpages with comprehensive SSRF protection, redirect tracking,
timeout enforcement, and response size limits.
"""

import socket
import ipaddress
import time
import re
from urllib.parse import urlparse, urljoin
from typing import Dict, Any, List, Optional, Tuple
import requests
from requests.exceptions import (
    ConnectionError, Timeout, TooManyRedirects,
    SSLError, RequestException
)

# ── Configuration ────────────────────────────────────────────────────────────

CONNECT_TIMEOUT = 5        # seconds
READ_TIMEOUT = 10          # seconds
MAX_RESPONSE_SIZE = 5 * 1024 * 1024   # 5 MB
MAX_HTML_SIZE = 2 * 1024 * 1024       # 2 MB
MAX_REDIRECTS = 10
USER_AGENT = "NeuraShield/3.0 Webpage Intelligence Scanner (Security Research)"

# Fetch status constants
FETCH_SUCCESS = "FETCH_SUCCESS"
DNS_FAILURE = "DNS_FAILURE"
CONNECTION_TIMEOUT = "CONNECTION_TIMEOUT"
CONNECTION_REFUSED = "CONNECTION_REFUSED"
TLS_FAILURE = "TLS_FAILURE"
HTTP_ERROR = "HTTP_ERROR"
HTTP_403 = "HTTP_403"
HTTP_404 = "HTTP_404"
HTTP_429 = "HTTP_429"
HTTP_5XX = "HTTP_5XX"
REDIRECT_LIMIT = "REDIRECT_LIMIT"
CONTENT_TOO_LARGE = "CONTENT_TOO_LARGE"
UNSUPPORTED_CONTENT = "UNSUPPORTED_CONTENT"
SSRF_BLOCKED = "SSRF_BLOCKED"
BLOCKED_BY_HUMAN_VERIFICATION = "BLOCKED_BY_HUMAN_VERIFICATION"
NETWORK_ERROR = "NETWORK_ERROR"
INVALID_URL = "INVALID_URL"

# ── SSRF Protection ─────────────────────────────────────────────────────────

# Blocked private/reserved IP ranges
BLOCKED_NETWORKS = [
    # IPv4 Private
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    # Loopback
    ipaddress.ip_network("127.0.0.0/8"),
    # Link-local
    ipaddress.ip_network("169.254.0.0/16"),
    # Current network
    ipaddress.ip_network("0.0.0.0/8"),
    # Shared address space
    ipaddress.ip_network("100.64.0.0/10"),
    # IETF protocol assignments
    ipaddress.ip_network("192.0.0.0/24"),
    # Documentation
    ipaddress.ip_network("192.0.2.0/24"),
    ipaddress.ip_network("198.51.100.0/24"),
    ipaddress.ip_network("203.0.113.0/24"),
    # Benchmarking
    ipaddress.ip_network("198.18.0.0/15"),
    # IPv6 Private/Reserved
    ipaddress.ip_network("::1/128"),        # loopback
    ipaddress.ip_network("fc00::/7"),       # unique local
    ipaddress.ip_network("fe80::/10"),      # link-local
    ipaddress.ip_network("::/128"),         # unspecified
]

# Cloud metadata endpoints
BLOCKED_HOSTNAMES = {
    "metadata.google.internal",
    "metadata.google",
    "169.254.169.254",       # AWS/GCP/Azure metadata
    "metadata",
    "localhost",
    "localhost.localdomain",
}


def _is_ip_blocked(ip_str: str) -> bool:
    """Check if an IP address falls within any blocked network."""
    try:
        addr = ipaddress.ip_address(ip_str)
        for net in BLOCKED_NETWORKS:
            if addr in net:
                return True
        return False
    except ValueError:
        return False


def _validate_hostname(hostname: str) -> Tuple[bool, str]:
    """Validate hostname is safe to connect to. Returns (is_safe, reason)."""
    hostname_lower = hostname.lower().strip()

    # Block known dangerous hostnames
    if hostname_lower in BLOCKED_HOSTNAMES:
        return False, f"Blocked hostname: {hostname_lower}"

    # Block hostnames that look like IPs
    try:
        addr = ipaddress.ip_address(hostname_lower)
        if _is_ip_blocked(str(addr)):
            return False, f"Blocked IP address: {hostname_lower}"
    except ValueError:
        pass  # Not an IP, continue with DNS

    # DNS resolution check — resolve and verify all IPs are public
    try:
        results = socket.getaddrinfo(hostname_lower, None, socket.AF_UNSPEC)
        for family, _, _, _, sockaddr in results:
            ip = sockaddr[0]
            if _is_ip_blocked(ip):
                return False, f"DNS resolves to blocked IP: {ip}"
    except socket.gaierror:
        return False, f"DNS resolution failed for: {hostname_lower}"
    except Exception as e:
        return False, f"DNS validation error: {str(e)}"

    return True, "OK"


def _validate_url(url: str) -> Tuple[bool, str, str]:
    """Validate and normalize URL. Returns (is_valid, normalized_url, reason)."""
    if not url or not isinstance(url, str):
        return False, "", "Empty or invalid URL"

    url = url.strip()

    # Add scheme if missing
    if not url.startswith(("http://", "https://")):
        url = "https://" + url

    parsed = urlparse(url)

    # Scheme validation
    if parsed.scheme not in ("http", "https"):
        return False, "", f"Unsupported scheme: {parsed.scheme}"

    # Hostname required
    if not parsed.hostname:
        return False, "", "No hostname in URL"

    # Validate hostname
    is_safe, reason = _validate_hostname(parsed.hostname)
    if not is_safe:
        return False, "", reason

    return True, url, "OK"


# ── Redirect Tracker ─────────────────────────────────────────────────────────

def _track_redirects(response: requests.Response) -> List[Dict[str, Any]]:
    """Extract the full redirect chain from a response."""
    chain = []
    for i, resp in enumerate(response.history):
        redirect_url = resp.headers.get("Location", "")
        parsed_from = urlparse(resp.url)
        parsed_to = urlparse(redirect_url) if redirect_url else None

        chain.append({
            "step": i + 1,
            "from_url": resp.url,
            "to_url": redirect_url,
            "status_code": resp.status_code,
            "redirect_type": "301 Permanent" if resp.status_code == 301 else
                             "302 Temporary" if resp.status_code == 302 else
                             "303 See Other" if resp.status_code == 303 else
                             "307 Temporary" if resp.status_code == 307 else
                             "308 Permanent" if resp.status_code == 308 else
                             f"{resp.status_code} Redirect",
            "from_domain": parsed_from.hostname or "",
            "to_domain": parsed_to.hostname if parsed_to else "",
            "domain_changed": (parsed_from.hostname or "").lower() != (parsed_to.hostname or "").lower() if parsed_to else False,
            "https_to_http": parsed_from.scheme == "https" and (parsed_to.scheme == "http" if parsed_to else False),
            "http_to_https": parsed_from.scheme == "http" and (parsed_to.scheme == "https" if parsed_to else False),
        })

    return chain


def _analyze_redirect_chain(chain: List[Dict], original_url: str, final_url: str) -> Dict[str, Any]:
    """Analyze redirect chain for suspicious patterns."""
    if not chain:
        return {
            "count": 0,
            "chain": [],
            "domain_changes": 0,
            "has_https_downgrade": False,
            "has_http_upgrade": False,
            "unique_domains": [],
            "suspicious": False,
            "findings": [],
        }

    domain_changes = sum(1 for r in chain if r.get("domain_changed", False))
    https_downgrades = sum(1 for r in chain if r.get("https_to_http", False))
    http_upgrades = sum(1 for r in chain if r.get("http_to_https", False))

    unique_domains = list(set(
        [r["from_domain"] for r in chain if r.get("from_domain")] +
        [r["to_domain"] for r in chain if r.get("to_domain")]
    ))

    findings = []
    if len(chain) > 3:
        findings.append(f"Excessive redirect chain ({len(chain)} redirects)")
    if domain_changes > 1:
        findings.append(f"Multiple domain changes during redirects ({domain_changes})")
    if https_downgrades > 0:
        findings.append("HTTPS to HTTP downgrade detected in redirect chain")

    return {
        "count": len(chain),
        "chain": chain,
        "domain_changes": domain_changes,
        "has_https_downgrade": https_downgrades > 0,
        "has_http_upgrade": http_upgrades > 0,
        "unique_domains": unique_domains,
        "suspicious": len(findings) > 0,
        "findings": findings,
    }


# ── Main Fetch Function ─────────────────────────────────────────────────────

def safe_fetch_webpage(url: str) -> Dict[str, Any]:
    """
    Safely fetch a webpage with full SSRF protection, redirect tracking,
    timeout enforcement, and response size limits.

    Returns a comprehensive fetch result dictionary.
    """
    timestamp_start = time.time()
    result = {
        "target_url": url,
        "normalized_url": None,
        "final_url": None,
        "fetch_status": None,
        "fetch_status_detail": None,
        "http_status": None,
        "response_time_ms": None,
        "content_type": None,
        "content_length": None,
        "server_header": None,
        "html_content": None,
        "response_headers": {},
        "redirect_analysis": None,
        "ssrf_policy": {"status": "enforced", "blocked_private_ips": True, "blocked_metadata": True},
        "timestamp": None,
    }

    # Step 1: Validate URL
    is_valid, normalized_url, reason = _validate_url(url)
    result["normalized_url"] = normalized_url

    if not is_valid:
        result["fetch_status"] = SSRF_BLOCKED if "Blocked" in reason or "blocked" in reason else (
            DNS_FAILURE if "DNS" in reason else INVALID_URL
        )
        result["fetch_status_detail"] = reason
        result["response_time_ms"] = round((time.time() - timestamp_start) * 1000)
        result["timestamp"] = time.strftime("%Y-%m-%dT%H:%M:%S")
        return result

    # Step 2: Fetch with protections
    try:
        session = requests.Session()
        session.max_redirects = MAX_REDIRECTS
        req_headers = {
            "User-Agent": USER_AGENT,
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.5",
            "Accept-Encoding": "gzip, deflate",
            "Connection": "close",
        }
        proxied = bool(requests.utils.get_environ_proxies(normalized_url))

        # Follow redirects MANUALLY so every hop is validated BEFORE any connection
        # is made to it (requests' automatic redirects would connect first).
        current_url = normalized_url
        history = []
        response = None
        for hop in range(MAX_REDIRECTS + 1):
            if hop > 0:
                hop_parsed = urlparse(current_url)
                if hop_parsed.scheme not in ("http", "https") or not hop_parsed.hostname:
                    result["fetch_status"] = SSRF_BLOCKED
                    result["fetch_status_detail"] = f"Redirect to unsupported destination blocked: {current_url[:200]}"
                    result["response_time_ms"] = round((time.time() - timestamp_start) * 1000)
                    result["timestamp"] = time.strftime("%Y-%m-%dT%H:%M:%S")
                    return result
                hop_safe, hop_reason = _validate_hostname(hop_parsed.hostname)
                if not hop_safe:
                    result["fetch_status"] = SSRF_BLOCKED
                    result["fetch_status_detail"] = f"Redirect destination blocked: {hop_reason}"
                    result["response_time_ms"] = round((time.time() - timestamp_start) * 1000)
                    result["timestamp"] = time.strftime("%Y-%m-%dT%H:%M:%S")
                    return result
            resp = session.get(current_url, timeout=(CONNECT_TIMEOUT, READ_TIMEOUT), headers=req_headers,
                               allow_redirects=False, verify=True, stream=True)
            # DNS-rebinding guard: the socket we actually connected to must be public.
            if not proxied:
                try:
                    peer_ip = resp.raw.connection.sock.getpeername()[0]
                    if _is_ip_blocked(peer_ip):
                        resp.close()
                        result["fetch_status"] = SSRF_BLOCKED
                        result["fetch_status_detail"] = f"Connected peer address is blocked: {peer_ip}"
                        result["response_time_ms"] = round((time.time() - timestamp_start) * 1000)
                        result["timestamp"] = time.strftime("%Y-%m-%dT%H:%M:%S")
                        return result
                except Exception:
                    pass  # peer address not exposed by this transport; pre-connection checks still apply
            if resp.is_redirect and resp.headers.get("Location"):
                history.append(resp)
                current_url = urljoin(resp.url, resp.headers.get("Location"))
                resp.close()
                continue
            response = resp
            break
        if response is None:
            raise TooManyRedirects(f"Exceeded {MAX_REDIRECTS} redirects")
        response.history = history

        # Validate each redirect destination
        for resp in response.history:
            redirect_url = resp.headers.get("Location", "")
            if redirect_url:
                parsed_redirect = urlparse(urljoin(resp.url, redirect_url))
                if parsed_redirect.hostname:
                    is_safe, block_reason = _validate_hostname(parsed_redirect.hostname)
                    if not is_safe:
                        result["fetch_status"] = SSRF_BLOCKED
                        result["fetch_status_detail"] = f"Redirect destination blocked: {block_reason}"
                        result["response_time_ms"] = round((time.time() - timestamp_start) * 1000)
                        result["timestamp"] = time.strftime("%Y-%m-%dT%H:%M:%S")
                        return result

        # Validate final destination
        final_parsed = urlparse(response.url)
        if final_parsed.hostname:
            is_safe, block_reason = _validate_hostname(final_parsed.hostname)
            if not is_safe:
                result["fetch_status"] = SSRF_BLOCKED
                result["fetch_status_detail"] = f"Final destination blocked: {block_reason}"
                result["response_time_ms"] = round((time.time() - timestamp_start) * 1000)
                result["timestamp"] = time.strftime("%Y-%m-%dT%H:%M:%S")
                return result

        # Check content type
        content_type = response.headers.get("Content-Type", "")
        if content_type and not any(t in content_type.lower() for t in ["text/html", "application/xhtml", "text/plain", "application/xml"]):
            result["fetch_status"] = UNSUPPORTED_CONTENT
            result["fetch_status_detail"] = f"Unsupported content type: {content_type}"
            result["http_status"] = response.status_code
            result["content_type"] = content_type
            result["final_url"] = response.url
            result["response_time_ms"] = round((time.time() - timestamp_start) * 1000)
            result["timestamp"] = time.strftime("%Y-%m-%dT%H:%M:%S")
            result["redirect_analysis"] = _analyze_redirect_chain(
                _track_redirects(response), url, response.url
            )
            return result

        # Read content with size limit
        content_chunks = []
        bytes_read = 0
        for chunk in response.iter_content(chunk_size=8192, decode_unicode=False):
            bytes_read += len(chunk)
            if bytes_read > MAX_RESPONSE_SIZE:
                result["fetch_status"] = CONTENT_TOO_LARGE
                result["fetch_status_detail"] = f"Response exceeded {MAX_RESPONSE_SIZE // (1024*1024)}MB limit"
                result["http_status"] = response.status_code
                result["final_url"] = response.url
                result["response_time_ms"] = round((time.time() - timestamp_start) * 1000)
                result["timestamp"] = time.strftime("%Y-%m-%dT%H:%M:%S")
                return result
            content_chunks.append(chunk)

        raw_content = b"".join(content_chunks)

        # Decode HTML
        encoding = response.encoding or "utf-8"
        try:
            html_content = raw_content.decode(encoding, errors="replace")
        except (UnicodeDecodeError, LookupError):
            html_content = raw_content.decode("utf-8", errors="replace")

        # Truncate if over HTML limit
        if len(html_content) > MAX_HTML_SIZE:
            html_content = html_content[:MAX_HTML_SIZE]

        # Extract key response headers
        security_headers = {}
        for h in ["Content-Security-Policy", "Strict-Transport-Security",
                   "X-Frame-Options", "X-Content-Type-Options",
                   "Referrer-Policy", "Permissions-Policy",
                   "X-XSS-Protection", "Access-Control-Allow-Origin"]:
            val = response.headers.get(h)
            if val:
                security_headers[h] = val

        # Check for CAPTCHA, bot challenge, Cloudflare or human verification barriers
        html_lower = html_content.lower() if html_content else ""
        server_hdr = (response.headers.get("Server") or "").lower()
        has_challenge_markers = any(term in html_lower for term in [
            "cf-ray", "cf-browser-verification", "cf_chl_opt", "turnstile", "hcaptcha",
            "g-recaptcha", "captcha", "verify you are human", "just a moment...",
            "ddos-guard", "challenge-platform", "checking your browser before accessing",
            "bot detection", "access denied - cloudflare"
        ]) or any(h in response.headers for h in ["cf-ray", "cf-mitigated"])

        http_status = response.status_code
        if (http_status in (403, 429, 503) and has_challenge_markers) or ("just a moment..." in html_lower and "cloudflare" in html_lower):
            fetch_status = BLOCKED_BY_HUMAN_VERIFICATION
            fetch_status_detail = "NeuraShield could not fully inspect this webpage because automated access was restricted by a bot challenge / human verification barrier."
        elif http_status >= 400:
            fetch_status = HTTP_ERROR
            fetch_status_detail = f"HTTP {http_status}"
            if http_status == 404:
                fetch_status_detail = "HTTP 404 Not Found"
            elif http_status == 403:
                fetch_status_detail = "HTTP 403 Forbidden"
            elif http_status == 429:
                fetch_status_detail = "HTTP 429 Too Many Requests"
            elif 500 <= http_status < 600:
                fetch_status_detail = f"HTTP {http_status} Server Error"
        elif not html_content.strip():
            fetch_status = UNSUPPORTED_CONTENT
            fetch_status_detail = "Empty HTTP response body (no HTML content retrieved)"
        else:
            fetch_status = FETCH_SUCCESS
            fetch_status_detail = "Success"

        result.update({
            "fetch_status": fetch_status,
            "fetch_status_detail": fetch_status_detail,
            "http_status": http_status,
            "final_url": response.url,
            "content_type": content_type,
            "content_length": bytes_read,
            "server_header": response.headers.get("Server", None),
            "html_content": html_content if fetch_status == FETCH_SUCCESS else "",
            "response_headers": dict(response.headers),
            "security_headers": security_headers,
            "redirect_analysis": _analyze_redirect_chain(
                _track_redirects(response), url, response.url
            ),
            "response_time_ms": round((time.time() - timestamp_start) * 1000),
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%S"),
        })

        return result

    except TooManyRedirects:
        result["fetch_status"] = REDIRECT_LIMIT
        result["fetch_status_detail"] = f"Exceeded maximum redirect limit ({MAX_REDIRECTS})"
    except SSLError as e:
        result["fetch_status"] = TLS_FAILURE
        result["fetch_status_detail"] = f"TLS/SSL error: {str(e)[:200]}"
    except Timeout:
        result["fetch_status"] = CONNECTION_TIMEOUT
        result["fetch_status_detail"] = f"Connection timed out after {CONNECT_TIMEOUT}s connect / {READ_TIMEOUT}s read"
    except ConnectionError as e:
        err_str = str(e).lower()
        if "name or service not known" in err_str or "nodename nor servname" in err_str or "getaddrinfo" in err_str:
            result["fetch_status"] = DNS_FAILURE
            result["fetch_status_detail"] = "DNS resolution failed"
        elif "refused" in err_str or "10061" in err_str or "111" in err_str:
            result["fetch_status"] = CONNECTION_REFUSED
            result["fetch_status_detail"] = "Connection refused by target server"
        else:
            result["fetch_status"] = NETWORK_ERROR
            result["fetch_status_detail"] = f"Connection error: {str(e)[:200]}"
    except RequestException as e:
        result["fetch_status"] = NETWORK_ERROR
        result["fetch_status_detail"] = f"Request error: {str(e)[:200]}"
    except Exception as e:
        result["fetch_status"] = NETWORK_ERROR
        result["fetch_status_detail"] = f"Unexpected error: {str(e)[:200]}"

    result["response_time_ms"] = round((time.time() - timestamp_start) * 1000)
    result["timestamp"] = time.strftime("%Y-%m-%dT%H:%M:%S")
    return result


def is_bot_challenge_or_spa(fetch_result: Dict[str, Any]) -> bool:
    """Check if static fetch encountered bot protection (403/503) or empty SPA template."""
    status = fetch_result.get("http_status")
    html = fetch_result.get("html_content") or ""
    server = (fetch_result.get("server_header") or "").lower()

    # 1. Cloudflare / Bot mitigation headers or codes
    if status in (403, 503):
        return True
    if "cloudflare" in server and any(term in html.lower() for term in ("turnstile", "cf-chl", "cf-browser-verification", "checking your browser")):
        return True

    # 2. SPA detection (empty root div with client-side script)
    if any(spa_tag in html for spa_tag in ('id="root"', 'id="app"', 'id="__next"')):
        if len(html) < 4000 and "<form" not in html.lower():
            return True

    return False


def safe_fetch_webpage_hybrid(
    url: str,
    force_headless: bool = False,
    screenshot_dir: Optional[str] = None
) -> Dict[str, Any]:
    """
    Dual-Tier Hybrid Fetcher:
    Tier 1: Runs fast static requests fetcher.
    Tier 2: Upgrades to sandboxed Playwright headless browser if bot challenge or SPA detected,
            or if force_headless is True.
    """
    try:
        from model.webpage_intelligence.headless_fetcher import dynamic_fetch_webpage, PLAYWRIGHT_AVAILABLE
    except ImportError:
        PLAYWRIGHT_AVAILABLE = False
        dynamic_fetch_webpage = None

    if force_headless and PLAYWRIGHT_AVAILABLE and dynamic_fetch_webpage:
        dynamic_res = dynamic_fetch_webpage(url, screenshot_dir=screenshot_dir)
        if dynamic_res.get("fetch_status") == FETCH_SUCCESS:
            return dynamic_res

    # Tier 1: Try static first
    static_res = safe_fetch_webpage(url)

    # Tier 2: Check if upgrade to headless browser is needed
    if PLAYWRIGHT_AVAILABLE and dynamic_fetch_webpage and is_bot_challenge_or_spa(static_res):
        dynamic_res = dynamic_fetch_webpage(url, screenshot_dir=screenshot_dir)
        if dynamic_res.get("fetch_status") == FETCH_SUCCESS:
            return dynamic_res

    # Default to static result
    static_res["engine_used"] = "STATIC_CRAWLER"
    static_res["screenshot_url"] = None
    return static_res

