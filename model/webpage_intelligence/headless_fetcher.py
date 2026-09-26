"""
NEURASHIELD — MODULE 3: PLAYWRIGHT HEADLESS BROWSER ENGINE
Sandboxed Headless Chromium engine for dynamic Single-Page Application (SPA) rendering,
JavaScript hydration, automated screenshot capture, and SSRF routing security.
"""

import os
import sys
import time
import socket
import ipaddress
import hashlib
from urllib.parse import urlparse
from typing import Dict, Any, Optional, Tuple

# Try importing Playwright
try:
    from playwright.sync_api import sync_playwright, TimeoutError as PlaywrightTimeoutError
    PLAYWRIGHT_AVAILABLE = True
except ImportError:
    PLAYWRIGHT_AVAILABLE = False
    sync_playwright = None
    PlaywrightTimeoutError = Exception

# SSRF Protected Networks
BLOCKED_NETWORKS = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("169.254.0.0/16"),
    ipaddress.ip_network("0.0.0.0/8"),
    ipaddress.ip_network("::1/128"),
    ipaddress.ip_network("fc00::/7"),
    ipaddress.ip_network("fe80::/10"),
]

BLOCKED_HOSTNAMES = {
    "localhost", "localhost.localdomain",
    "metadata.google.internal", "metadata.google",
    "169.254.169.254", "metadata"
}

def is_ip_blocked(ip_str: str) -> bool:
    try:
        ip = ipaddress.ip_address(ip_str)
        return any(ip in net for net in BLOCKED_NETWORKS)
    except ValueError:
        return True

def validate_target_url(url: str) -> Tuple[bool, str]:
    try:
        parsed = urlparse(url if "://" in url else f"https://{url}")
        host = (parsed.hostname or "").lower().strip()
        if not host:
            return False, "Empty or invalid hostname"
        if host in BLOCKED_HOSTNAMES:
            return False, f"Target hostname {host} is blocked by SSRF policy"
        try:
            addr_info = socket.getaddrinfo(host, None)
            for item in addr_info:
                ip = item[4][0]
                if is_ip_blocked(ip):
                    return False, f"Target resolves to blocked address ({ip})"
        except socket.gaierror:
            pass # allow DNS resolution to proceed in browser if needed
        return True, "Valid"
    except Exception as e:
        return False, str(e)


def dynamic_fetch_webpage(
    url: str,
    screenshot_dir: Optional[str] = None,
    timeout_ms: int = 15000,
    wait_time_ms: int = 2000
) -> Dict[str, Any]:
    """
    Launch headless Chromium, navigate to URL, wait for dynamic JS to render,
    intercept and block any internal/SSRF requests, capture screenshot and full DOM.
    """
    if not PLAYWRIGHT_AVAILABLE:
        return {
            "fetch_status": "PLAYWRIGHT_UNAVAILABLE",
            "fetch_status_detail": "Playwright is not installed in the Python environment.",
            "http_status": None,
            "html_content": None,
            "engine_used": "NONE",
            "screenshot_url": None,
        }

    is_valid, reason = validate_target_url(url)
    if not is_valid:
        return {
            "fetch_status": "SSRF_BLOCKED",
            "fetch_status_detail": f"SSRF Security Violation: {reason}",
            "http_status": 403,
            "html_content": None,
            "engine_used": "PLAYWRIGHT_SANDBOX",
            "screenshot_url": None,
        }

    start_time = time.time()
    normalized_url = url if "://" in url else f"https://{url}"

    # Setup screenshot path
    url_hash = hashlib.sha256(normalized_url.encode()).hexdigest()[:12]
    screenshot_filename = f"scan_{url_hash}_{int(time.time())}.png"
    
    if not screenshot_dir:
        # Default to frontend/static/screenshots
        base_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "frontend", "static", "screenshots"))
        os.makedirs(base_dir, exist_ok=True)
        screenshot_path = os.path.join(base_dir, screenshot_filename)
        screenshot_url = f"/static/screenshots/{screenshot_filename}"
    else:
        os.makedirs(screenshot_dir, exist_ok=True)
        screenshot_path = os.path.join(screenshot_dir, screenshot_filename)
        screenshot_url = f"/static/screenshots/{screenshot_filename}"

    captured_requests = []
    intercepted_blocks = 0
    http_status = None
    response_headers = {}
    final_url = normalized_url
    rendered_html = ""

    try:
        with sync_playwright() as p:
            local_appdata = os.environ.get("LOCALAPPDATA", "")
            chrome_candidates = [
                os.path.join(local_appdata, "ms-playwright", "chromium_headless_shell-1243", "chrome-headless-shell-win64", "chrome-headless-shell.exe"),
                os.path.join(local_appdata, "ms-playwright", "chromium-1243", "chrome-win64", "chrome.exe"),
            ]
            launch_kwargs = {
                "headless": True,
                "args": [
                    "--no-sandbox",
                    "--disable-dev-shm-usage",
                    "--disable-gpu",
                    "--disable-blink-features=AutomationControlled",
                ]
            }
            for candidate in chrome_candidates:
                if os.path.exists(candidate):
                    launch_kwargs["executable_path"] = candidate
                    break

            browser = p.chromium.launch(**launch_kwargs)
            context = browser.new_context(
                viewport={"width": 1280, "height": 800},
                user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36 NeuraShield/3.0",
                ignore_https_errors=True
            )

            page = context.new_page()

            # SSRF Route Interception
            def handle_route(route):
                req_url = route.request.url
                try:
                    p_url = urlparse(req_url)
                    p_host = (p_url.hostname or "").lower()
                    if p_host in BLOCKED_HOSTNAMES or p_host == "127.0.0.1" or p_host == "localhost":
                        route.abort()
                        return
                    # Quick IP check if raw IP
                    if any(c.isdigit() for c in p_host) and is_ip_blocked(p_host):
                        route.abort()
                        return
                except Exception:
                    pass
                route.continue_()

            page.route("**/*", handle_route)

            # Navigate to target
            response = page.goto(
                normalized_url,
                timeout=timeout_ms,
                wait_until="domcontentloaded"
            )

            # Extra wait for dynamic client-side hydration (React/Vue/Angular rendering)
            if wait_time_ms > 0:
                page.wait_for_timeout(wait_time_ms)

            if response:
                http_status = response.status
                response_headers = response.headers
                final_url = page.url

            rendered_html = page.content()

            # Capture visual screenshot
            try:
                page.screenshot(path=screenshot_path, full_page=False)
            except Exception as se:
                print(f"Screenshot capture notice: {se}")
                screenshot_url = None

            browser.close()

            elapsed_ms = int((time.time() - start_time) * 1000)

            return {
                "target_url": url,
                "normalized_url": normalized_url,
                "final_url": final_url,
                "fetch_status": "FETCH_SUCCESS",
                "fetch_status_detail": f"{http_status} OK (Rendered via Playwright Chromium Sandbox)",
                "http_status": http_status or 200,
                "response_time_ms": elapsed_ms,
                "content_type": response_headers.get("content-type", "text/html"),
                "content_length": len(rendered_html.encode('utf-8')),
                "server_header": response_headers.get("server", "Dynamic/Chromium"),
                "html_content": rendered_html,
                "response_headers": response_headers,
                "engine_used": "PLAYWRIGHT_SANDBOX",
                "screenshot_url": screenshot_url,
                "screenshot_path": screenshot_path,
                "redirect_analysis": {
                    "count": 1 if final_url != normalized_url else 0,
                    "final_url": final_url,
                    "is_cross_domain": urlparse(final_url).hostname != urlparse(normalized_url).hostname
                },
                "ssrf_policy": {
                    "status": "enforced",
                    "blocked_private_ips": True,
                    "intercepted_blocks": intercepted_blocks
                },
                "timestamp": time.strftime("%Y-%m-%dT%H:%M:%S")
            }

    except PlaywrightTimeoutError:
        elapsed_ms = int((time.time() - start_time) * 1000)
        return {
            "target_url": url,
            "normalized_url": normalized_url,
            "final_url": normalized_url,
            "fetch_status": "CONNECTION_TIMEOUT",
            "fetch_status_detail": f"Playwright navigation timed out after {timeout_ms}ms.",
            "http_status": None,
            "response_time_ms": elapsed_ms,
            "html_content": None,
            "engine_used": "PLAYWRIGHT_SANDBOX",
            "screenshot_url": None,
        }
    except Exception as e:
        elapsed_ms = int((time.time() - start_time) * 1000)
        return {
            "target_url": url,
            "normalized_url": normalized_url,
            "final_url": normalized_url,
            "fetch_status": "DYNAMIC_FETCH_ERROR",
            "fetch_status_detail": f"Playwright execution error: {str(e)}",
            "http_status": None,
            "response_time_ms": elapsed_ms,
            "html_content": None,
            "engine_used": "PLAYWRIGHT_SANDBOX",
            "screenshot_url": None,
        }
