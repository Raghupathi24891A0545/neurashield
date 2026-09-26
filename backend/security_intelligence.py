"""NeuraShield Security Intelligence Adapter Layer.

Integrates external security intelligence APIs:
- VirusTotal (API v3)
- urlscan.io
- Google Safe Browsing (Lookup API v4)

Follows strict principles:
1. Provider adapter abstraction — no hardcoded provider logic elsewhere.
2. Evidence model normalization — all findings fit NeuraShield's EvidenceItem structure.
3. Graceful degradation — if an API key is missing or an endpoint fails, the system
   reports status UNAVAILABLE without halting or fabricating results.
4. Secrets stay backend-only via environment variables.
5. In-memory caching prevents duplicate queries and respects provider rate limits.
"""

import base64
import hashlib
import json
import os
import time
from urllib.parse import urlparse
import requests


# ─────────────────────────────────────────────────────────────────────────────
# Cache & Rate Limiting helper
# ─────────────────────────────────────────────────────────────────────────────

class _TTLCache:
    def __init__(self, ttl_seconds=900):
        self._ttl = ttl_seconds
        self._store = {}

    def get(self, key):
        entry = self._store.get(key)
        if not entry:
            return None
        val, ts = entry
        if time.time() - ts > self._ttl:
            del self._store[key]
            return None
        return val

    def set(self, key, val):
        self._store[key] = (val, time.time())


_intel_cache = _TTLCache(ttl_seconds=1800)


# ─────────────────────────────────────────────────────────────────────────────
# 1. VIRUSTOTAL ADAPTER (API v3)
# ─────────────────────────────────────────────────────────────────────────────

class VirusTotalAdapter:
    """VirusTotal API v3 integration for URL and domain reputation."""

    BASE_URL = "https://www.virustotal.com/api/v3"

    def __init__(self, api_key=None):
        self.api_key = api_key or os.environ.get("VIRUSTOTAL_API_KEY", "").strip()

    @property
    def is_configured(self) -> bool:
        return bool(self.api_key)

    def _headers(self):
        return {
            "x-apikey": self.api_key,
            "Accept": "application/json",
            "User-Agent": "NeuraShield-Cybersecurity-Intelligence/2.0"
        }

    def _url_to_id(self, url: str) -> str:
        # VT v3 URL ID is base64url encoded without padding
        return base64.urlsafe_b64encode(url.encode()).decode().strip("=")

    def query_url(self, url: str) -> dict:
        """Query URL reputation from VirusTotal."""
        if not self.is_configured:
            return {
                "source": "VirusTotal",
                "target": url,
                "target_type": "URL",
                "status": "UNAVAILABLE",
                "reason": "Unavailable — VIRUSTOTAL_API_KEY not configured.",
                "evidence": None
            }

        cache_key = f"vt:url:{url}"
        cached = _intel_cache.get(cache_key)
        if cached:
            return cached

        url_id = self._url_to_id(url)
        endpoint = f"{self.BASE_URL}/urls/{url_id}"

        try:
            resp = requests.get(endpoint, headers=self._headers(), timeout=8)
            if resp.status_code == 200:
                data = resp.json().get("data", {})
                attrs = data.get("attributes", {})
                stats = attrs.get("last_analysis_stats", {})
                results = attrs.get("last_analysis_results", {})
                reputation = attrs.get("reputation", 0)

                malicious = stats.get("malicious", 0)
                suspicious = stats.get("suspicious", 0)
                harmless = stats.get("harmless", 0)
                undetected = stats.get("undetected", 0)
                total_engines = malicious + suspicious + harmless + undetected

                flagged_vendors = [
                    v for v, r in results.items()
                    if r.get("category") in ("malicious", "suspicious")
                ][:10]

                observation = (
                    f"VirusTotal v3: {malicious}/{total_engines} engines flagged as malicious, "
                    f"{suspicious} suspicious (Reputation score: {reputation})."
                )
                if flagged_vendors:
                    observation += f" Flagged by: {', '.join(flagged_vendors[:5])}."

                res = {
                    "source": "VirusTotal",
                    "target": url,
                    "target_type": "URL",
                    "status": "VERIFIED_EXTERNAL_INTELLIGENCE",
                    "malicious_count": malicious,
                    "suspicious_count": suspicious,
                    "harmless_count": harmless,
                    "total_engines": total_engines,
                    "reputation_score": reputation,
                    "flagged_vendors": flagged_vendors,
                    "categories": attrs.get("categories", {}),
                    "last_analysis_date": attrs.get("last_analysis_date"),
                    "observation": observation,
                    "evidence": {
                        "category": "EXTERNAL_SECURITY_INTELLIGENCE",
                        "source": "VirusTotal",
                        "observation": observation,
                        "value": {
                            "malicious": malicious,
                            "suspicious": suspicious,
                            "total": total_engines,
                            "reputation": reputation,
                            "vendors": flagged_vendors
                        },
                        "confidence": "VERIFIED",
                        "status": "VERIFIED"
                    }
                }
                _intel_cache.set(cache_key, res)
                return res

            elif resp.status_code == 404:
                # URL has not been analyzed yet on VirusTotal
                return {
                    "source": "VirusTotal",
                    "target": url,
                    "target_type": "URL",
                    "status": "UNAVAILABLE",
                    "reason": "URL not previously observed or analyzed by VirusTotal.",
                    "evidence": None
                }
            elif resp.status_code == 429:
                return {
                    "source": "VirusTotal",
                    "target": url,
                    "target_type": "URL",
                    "status": "UNAVAILABLE",
                    "reason": "VirusTotal API rate limit reached.",
                    "evidence": None
                }
            else:
                return {
                    "source": "VirusTotal",
                    "target": url,
                    "target_type": "URL",
                    "status": "UNAVAILABLE",
                    "reason": f"VirusTotal returned HTTP {resp.status_code}.",
                    "evidence": None
                }

        except Exception as e:
            return {
                "source": "VirusTotal",
                "target": url,
                "target_type": "URL",
                "status": "UNAVAILABLE",
                "reason": f"VirusTotal connection error: {str(e)}",
                "evidence": None
            }

    def query_domain(self, domain: str) -> dict:
        """Query domain reputation from VirusTotal."""
        if not self.is_configured:
            return {
                "source": "VirusTotal",
                "target": domain,
                "target_type": "DOMAIN",
                "status": "UNAVAILABLE",
                "reason": "Unavailable — VIRUSTOTAL_API_KEY not configured.",
                "evidence": None
            }

        cache_key = f"vt:domain:{domain}"
        cached = _intel_cache.get(cache_key)
        if cached:
            return cached

        endpoint = f"{self.BASE_URL}/domains/{domain}"
        try:
            resp = requests.get(endpoint, headers=self._headers(), timeout=8)
            if resp.status_code == 200:
                data = resp.json().get("data", {})
                attrs = data.get("attributes", {})
                stats = attrs.get("last_analysis_stats", {})
                results = attrs.get("last_analysis_results", {})
                reputation = attrs.get("reputation", 0)

                malicious = stats.get("malicious", 0)
                suspicious = stats.get("suspicious", 0)
                harmless = stats.get("harmless", 0)
                undetected = stats.get("undetected", 0)
                total = malicious + suspicious + harmless + undetected

                flagged_vendors = [
                    v for v, r in results.items()
                    if r.get("category") in ("malicious", "suspicious")
                ][:10]

                registrar = attrs.get("registrar", "")
                categories = attrs.get("categories", {})

                observation = (
                    f"VirusTotal v3: Domain '{domain}' flagged by {malicious}/{total} security engines. "
                    f"Reputation: {reputation}."
                )

                res = {
                    "source": "VirusTotal",
                    "target": domain,
                    "target_type": "DOMAIN",
                    "status": "VERIFIED_EXTERNAL_INTELLIGENCE",
                    "malicious_count": malicious,
                    "suspicious_count": suspicious,
                    "harmless_count": harmless,
                    "total_engines": total,
                    "reputation_score": reputation,
                    "flagged_vendors": flagged_vendors,
                    "categories": categories,
                    "registrar": registrar,
                    "observation": observation,
                    "evidence": {
                        "category": "EXTERNAL_SECURITY_INTELLIGENCE",
                        "source": "VirusTotal",
                        "observation": observation,
                        "value": {
                            "malicious": malicious,
                            "suspicious": suspicious,
                            "total": total,
                            "reputation": reputation,
                            "vendors": flagged_vendors
                        },
                        "confidence": "VERIFIED",
                        "status": "VERIFIED"
                    }
                }
                _intel_cache.set(cache_key, res)
                return res
            elif resp.status_code == 404:
                return {
                    "source": "VirusTotal",
                    "target": domain,
                    "target_type": "DOMAIN",
                    "status": "UNAVAILABLE",
                    "reason": "Domain not observed in VirusTotal dataset.",
                    "evidence": None
                }
            else:
                return {
                    "source": "VirusTotal",
                    "target": domain,
                    "target_type": "DOMAIN",
                    "status": "UNAVAILABLE",
                    "reason": f"VirusTotal returned HTTP {resp.status_code}.",
                    "evidence": None
                }
        except Exception as e:
            return {
                "source": "VirusTotal",
                "target": domain,
                "target_type": "DOMAIN",
                "status": "UNAVAILABLE",
                "reason": f"VirusTotal connection error: {str(e)}",
                "evidence": None
            }


# ─────────────────────────────────────────────────────────────────────────────
# 2. URLSCAN.IO ADAPTER
# ─────────────────────────────────────────────────────────────────────────────

class UrlscanAdapter:
    """urlscan.io integration for historical webpage/domain intelligence."""

    BASE_URL = "https://urlscan.io/api/v1"

    def __init__(self, api_key=None):
        self.api_key = api_key or os.environ.get("URLSCAN_API_KEY", "").strip()

    @property
    def is_configured(self) -> bool:
        return bool(self.api_key)

    def _headers(self):
        h = {"User-Agent": "NeuraShield-Cybersecurity-Intelligence/2.0"}
        if self.api_key:
            h["API-Key"] = self.api_key
        return h

    def query_target(self, target: str, is_domain: bool = False) -> dict:
        """Search urlscan.io for existing scan records without unnecessary submission."""
        cache_key = f"urlscan:{'domain' if is_domain else 'url'}:{target}"
        cached = _intel_cache.get(cache_key)
        if cached:
            return cached

        # Search endpoint doesn't strictly require API key, but having it increases limits
        try:
            q = f'page.domain:"{target}"' if is_domain else f'page.url:"{target}"'
            endpoint = f"{self.BASE_URL}/search/?q={requests.utils.quote(q)}&size=1"
            resp = requests.get(endpoint, headers=self._headers(), timeout=8)

            if resp.status_code == 200:
                results = resp.json().get("results", [])
                if results:
                    hit = results[0]
                    page = hit.get("page", {})
                    task = hit.get("task", {})
                    stats = hit.get("stats", {})
                    verdicts = hit.get("verdicts", {})
                    screenshot_url = hit.get("screenshot")
                    result_url = hit.get("result")

                    overall_malicious = (verdicts.get("overall", {}).get("malicious") or
                                         verdicts.get("urlscan", {}).get("malicious"))
                    score = verdicts.get("overall", {}).get("score", 0)

                    obs = (
                        f"urlscan.io historical scan: Observed IP {page.get('ip', 'unknown')} "
                        f"({page.get('country', 'unknown')}), Server: {page.get('server', 'unknown')}. "
                        f"Verdict malicious: {bool(overall_malicious)} (Score: {score})."
                    )

                    res = {
                        "source": "urlscan.io",
                        "target": target,
                        "status": "VERIFIED_EXTERNAL_INTELLIGENCE",
                        "ip": page.get("ip"),
                        "country": page.get("country"),
                        "server": page.get("server"),
                        "asn": page.get("asnname"),
                        "screenshot_url": screenshot_url,
                        "result_url": result_url,
                        "malicious": bool(overall_malicious),
                        "score": score,
                        "scan_time": task.get("time"),
                        "observation": obs,
                        "evidence": {
                            "category": "EXTERNAL_SECURITY_INTELLIGENCE",
                            "source": "urlscan.io",
                            "observation": obs,
                            "value": {
                                "ip": page.get("ip"),
                                "country": page.get("country"),
                                "server": page.get("server"),
                                "malicious": bool(overall_malicious),
                                "score": score,
                                "screenshot": screenshot_url
                            },
                            "confidence": "VERIFIED",
                            "status": "VERIFIED"
                        }
                    }
                    _intel_cache.set(cache_key, res)
                    return res
                else:
                    return {
                        "source": "urlscan.io",
                        "target": target,
                        "status": "UNAVAILABLE",
                        "reason": "No previous urlscan.io scan records found for this target.",
                        "evidence": None
                    }
            elif resp.status_code == 429:
                return {
                    "source": "urlscan.io",
                    "target": target,
                    "status": "UNAVAILABLE",
                    "reason": "urlscan.io rate limit reached.",
                    "evidence": None
                }
            else:
                return {
                    "source": "urlscan.io",
                    "target": target,
                    "status": "UNAVAILABLE",
                    "reason": f"urlscan.io search returned HTTP {resp.status_code}.",
                    "evidence": None
                }

        except Exception as e:
            return {
                "source": "urlscan.io",
                "target": target,
                "status": "UNAVAILABLE",
                "reason": f"urlscan.io connection error: {str(e)}",
                "evidence": None
            }


# ─────────────────────────────────────────────────────────────────────────────
# 3. GOOGLE SAFE BROWSING ADAPTER (v4)
# ─────────────────────────────────────────────────────────────────────────────

class GoogleSafeBrowsingAdapter:
    """Google Safe Browsing v4 threatMatches lookup API."""

    BASE_URL = "https://safebrowsing.googleapis.com/v4/threatMatches:find"

    def __init__(self, api_key=None):
        self.api_key = api_key or os.environ.get("GOOGLE_SAFE_BROWSING_API_KEY", "").strip()

    @property
    def is_configured(self) -> bool:
        return bool(self.api_key)

    def query_url(self, url: str) -> dict:
        """Lookup URL in Google Safe Browsing lists."""
        if not self.is_configured:
            return {
                "source": "Google Safe Browsing",
                "target": url,
                "status": "UNAVAILABLE",
                "reason": "Unavailable — GOOGLE_SAFE_BROWSING_API_KEY not configured.",
                "evidence": None
            }

        cache_key = f"gsb:{url}"
        cached = _intel_cache.get(cache_key)
        if cached:
            return cached

        payload = {
            "client": {
                "clientId": "neurashield-investigation-platform",
                "clientVersion": "2.0.0"
            },
            "threatInfo": {
                "threatTypes": [
                    "MALWARE",
                    "SOCIAL_ENGINEERING",
                    "UNWANTED_SOFTWARE",
                    "POTENTIALLY_HARMFUL_APPLICATION"
                ],
                "platformTypes": ["ANY_PLATFORM"],
                "threatEntryTypes": ["URL"],
                "threatEntries": [{"url": url}]
            }
        }

        try:
            endpoint = f"{self.BASE_URL}?key={self.api_key}"
            resp = requests.post(endpoint, json=payload, timeout=7)
            if resp.status_code == 200:
                matches = resp.json().get("matches", [])
                if matches:
                    threat_types = list(set(m.get("threatType") for m in matches))
                    obs = f"Google Safe Browsing ACTIVE THREAT MATCH: Flagged as {', '.join(threat_types)}."
                    res = {
                        "source": "Google Safe Browsing",
                        "target": url,
                        "status": "VERIFIED_EXTERNAL_INTELLIGENCE",
                        "listed": True,
                        "threat_types": threat_types,
                        "observation": obs,
                        "evidence": {
                            "category": "EXTERNAL_SECURITY_INTELLIGENCE",
                            "source": "Google Safe Browsing",
                            "observation": obs,
                            "value": {"threat_types": threat_types, "listed": True},
                            "confidence": "VERIFIED",
                            "status": "VERIFIED"
                        }
                    }
                else:
                    obs = "Google Safe Browsing verified: Target not listed on threat databases."
                    res = {
                        "source": "Google Safe Browsing",
                        "target": url,
                        "status": "VERIFIED_EXTERNAL_INTELLIGENCE",
                        "listed": False,
                        "threat_types": [],
                        "observation": obs,
                        "evidence": {
                            "category": "EXTERNAL_SECURITY_INTELLIGENCE",
                            "source": "Google Safe Browsing",
                            "observation": obs,
                            "value": {"listed": False},
                            "confidence": "VERIFIED",
                            "status": "VERIFIED"
                        }
                    }
                _intel_cache.set(cache_key, res)
                return res
            else:
                return {
                    "source": "Google Safe Browsing",
                    "target": url,
                    "status": "UNAVAILABLE",
                    "reason": f"Google Safe Browsing returned HTTP {resp.status_code}.",
                    "evidence": None
                }
        except Exception as e:
            return {
                "source": "Google Safe Browsing",
                "target": url,
                "status": "UNAVAILABLE",
                "reason": f"Google Safe Browsing connection error: {str(e)}",
                "evidence": None
            }


# ─────────────────────────────────────────────────────────────────────────────
# 4. UNIFIED SECURITY INTELLIGENCE COORDINATOR
# ─────────────────────────────────────────────────────────────────────────────

class SecurityIntelligenceCoordinator:
    """Orchestrates all external intelligence providers, providing unified evidence."""

    def __init__(self):
        self.virustotal = VirusTotalAdapter()
        self.urlscan = UrlscanAdapter()
        self.safe_browsing = GoogleSafeBrowsingAdapter()

    def get_provider_status(self) -> dict:
        """Returns configuration status for all external intelligence providers."""
        return {
            "virustotal": {
                "configured": self.virustotal.is_configured,
                "label": "VirusTotal v3",
                "status": "CONFIGURED" if self.virustotal.is_configured else "KEY_NOT_CONFIGURED"
            },
            "urlscan": {
                "configured": self.urlscan.is_configured,
                "label": "urlscan.io",
                "status": "CONFIGURED" if self.urlscan.is_configured else "KEY_NOT_CONFIGURED"
            },
            "google_safe_browsing": {
                "configured": self.safe_browsing.is_configured,
                "label": "Google Safe Browsing",
                "status": "CONFIGURED" if self.safe_browsing.is_configured else "KEY_NOT_CONFIGURED"
            }
        }

    def collect_intelligence(self, url: str = None, domain: str = None) -> list:
        """Collect and normalize evidence from all available external sources.

        Returns a list of normalized evidence dicts.
        """
        results = []

        if url:
            # VirusTotal URL
            vt_res = self.virustotal.query_url(url)
            results.append(vt_res)

            # Google Safe Browsing
            gsb_res = self.safe_browsing.query_url(url)
            results.append(gsb_res)

            # urlscan.io
            us_res = self.urlscan.query_target(url, is_domain=False)
            results.append(us_res)

        if domain and not url:
            # VirusTotal Domain
            vt_res = self.virustotal.query_domain(domain)
            results.append(vt_res)

            # urlscan.io Domain
            us_res = self.urlscan.query_target(domain, is_domain=True)
            results.append(us_res)

        return results
