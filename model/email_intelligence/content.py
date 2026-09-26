"""Static content analysis: explainable language signals, HTML structure, URLs.

HTML is parsed as text with BeautifulSoup's html.parser. It is never rendered,
and scripts are never executed. A single keyword never decides anything:
signals are grouped into categories and the rules look for combinations."""
import ipaddress
import re
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse, unquote, parse_qs

from .common import registered_domain, truncate

try:
    from bs4 import BeautifulSoup
except Exception:  # pragma: no cover
    BeautifulSoup = None

SIGNAL_CATEGORIES: Dict[str, Dict[str, Any]] = {
    "urgency": {
        "label": "Urgency / time pressure",
        "patterns": [r"\burgent(ly)?\b", r"\bimmediate(ly)?\b", r"\bwithin (24|48|72) hours\b", r"\bact now\b",
                     r"\bas soon as possible\b", r"\bfinal (notice|warning|reminder)\b", r"\bexpires? (today|soon|in \d+)",
                     r"\blimited time\b", r"\blast (chance|warning)\b", r"\bright away\b", r"\btoday only\b"],
    },
    "credential_request": {
        "label": "Credential / secret request",
        "patterns": [r"\b(verify|confirm|enter|update|validate|re-?enter|provide)\s+(your\s+)?(password|passcode|credentials|login details|pin)\b",
                     r"\busername and password\b", r"\b(one[- ]time password|otp|verification code)\b.{0,40}\b(share|send|reply|enter|provide)\b",
                     r"\b(share|send|reply with|provide)\b.{0,40}\b(otp|one[- ]time password|verification code|pin)\b",
                     r"\bsign[ -]?in to (verify|confirm|restore|unlock)\b", r"\blog[ -]?in (to|and) (verify|confirm|restore|unlock)\b"],
    },
    "account_verification": {
        "label": "Account verification / suspension claim",
        "patterns": [r"\bverify your (account|identity|information|details)\b", r"\bconfirm your (account|identity|information|details)\b",
                     r"\baccount (has been|was|will be|is) (suspended|locked|limited|restricted|disabled|deactivated|on hold)\b",
                     r"\bunusual (sign[- ]?in|login|activity)\b", r"\bsuspicious (activity|login|sign[- ]?in)\b",
                     r"\bvalidate your account\b", r"\brestore (your )?(account )?access\b"],
    },
    "payment_request": {
        "label": "Payment / financial request",
        "patterns": [r"\bwire transfer\b", r"\bbank transfer\b", r"\bgift ?cards?\b", r"\b(bitcoin|btc|usdt|crypto(currency)?)\b",
                     r"\bpayment (is )?(overdue|pending|failed|declined)\b", r"\b(outstanding|unpaid|overdue) invoice\b",
                     r"\bupdate (your )?(payment|billing) (method|information|details)\b", r"\bbilling information\b",
                     r"\brefund\b", r"\bchange (of|in) (bank|account) details\b", r"\bnew bank account\b"],
    },
    "threat_language": {
        "label": "Threat / consequence language",
        "patterns": [r"\bwill be (suspended|terminated|closed|deleted|blocked|disabled)\b", r"\blegal action\b", r"\bpenalt(y|ies)\b",
                     r"\barrest\b", r"\bfailure to (comply|respond|verify)\b", r"\bpermanently (deleted|closed|suspended|lost)\b",
                     r"\blaw enforcement\b"],
    },
    "suspicious_instructions": {
        "label": "Suspicious instructions",
        "patterns": [r"\benable (macros?|content|editing)\b", r"\bopen the attach(ed|ment)\b", r"\bdownload the attach(ed|ment)\b",
                     r"\bkeep this (confidential|between us)\b", r"\bdo not (share|tell|discuss) (this|anyone)\b",
                     r"\bdisable (your )?(antivirus|security|firewall)\b", r"\breply with your\b", r"\bclick (the link|here) (below )?to\b"],
    },
    "reward_lure": {
        "label": "Reward / prize lure",
        "patterns": [r"\byou('ve| have) won\b", r"\bclaim your (prize|reward|refund|gift)\b", r"\blottery\b", r"\binheritance\b",
                     r"\bcongratulations\b.{0,60}\b(won|selected|winner)\b"],
    },
    "generic_greeting": {
        "label": "Generic greeting",
        "patterns": [r"\bdear (customer|user|client|valued (customer|member|user)|account holder|member|sir(/| or )madam|beneficiary)\b"],
    },
}

URL_RE = re.compile(r"""(?i)\b((?:https?://|www\.)[^\s<>"'()\[\]{}]+)""")
SHORTENERS = {"bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly", "rebrand.ly", "cutt.ly",
              "shorturl.at", "rb.gy", "tiny.cc", "t.ly", "bl.ink", "s.id", "v.gd", "shorte.st", "lnkd.in"}
_DOMAINISH = re.compile(r"^(?:https?://)?(?:www\.)?([a-z0-9-]+(?:\.[a-z0-9-]+)+)(?:[/:?#].*)?$", re.I)


def visible_text_from_html(html: str) -> str:
    if not html:
        return ""
    if BeautifulSoup is None:
        return re.sub(r"<[^>]+>", " ", html)
    soup = BeautifulSoup(html, "html.parser")
    for t in soup(["script", "style", "head", "noscript"]):
        t.decompose()
    return " ".join(soup.get_text(" ").split())


def analyze_language(text: str) -> Dict[str, Any]:
    text_norm = " ".join((text or "").split())
    lower = text_norm.lower()
    categories = []
    for key, cfg in SIGNAL_CATEGORIES.items():
        hits = []
        for p in cfg["patterns"]:
            for m in re.finditer(p, lower, re.I):
                s, e = max(0, m.start() - 60), min(len(text_norm), m.end() + 60)
                hits.append({"phrase": text_norm[m.start():m.end()], "context": truncate(text_norm[s:e], 180)})
                if len(hits) >= 5:
                    break
            if len(hits) >= 5:
                break
        if hits:
            categories.append({"category": key, "label": cfg["label"], "match_count": len(hits), "matches": hits})
    return {
        "text_length": len(text_norm),
        "word_count": len(text_norm.split()),
        "categories": categories,
        "category_keys": [c["category"] for c in categories],
        "note": "Language signals are phrase matches grouped by category. No single phrase determines the verdict.",
    }


def _is_ip_host(host: str) -> bool:
    try:
        ipaddress.ip_address(host.strip("[]"))
        return True
    except Exception:
        return False


# Known corporate product and service affiliations (not deceptive mismatches)
DOMAIN_AFFILIATIONS = {
    'gmail.com': {'google.com', 'gmail.com', 'googleusercontent.com', 'gstatic.com', 'youtube.com'},
    'google.com': {'gmail.com', 'google.com', 'googleusercontent.com', 'gstatic.com', 'youtube.com'},
    'youtube.com': {'google.com', 'youtube.com', 'youtu.be'},
    'outlook.com': {'microsoft.com', 'live.com', 'office.com', 'outlook.com', 'msn.com', 'office365.com'},
    'office.com': {'microsoft.com', 'live.com', 'office.com', 'outlook.com', 'office365.com'},
    'live.com': {'microsoft.com', 'live.com', 'office.com', 'outlook.com'},
    'microsoft.com': {'microsoft.com', 'live.com', 'office.com', 'outlook.com', 'office365.com'},
    'apple.com': {'apple.com', 'icloud.com'},
    'icloud.com': {'apple.com', 'icloud.com'}
}


def _norm_url(u: str) -> Optional[str]:
    u = u.strip().rstrip(".,;:!?)'\"")
    if not u:
        return None
    # Unwrap Google redirect if present (e.g. from Gmail DOM / email)
    if "google.com/url?" in u.lower() or ("google.co" in u.lower() and "/url?" in u.lower()):
        try:
            pq = parse_qs(urlparse(u).query)
            q_val = pq.get('q') or pq.get('url')
            if q_val and q_val[0]:
                u = unquote(q_val[0]).strip().rstrip(".,;:!?)'\"")
        except Exception:
            pass

    if u.lower().startswith("www."):
        u = "https://" + u
    elif not re.match(r"(?i)^[a-z][a-z0-9+.-]*://", u):
        u = "https://" + u
    if not re.match(r"(?i)^https?://", u):
        return None
    return u[:2048]


def _anchor_domain(text: str) -> Optional[str]:
    t = (text or "").strip()
    if not t or " " in t or len(t) > 200:
        return None
    m = _DOMAINISH.match(t)
    if not m:
        return None
    host = m.group(1).lower()
    if "." not in host or host.endswith((".png", ".jpg", ".gif", ".pdf")):
        return None
    return host


def analyze_html(html: str) -> Dict[str, Any]:
    if not html:
        return {"present": False}
    if BeautifulSoup is None:
        return {"present": True, "analysed": False, "reason": "beautifulsoup4 not installed"}
    soup = BeautifulSoup(html, "html.parser")
    forms = []
    for f in soup.find_all("form"):
        forms.append({"action": truncate(f.get("action") or "", 300), "method": (f.get("method") or "GET").upper(),
                      "has_password": bool(f.find("input", attrs={"type": re.compile("password", re.I)}))})
    pw_inputs = soup.find_all("input", attrs={"type": re.compile("password", re.I)})
    scripts = soup.find_all("script")
    iframes = soup.find_all(["iframe", "frame", "object", "embed"])
    meta_refresh = [m.get("content", "") for m in soup.find_all("meta", attrs={"http-equiv": re.compile("refresh", re.I)})]
    remote_imgs = [i.get("src") for i in soup.find_all("img") if (i.get("src") or "").lower().startswith(("http://", "https://"))]
    tracking_pixels = [i.get("src") for i in soup.find_all("img")
                       if (i.get("width") in ("1", "0") and i.get("height") in ("1", "0"))]
    hidden = []
    for el in soup.find_all(style=re.compile(r"display\s*:\s*none|visibility\s*:\s*hidden|font-size\s*:\s*0", re.I)):
        txt = " ".join(el.get_text(" ").split())
        if len(txt) >= 20:
            hidden.append(truncate(txt, 160))
    event_handlers = sum(1 for el in soup.find_all(True) for a in el.attrs if str(a).lower().startswith("on"))
    return {
        "present": True, "analysed": True,
        "forms": forms, "form_count": len(forms), "password_inputs": len(pw_inputs),
        "script_count": len(scripts), "iframe_like_count": len(iframes), "event_handler_attributes": event_handlers,
        "meta_refresh": meta_refresh[:3], "remote_image_count": len(remote_imgs),
        "tracking_pixel_count": len(tracking_pixels), "hidden_text_blocks": hidden[:5],
        "note": "Static inspection only. Email HTML was not rendered and scripts were not executed.",
    }


def extract_urls(text: str, html: str, from_domain: str) -> Dict[str, Any]:
    found: Dict[str, Dict[str, Any]] = {}

    def add(u: str, where: str, anchor_text: Optional[str] = None):
        nu = _norm_url(u)
        if not nu:
            return
        parsed = urlparse(nu)
        host = (parsed.hostname or "").lower()
        if not host:
            return
        entry = found.setdefault(nu, {"url": nu, "host": host, "registered_domain": registered_domain(host),
                                      "scheme": parsed.scheme.lower(), "locations": [], "anchor_texts": []})
        if where not in entry["locations"]:
            entry["locations"].append(where)
        if anchor_text and len(entry["anchor_texts"]) < 3:
            entry["anchor_texts"].append(truncate(" ".join(anchor_text.split()), 160))

    for m in URL_RE.finditer(text or ""):
        add(m.group(1), "text body")

    mismatches = []
    if html and BeautifulSoup is not None:
        soup = BeautifulSoup(html, "html.parser")
        for a in soup.find_all("a", href=True):
            raw_href = a["href"].strip()
            # Unwrap Google redirect if present
            if "google.com/url?" in raw_href.lower() or ("google.co" in raw_href.lower() and "/url?" in raw_href.lower()):
                try:
                    pq = parse_qs(urlparse(raw_href).query)
                    q_val = pq.get('q') or pq.get('url')
                    if q_val and q_val[0]:
                        raw_href = unquote(q_val[0]).strip()
                except Exception:
                    pass
            href = unquote(raw_href)
            txt = a.get_text(" ").strip()
            add(href, "html link", txt)
            shown = _anchor_domain(txt)
            nu = _norm_url(href)
            if shown and nu:
                actual = (urlparse(nu).hostname or "").lower()
                reg_shown = registered_domain(shown)
                reg_actual = registered_domain(actual)
                is_affiliated = (
                    reg_shown == reg_actual or
                    reg_actual in DOMAIN_AFFILIATIONS.get(reg_shown, set()) or
                    reg_shown in DOMAIN_AFFILIATIONS.get(reg_actual, set())
                )
                if actual and not is_affiliated:
                    mismatches.append({"displayed": truncate(txt, 160), "displayed_domain": reg_shown,
                                       "actual_url": nu, "actual_domain": reg_actual})
        for f in soup.find_all("form", action=True):
            add(f["action"], "html form action")
        for tag, attr in (("img", "src"), ("iframe", "src"), ("script", "src"), ("link", "href")):
            for el in soup.find_all(tag):
                if el.get(attr):
                    add(el[attr], f"html {tag} src")
        for m in URL_RE.finditer(visible_text_from_html(html)):
            add(m.group(1), "html visible text")

    urls = list(found.values())
    fr = registered_domain(from_domain) if from_domain else ""
    for u in urls:
        u["ip_host"] = _is_ip_host(u["host"])
        u["shortener"] = u["host"] in SHORTENERS or u["registered_domain"] in SHORTENERS
        u["punycode"] = "xn--" in u["host"]
        u["uses_https"] = u["scheme"] == "https"
        u["same_domain_as_sender"] = bool(fr) and u["registered_domain"] == fr
        u["resource_only"] = all(l.startswith("html img") or l.startswith("html link") for l in u["locations"])
    domains = sorted({u["registered_domain"] for u in urls if u["registered_domain"]})
    external = sorted({u["registered_domain"] for u in urls if u["registered_domain"] and u["registered_domain"] != fr})
    return {"urls": urls, "url_count": len(urls), "clickable_count": sum(1 for u in urls if not u["resource_only"]),
            "domains": domains, "domain_count": len(domains), "external_domains": external,
            "anchor_mismatches": mismatches}
