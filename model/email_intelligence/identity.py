"""Sender identity consistency: display name, From, Reply-To, Return-Path,
Sender, Message-ID, DKIM d=, Received routing.

The From header is a CLAIM made by whoever composed the message. Nothing here
proves who sent it; it detects inconsistencies between claims and evidence."""
import re
from typing import Any, Dict, List, Optional

from .common import registered_domain, domain_of

# Brand → official registered domains. Used only to flag inconsistency between a
# brand claimed in the display name and the actual sending domain.
BRANDS: Dict[str, List[str]] = {
    "paypal": ["paypal.com", "paypal.me", "paypal-communication.com"],
    "microsoft": ["microsoft.com", "microsoftonline.com", "office.com", "office365.com", "outlook.com", "live.com", "hotmail.com", "microsoft365.com", "sharepoint.com", "onmicrosoft.com"],
    "office 365": ["microsoft.com", "office.com", "office365.com", "microsoftonline.com", "onmicrosoft.com"],
    "outlook": ["outlook.com", "microsoft.com", "live.com", "hotmail.com"],
    "apple": ["apple.com", "icloud.com", "me.com"],
    "icloud": ["icloud.com", "apple.com"],
    "google": ["google.com", "gmail.com", "googlemail.com", "youtube.com", "accounts.google.com"],
    "gmail": ["gmail.com", "google.com", "googlemail.com"],
    "amazon": ["amazon.com", "amazon.in", "amazon.co.uk", "amazon.de", "amazonses.com", "amazon.ca", "amazon.com.au", "aws.com"],
    "netflix": ["netflix.com"],
    "facebook": ["facebook.com", "facebookmail.com", "meta.com", "fb.com"],
    "meta": ["meta.com", "facebook.com", "facebookmail.com"],
    "instagram": ["instagram.com", "facebookmail.com", "mail.instagram.com"],
    "whatsapp": ["whatsapp.com", "facebookmail.com"],
    "linkedin": ["linkedin.com"],
    "dhl": ["dhl.com", "dhl.de", "dhl.co.in"],
    "fedex": ["fedex.com"],
    "ups": ["ups.com"],
    "dropbox": ["dropbox.com", "dropboxmail.com"],
    "docusign": ["docusign.com", "docusign.net"],
    "adobe": ["adobe.com"],
    "wells fargo": ["wellsfargo.com"],
    "chase": ["chase.com", "jpmorgan.com"],
    "bank of america": ["bankofamerica.com", "bofa.com"],
    "hdfc": ["hdfcbank.com", "hdfcbank.net"],
    "icici": ["icicibank.com"],
    "sbi": ["sbi.co.in", "onlinesbi.sbi", "sbi.bank.in"],
    "axis bank": ["axisbank.com"],
    "irs": ["irs.gov"],
    "income tax": ["incometax.gov.in", "incometaxindia.gov.in"],
    "coinbase": ["coinbase.com"],
    "binance": ["binance.com"],
    "steam": ["steampowered.com", "steamcommunity.com"],
    "zoom": ["zoom.us", "zoom.com"],
    "twitter": ["twitter.com", "x.com"],
    "flipkart": ["flipkart.com"],
    "paytm": ["paytm.com"],
}
# Tokens too generic to treat as a brand claim on their own.
_SECURITY_WORDS = re.compile(r"\b(security|support|service|team|account|billing|helpdesk|help desk|admin|administrator|it department|verification|alert|notification)s?\b", re.I)
_EMAIL_IN_NAME = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")


def _brand_claims(display_name: str) -> List[str]:
    dn = (display_name or "").lower()
    found = []
    for brand in BRANDS:
        if re.search(rf"(?<![a-z0-9]){re.escape(brand)}(?![a-z0-9])", dn):
            found.append(brand)
    # prefer the longer, more specific token ("office 365" over "office")
    return sorted(set(found), key=len, reverse=True)


def _msgid_domain(message_id: Optional[str]) -> str:
    if not message_id:
        return ""
    m = re.search(r"@([^>\s]+)", message_id)
    return m.group(1).lower() if m else ""


def analyze_identity(parsed: Dict[str, Any], auth: Dict[str, Any]) -> Dict[str, Any]:
    frm = (parsed.get("from") or [])
    primary = frm[0] if frm else None
    from_addr = primary["address"] if primary else ""
    from_domain = primary["domain"] if primary else ""
    display = primary["display_name"] if primary else ""
    from_reg = registered_domain(from_domain)

    reply_to = parsed.get("reply_to") or []
    rp = parsed.get("return_path")
    sender = parsed.get("sender") or []
    msgid_dom = _msgid_domain(parsed.get("message_id"))
    dkim_d = [s.get("d") for s in (parsed.get("dkim_signatures") or []) if s.get("d")]

    comparisons = []

    def compare(label, value, dom):
        if value is None:
            comparisons.append({"field": label, "value": None, "domain": None, "relation": "NOT_PRESENT"})
            return
        rel = "SAME_ORGANISATIONAL_DOMAIN" if (dom and from_reg and registered_domain(dom) == from_reg) else (
            "DIFFERENT_DOMAIN" if dom and from_reg else "UNDETERMINED")
        comparisons.append({"field": label, "value": value, "domain": dom or None, "relation": rel})

    for r in reply_to:
        compare("Reply-To", r["address"], r["domain"])
    if not reply_to:
        compare("Reply-To", None, None)
    if rp is not None:
        compare("Return-Path", rp.get("address") or "<> (null sender)", rp.get("domain"))
    else:
        compare("Return-Path", None, None)
    for s in sender:
        compare("Sender", s["address"], s["domain"])
    compare("Message-ID domain", msgid_dom or None, msgid_dom)
    for d in dkim_d:
        compare("DKIM-Signature d=", d, d)
    for mech in ("spf", "dkim", "dmarc"):
        dom = (auth.get(mech) or {}).get("domain")
        if dom:
            compare(f"{mech.upper()} evaluated domain", dom, dom)

    brand_claims = _brand_claims(display)
    brand_consistency = []
    for b in brand_claims:
        official = BRANDS[b]
        ok = from_reg in official
        brand_consistency.append({"brand": b, "official_domains": official, "from_domain": from_reg or None,
                                  "state": "CONSISTENT" if ok else ("INCONSISTENT" if from_reg else "INSUFFICIENT_EVIDENCE")})

    embedded = _EMAIL_IN_NAME.findall(display or "")
    embedded_mismatch = [e for e in embedded if e.lower() != from_addr]

    hops = parsed.get("received") or []
    origin = None
    for h in reversed(hops):  # oldest hop last in list
        if h.get("from_ip") or h.get("from_host"):
            origin = {"from_host": h.get("from_host"), "from_ip": h.get("from_ip")}
            break

    return {
        "claimed_sender": {
            "display_name": display or None,
            "address": from_addr or None,
            "domain": from_domain or None,
            "registered_domain": from_reg or None,
            "multiple_from": len(frm) > 1,
            "note": "The From header is a claim written by the sender; it is not proof of identity.",
        },
        "comparisons": comparisons,
        "brand_claims": brand_consistency,
        "display_name_security_words": bool(_SECURITY_WORDS.search(display or "")),
        "display_name_embedded_addresses": embedded,
        "display_name_embedded_mismatch": embedded_mismatch,
        "earliest_observed_hop": origin,
        "received_hop_count": len(hops),
        "routing_note": ("Received headers are listed newest-first. Only headers added by servers you trust "
                         "(your own provider) are reliable; earlier hops can be written by the sender."),
    }
