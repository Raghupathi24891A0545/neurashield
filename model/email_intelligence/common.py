"""Shared helpers for Email Intelligence: availability states, domain helpers."""
import re
from typing import Optional

# Data-availability vocabulary (master prompt §3)
OBSERVED = "OBSERVED"            # present in the message itself, not independently checked
VERIFIED = "VERIFIED"            # independently confirmed by a live check performed now
INFERRED = "INFERRED"            # derived by NeuraShield from other evidence
UNAVAILABLE = "UNAVAILABLE"      # we tried / it should exist, but it could not be obtained
NOT_APPLICABLE = "NOT_APPLICABLE"
NOT_CHECKED = "NOT_CHECKED"      # deliberately not performed (disabled / out of scope)

try:
    import tldextract
    # Offline extractor: never download the public-suffix list at request time.
    _TLD = tldextract.TLDExtract(suffix_list_urls=())
except Exception:  # pragma: no cover
    _TLD = None


def availability(state: str, value=None, reason: Optional[str] = None, source: Optional[str] = None) -> dict:
    d = {"state": state, "value": value}
    if reason:
        d["reason"] = reason
    if source:
        d["source"] = source
    return d


def registered_domain(host: Optional[str]) -> str:
    """eTLD+1 for a hostname or e-mail domain ('mail.paypal.co.uk' -> 'paypal.co.uk')."""
    if not host:
        return ""
    host = host.strip().strip(".").lower()
    host = host.split("@")[-1]
    host = re.sub(r":\d+$", "", host)
    if host.startswith("[") or re.fullmatch(r"[\d.]+", host):
        return host.strip("[]")
    if _TLD is not None:
        ext = _TLD(host)
        if ext.domain and ext.suffix:
            return f"{ext.domain}.{ext.suffix}"
        if ext.domain:
            return ext.domain
    parts = host.split(".")
    return ".".join(parts[-2:]) if len(parts) >= 2 else host


def domain_of(address: Optional[str]) -> str:
    if not address or "@" not in address:
        return ""
    return address.rsplit("@", 1)[1].strip().strip(">").lower()


def truncate(text: Optional[str], limit: int) -> str:
    if text is None:
        return ""
    text = str(text)
    return text if len(text) <= limit else text[: limit - 1] + "…"
