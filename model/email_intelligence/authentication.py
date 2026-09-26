"""Authentication evidence (SPF / DKIM / DMARC) as REPORTED in the message.

Important limits (surfaced in the UI and report):
- Authentication-Results are written by a receiving mail server. NeuraShield
  reads them; it does not re-run SPF/DKIM/DMARC for this message.
- A header can be forged by anyone upstream of the receiving server, so the
  authserv-id is shown so the user can judge whether it is their own provider.
- Failure is evidence, not proof of phishing. Pass is not proof of safety.
"""
import re
from typing import Any, Dict, List, Optional

from .common import OBSERVED, UNAVAILABLE, registered_domain

KNOWN_RESULTS = {"pass", "fail", "softfail", "neutral", "none", "temperror", "permerror", "policy", "bestguesspass"}


def _find(pattern: str, text: str) -> Optional[str]:
    m = re.search(pattern, text, re.I)
    return m.group(1).strip().strip('"').lower() if m else None


def _parse_ar(header: str) -> Dict[str, Any]:
    text = " ".join(header.split())
    authserv = text.split(";", 1)[0].strip() if ";" in text else None
    res = {"authserv_id": authserv, "raw": text[:1500]}
    for mech in ("spf", "dkim", "dmarc"):
        # take the first occurrence of each mechanism
        m = re.search(rf"\b{mech}\s*=\s*([a-z]+)([^;]*)", text, re.I)
        if not m:
            continue
        result = m.group(1).lower()
        tail = m.group(2)
        entry = {"result": result if result in KNOWN_RESULTS else result, "detail": tail.strip()[:300]}
        if mech == "spf":
            entry["domain"] = _find(r"smtp\.mailfrom\s*=\s*([^\s;]+)", tail) or _find(r"smtp\.helo\s*=\s*([^\s;]+)", tail)
            if entry["domain"] and "@" in entry["domain"]:
                entry["domain"] = entry["domain"].split("@", 1)[1]
        elif mech == "dkim":
            entry["domain"] = _find(r"header\.d\s*=\s*([^\s;]+)", tail) or _find(r"header\.i\s*=\s*@?([^\s;]+)", tail)
            if entry["domain"] and "@" in entry["domain"]:
                entry["domain"] = entry["domain"].split("@", 1)[1]
        elif mech == "dmarc":
            entry["domain"] = _find(r"header\.from\s*=\s*([^\s;]+)", tail)
            entry["policy"] = _find(r"\bp\s*=\s*([a-z]+)", tail) or _find(r"policy\.dmarc\s*=\s*([a-z]+)", tail)
        res[mech] = entry
    return res


def analyze_authentication(parsed: Dict[str, Any], from_domain: str) -> Dict[str, Any]:
    ar_headers: List[str] = parsed.get("authentication_results") or []
    rspf: List[str] = parsed.get("received_spf") or []
    dkim_sigs = parsed.get("dkim_signatures") or []

    results = [_parse_ar(h) for h in ar_headers]
    # The top-most Authentication-Results header is the one added last (closest to the recipient).
    primary = results[0] if results else {}

    out: Dict[str, Any] = {
        "authentication_results_present": bool(results),
        "authserv_id": primary.get("authserv_id"),
        "header_count": len(results),
        "arc_present": parsed.get("arc_present", False),
        "dkim_signatures_observed": dkim_sigs,
        "independently_reverified": False,
        "note": ("Results are read from the Authentication-Results header written by the receiving mail server "
                 "(authserv-id shown). NeuraShield did not re-run SPF/DKIM/DMARC for this message."),
    }

    for mech in ("spf", "dkim", "dmarc"):
        if primary.get(mech):
            e = dict(primary[mech])
            e["state"] = OBSERVED
            e["source"] = "Authentication-Results"
            out[mech] = e
        elif mech == "spf" and rspf:
            first = " ".join(rspf[0].split())
            result = first.split()[0].lower() if first else None
            out[mech] = {"result": result, "state": OBSERVED, "source": "Received-SPF",
                         "detail": first[:300], "domain": None}
        else:
            reason = ("Authentication-Results header absent" if not results
                      else f"No {mech.upper()} result in Authentication-Results")
            if mech == "dkim" and dkim_sigs:
                reason += f"; a DKIM-Signature (d={dkim_sigs[0].get('d')}) is present but its verification result was not reported"
            out[mech] = {"result": None, "state": UNAVAILABLE, "reason": reason}

    # Alignment with the visible From domain (relaxed: registered-domain match)
    fd = registered_domain(from_domain)
    align = {}
    for mech in ("spf", "dkim"):
        d = out[mech].get("domain")
        if out[mech].get("result") and d and fd:
            align[mech] = registered_domain(d) == fd
        else:
            align[mech] = None
    out["alignment"] = align
    return out
