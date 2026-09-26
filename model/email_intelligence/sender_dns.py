"""Live DNS evidence about the sender DOMAIN (not the mailbox).

Distinguishes (master prompt §19):
  sender address observed  → from the message (OBSERVED)
  domain exists            → DNS answer now (VERIFIED) or failure (UNAVAILABLE)
  mail infrastructure      → MX records now (VERIFIED)
  specific mailbox exists  → NEVER verified here (NOT_VERIFIED)
"""
import time
from typing import Any, Dict

from .common import VERIFIED, UNAVAILABLE, NOT_APPLICABLE, availability

try:
    import dns.resolver
    import dns.exception
except Exception:  # pragma: no cover
    dns = None

DNS_LIFETIME = 4.0

MAILBOX_NOT_VERIFIED = availability(
    "NOT_VERIFIED", None,
    "Mailbox existence was not verified. DNS/MX records only show that the domain can receive mail; "
    "they do not prove this specific address exists or that its owner sent the message.")


def _resolver():
    r = dns.resolver.Resolver()
    r.lifetime = DNS_LIFETIME
    r.timeout = DNS_LIFETIME / 2
    return r


def _query(res, name: str, rtype: str) -> Dict[str, Any]:
    try:
        ans = res.resolve(name, rtype)
        return {"status": "OK", "records": [a.to_text().strip('"') for a in ans]}
    except dns.resolver.NXDOMAIN:
        return {"status": "NXDOMAIN", "records": []}
    except dns.resolver.NoAnswer:
        return {"status": "NO_ANSWER", "records": []}
    except dns.resolver.NoNameservers as e:
        return {"status": "DNS_FAILURE", "records": [], "error": "No nameserver answered"}
    except dns.exception.Timeout:
        return {"status": "TIMEOUT", "records": []}
    except Exception as e:
        return {"status": "DNS_FAILURE", "records": [], "error": type(e).__name__}


def check_sender_domain(domain: str) -> Dict[str, Any]:
    started = time.time()
    if not domain:
        na = availability(NOT_APPLICABLE, None, "No sender domain observed in the From header")
        return {"domain": None, "domain_exists": na, "mx": na, "spf_record": na, "dmarc_record": na,
                "mailbox": MAILBOX_NOT_VERIFIED, "duration_ms": 0}
    if dns is None:
        ua = availability(UNAVAILABLE, None, "dnspython is not installed")
        return {"domain": domain, "domain_exists": ua, "mx": ua, "spf_record": ua, "dmarc_record": ua,
                "mailbox": MAILBOX_NOT_VERIFIED, "duration_ms": 0}

    res = _resolver()
    a = _query(res, domain, "A")
    failed = a["status"] in ("DNS_FAILURE", "TIMEOUT")

    if a["status"] == "NXDOMAIN":
        exists = availability(VERIFIED, False, "Authoritative DNS answered NXDOMAIN: the domain does not exist", "DNS")
    elif failed:
        exists = availability(UNAVAILABLE, None, f"DNS lookup failed ({a['status']}{': ' + a.get('error') if a.get('error') else ''})", "DNS")
    else:
        exists = availability(VERIFIED, True, "Domain resolves in DNS" if a["records"] else "Domain exists (no A record)", "DNS")

    if failed or a["status"] == "NXDOMAIN":
        why = exists.get("reason")
        skipped = availability(UNAVAILABLE if failed else VERIFIED, None if failed else False, why, "DNS")
        return {"domain": domain, "domain_exists": exists, "a_records": a["records"],
                "mx": skipped, "spf_record": skipped, "dmarc_record": skipped,
                "mailbox": MAILBOX_NOT_VERIFIED, "duration_ms": int((time.time() - started) * 1000)}

    mx = _query(res, domain, "MX")
    if mx["status"] == "OK":
        mx_av = availability(VERIFIED, sorted(mx["records"])[:10], f"{len(mx['records'])} MX record(s)", "DNS")
    elif mx["status"] in ("NO_ANSWER", "NXDOMAIN"):
        mx_av = availability(VERIFIED, [], "No MX records published", "DNS")
    else:
        mx_av = availability(UNAVAILABLE, None, f"MX lookup failed ({mx['status']})", "DNS")

    txt = _query(res, domain, "TXT")
    if txt["status"] == "OK" or txt["status"] == "NO_ANSWER":
        spf = [t for t in txt["records"] if t.lower().replace('" "', "").startswith("v=spf1")]
        spf_av = availability(VERIFIED, spf[0][:400] if spf else None,
                              "SPF record published" if spf else "No SPF record published", "DNS")
    else:
        spf_av = availability(UNAVAILABLE, None, f"TXT lookup failed ({txt['status']})", "DNS")

    dm = _query(res, f"_dmarc.{domain}", "TXT")
    if dm["status"] in ("OK", "NO_ANSWER", "NXDOMAIN"):
        rec = [t for t in dm["records"] if t.lower().startswith("v=dmarc1")]
        policy = None
        if rec:
            for tag in rec[0].split(";"):
                k, _, v = tag.strip().partition("=")
                if k.strip().lower() == "p":
                    policy = v.strip().lower()
        dm_av = availability(VERIFIED, {"record": rec[0][:400], "policy": policy} if rec else None,
                             f"DMARC policy p={policy}" if rec else "No DMARC record published", "DNS")
    else:
        dm_av = availability(UNAVAILABLE, None, f"DMARC lookup failed ({dm['status']})", "DNS")

    return {"domain": domain, "domain_exists": exists, "a_records": a["records"][:10],
            "mx": mx_av, "spf_record": spf_av, "dmarc_record": dm_av,
            "mailbox": MAILBOX_NOT_VERIFIED, "duration_ms": int((time.time() - started) * 1000)}
