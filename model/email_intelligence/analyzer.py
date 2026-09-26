"""MODULE 4 pipeline: parse → headers → authentication → sender DNS → content →
URLs (→ Module 1 / Module 2 / optional Module 3) → attachments → rules + ML →
risk fusion → Threat DNA → relationship graph → explainability payload.

External modules are injected as callables (`services`) so this package has no
dependency on the Flask app and can be tested offline."""
import hashlib
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from typing import Any, Callable, Dict, List, Optional

from . import MODULE_VERSION
from .common import (OBSERVED, VERIFIED, INFERRED, UNAVAILABLE, NOT_APPLICABLE, NOT_CHECKED,
                     availability, registered_domain, truncate)
from .parser import parse_email, EmailParseError
from .authentication import analyze_authentication
from .identity import analyze_identity
from .sender_dns import check_sender_domain
from .content import analyze_language, analyze_html, extract_urls, visible_text_from_html
from .attachments import analyze_attachments
from .rules import evaluate_email_rules, SEVERITY_ORDER
from . import ml as email_ml

MAX_URLS_ANALYSED = 15
MAX_LINK_DOMAINS = 5
MAX_WEBPAGES = 3
ML_WEIGHT = 0.25   # share of final risk taken from the text model, when a validated model exists
PORTAL_URL = "https://cybercrime.gov.in"


class StageClock:
    """Records the stages that actually ran, with real timings."""
    def __init__(self):
        self.stages: List[Dict[str, Any]] = []

    def run(self, key: str, name: str, fn: Callable, *a, **kw):
        t0 = time.time()
        started = datetime.now(timezone.utc).isoformat()
        try:
            result = fn(*a, **kw)
            self.stages.append({"key": key, "name": name, "status": "COMPLETED", "started_at": started,
                                "duration_ms": int((time.time() - t0) * 1000)})
            return result
        except Exception as e:
            self.stages.append({"key": key, "name": name, "status": "FAILED", "started_at": started,
                                "duration_ms": int((time.time() - t0) * 1000), "detail": type(e).__name__})
            raise

    def skip(self, key: str, name: str, state: str, reason: str):
        self.stages.append({"key": key, "name": name, "status": state, "detail": reason,
                            "started_at": datetime.now(timezone.utc).isoformat(), "duration_ms": 0})


def _combine(contribs: List[float]) -> int:
    """Probabilistic OR: one strong signal matters; many weak ones do not simply add up."""
    p = 1.0
    for c in contribs:
        p *= (1 - max(0.0, min(100.0, c)) / 100.0)
    return int(round(100 * (1 - p)))


def _risk_level(score: int) -> str:
    return "CRITICAL" if score >= 80 else "HIGH" if score >= 60 else "MEDIUM" if score >= 40 else "LOW" if score >= 20 else "MINIMAL"


def _verdict(score: int) -> Dict[str, str]:
    if score >= 70:
        return {"verdict": "HIGH_RISK", "label": "High risk based on observed evidence"}
    if score >= 40:
        return {"verdict": "SUSPICIOUS", "label": "Suspicious — treat with caution"}
    if score >= 20:
        return {"verdict": "LOW_RISK", "label": "Low risk — minor observations"}
    return {"verdict": "NO_SIGNIFICANT_INDICATORS", "label": "No significant risk indicators observed"}


def run_email_investigation(raw: bytes, filename: Optional[str] = None, options: Optional[Dict[str, Any]] = None,
                            services: Optional[Dict[str, Callable]] = None, investigation_id: Optional[str] = None) -> Dict[str, Any]:
    options = options or {}
    services = services or {}
    clock = StageClock()
    t_start = datetime.now(timezone.utc)

    parsed = clock.run("parse", "Email parsing", parse_email, raw, filename)   # raises EmailParseError
    body_only = parsed["input_mode"] == "BODY_ONLY"

    # ── headers / identity / authentication ──
    frm = parsed.get("from") or []
    from_domain = frm[0]["domain"] if frm else ""
    if body_only:
        clock.skip("headers", "Header analysis", "UNAVAILABLE", "Only message body text was supplied")
        auth = analyze_authentication(parsed, from_domain)
        identity = analyze_identity(parsed, auth)
        clock.skip("auth", "Authentication analysis", "UNAVAILABLE", "No headers supplied")
    else:
        auth = clock.run("auth", "Authentication analysis", analyze_authentication, parsed, from_domain)
        identity = clock.run("headers", "Header & sender-consistency analysis", analyze_identity, parsed, auth)

    if from_domain and options.get("live_dns", True):
        sender_dns = clock.run("sender_dns", "Sender domain DNS check", check_sender_domain, from_domain)
    else:
        sender_dns = check_sender_domain("") if not from_domain else None
        clock.skip("sender_dns", "Sender domain DNS check", NOT_APPLICABLE if not from_domain else NOT_CHECKED,
                   "No sender domain observed" if not from_domain else "Live DNS disabled for this run")

    # ── content ──
    text_body = parsed.get("text_body") or ""
    html_body = parsed.get("html_body") or ""
    analysable_text = text_body if text_body.strip() else visible_text_from_html(html_body)
    language = clock.run("content", "Content analysis", analyze_language, f"{parsed.get('subject') or ''}\n{analysable_text}")
    html = analyze_html(html_body) if html_body else {"present": False}

    urls = clock.run("urls", "URL extraction", extract_urls, text_body, html_body, from_domain)

    # ── Module 1 on each link ──
    url_results: List[Dict[str, Any]] = []
    candidates = [u for u in urls["urls"] if not u["resource_only"]][:MAX_URLS_ANALYSED]
    if candidates and services.get("url_analyzer"):
        def _m1():
            for u in candidates:
                try:
                    r = services["url_analyzer"](u["url"])
                    r["url"] = u["url"]
                    url_results.append(r)
                except Exception as e:
                    url_results.append({"url": u["url"], "status": "ANALYSIS_UNAVAILABLE", "reason": type(e).__name__})
        clock.run("url_intel", "URL Intelligence on extracted links", _m1)
    elif candidates:
        clock.skip("url_intel", "URL Intelligence on extracted links", UNAVAILABLE, "URL Intelligence service not connected")

    # ── Module 2 on link domains + sender domain ──
    domain_results: List[Dict[str, Any]] = []
    link_domains = []
    for u in candidates:
        d = u["registered_domain"]
        if d and d not in link_domains and not u["ip_host"]:
            link_domains.append(d)
    from_reg = registered_domain(from_domain)
    dom_targets = ([from_reg] if from_reg else []) + [d for d in link_domains if d != from_reg]
    dom_targets = dom_targets[:MAX_LINK_DOMAINS]
    if dom_targets and services.get("domain_analyzer") and options.get("domain_intel", True):
        def _one_domain(d):
            try:
                r = services["domain_analyzer"](d)
            except Exception as e:
                r = {"status": "ANALYSIS_UNAVAILABLE", "reason": type(e).__name__}
            r["domain"] = d
            r["role"] = "sender domain" if d == from_reg else "link domain"
            return r

        def _m2():
            # bounded concurrency: live DNS/RDAP/TLS collection per domain
            with ThreadPoolExecutor(max_workers=min(4, len(dom_targets))) as pool:
                domain_results.extend(pool.map(_one_domain, dom_targets))
        clock.run("domain_intel", "Domain Intelligence on sender/link domains", _m2)
    elif dom_targets:
        clock.skip("domain_intel", "Domain Intelligence on sender/link domains", NOT_CHECKED,
                   "Domain Intelligence disabled for this run" if not options.get("domain_intel", True) else "Service not connected")

    # ── Module 3 (opt-in) ──
    webpage_results: List[Dict[str, Any]] = []
    if options.get("fetch_linked_pages") and candidates and services.get("webpage_analyzer"):
        def _one_page(u):
            try:
                r = services["webpage_analyzer"](u["url"])
            except Exception as e:
                r = {"webpage_status": "UNAVAILABLE", "reason": type(e).__name__}
            r["url"] = u["url"]
            return r

        def _m3():
            with ThreadPoolExecutor(max_workers=MAX_WEBPAGES) as pool:
                webpage_results.extend(pool.map(_one_page, candidates[:MAX_WEBPAGES]))
        clock.run("webpage_intel", "Webpage Intelligence on linked pages (opt-in)", _m3)
    elif candidates:
        clock.skip("webpage_intel", "Webpage Intelligence on linked pages", NOT_CHECKED,
                   "Linked pages were not retrieved (opt-in). Visiting a tracked link can confirm to the sender that the e-mail was opened.")

    attachments = clock.run("attachments", "Attachment static analysis", analyze_attachments, parsed.get("attachments_raw") or [])

    rules = clock.run("rules", "Security rules", evaluate_email_rules, parsed, identity, auth, sender_dns or {}, language,
                      html, urls, url_results, attachments)

    ml_result = clock.run("ml", "Email text model", email_ml.predict, parsed.get("subject") or "", analysable_text)

    # ── fusion ──
    fusion = clock.run("fusion", "Risk fusion", _fuse, rules, ml_result, url_results)

    coverage = _coverage(parsed, auth, sender_dns, analysable_text, html, candidates, url_results, dom_targets,
                         domain_results, attachments, ml_result, options, webpage_results)
    confidence = _confidence(coverage, body_only, auth, fusion["risk_score"])

    inv_id = investigation_id or ("NS-EML-" + datetime.now().strftime("%Y") + "-" +
                                  hashlib.sha256(f"{parsed['sha256']}|{t_start.isoformat()}".encode()).hexdigest()[:8].upper())

    dna = _threat_dna(parsed, identity, auth, urls, attachments, language, rules)
    graph = _graph(parsed, identity, urls, attachments, domain_results, dna, url_results)
    timeline = _timeline(parsed, clock.stages, t_start)
    verdict = _verdict(fusion["risk_score"])

    email_layer = {
        "input_mode": parsed["input_mode"],
        "message": {
            "subject": parsed.get("subject"), "date": parsed.get("date"), "date_raw": parsed.get("date_raw"),
            "message_id": parsed.get("message_id"), "size_bytes": parsed["size_bytes"], "sha256": parsed["sha256"],
            "filename": parsed.get("filename"), "x_mailer": parsed.get("x_mailer"),
            "list_unsubscribe_present": bool(parsed.get("list_unsubscribe")),
            "parser_defects": parsed.get("defects", []),
        },
        "recipients": {"to": parsed.get("to"), "cc": parsed.get("cc"),
                       "bcc": parsed.get("bcc") if parsed.get("bcc") else None,
                       "bcc_note": None if parsed.get("bcc") else "Bcc is normally removed before delivery, so it is usually not observable."},
        "identity": identity,
        "authentication": auth,
        "sender_dns": sender_dns,
        "received_chain": parsed.get("received"),
        "mime": parsed.get("mime"),
        "headers": parsed.get("header_list"),
        "content": {"language": language, "html": html,
                    "text_excerpt": truncate(" ".join(analysable_text.split()), 1500),
                    "has_text_part": bool(text_body.strip()), "has_html_part": bool(html_body.strip())},
        "urls": urls,
        "attachments": attachments,
    }

    findings = _plain_findings(rules, auth, identity, sender_dns, urls, attachments, body_only)
    could_not = _could_not_verify(coverage, auth, body_only, options, candidates)
    recs = _recommendations(fusion["risk_score"], rules, language, attachments, urls)
    key_findings = [r for r in rules if r["severity"] != "INFORMATIONAL"][:6]

    explanation = _explanation(fusion, rules, coverage, verdict, body_only)
    status = "PARTIAL" if coverage["percent"] < 60 else "COMPLETE"

    return {
        "investigation_id": inv_id,
        "investigation_type": "email",
        "schema_version": "ns-investigation-1",
        "module_version": MODULE_VERSION,
        "timestamp": t_start.isoformat(),
        "completed_at": datetime.now(timezone.utc).isoformat(),
        "status": status,
        "target": {
            "type": "email",
            "display": parsed.get("subject") or "(no subject)",
            "input": parsed.get("filename") or ("pasted e-mail source" if not body_only else "pasted e-mail text"),
            "normalized": f"sha256:{parsed['sha256']}",
            "claimed_sender": (identity.get("claimed_sender") or {}).get("address"),
            "input_mode": parsed["input_mode"],
        },
        "summary": {
            "verdict": verdict["verdict"], "verdict_label": verdict["label"],
            "risk_score": fusion["risk_score"], "risk_level": _risk_level(fusion["risk_score"]),
            "ml_probability": ml_result.get("probability"), "ml_status": ml_result.get("status"),
            "ml_reason": ml_result.get("reason"),
            "confidence": confidence["percent"], "evidence_coverage": coverage["percent"],
            "explanation": explanation,
        },
        "brief": {
            "investigated": ("An e-mail message supplied as " + ("raw source with headers" if not body_only else "body text only (no headers)")
                             + f" — {len(candidates)} link(s), {attachments['count']} attachment(s)."),
            "observed": [f["text"] for f in findings[:4]],
            "limitations": [c["text"] for c in could_not[:4]],
        },
        "key_findings": key_findings,
        "rules": rules,
        "layers": {
            "email": email_layer,
            "url": url_results,
            "domain": domain_results,
            "webpage": webpage_results,
        },
        "ml": ml_result,
        "risk_fusion": fusion,
        "confidence_detail": confidence,
        "coverage": coverage,
        "threat_dna": dna,
        "graph": graph,
        "timeline": timeline,
        "stages": clock.stages,
        "findings": findings,
        "could_not_verify": could_not,
        "recommendations": recs,
        "interaction_guidance": _interaction_guidance(),
        "final_assessment": _final_assessment(fusion["risk_score"], verdict, key_findings, coverage),
        "evidence_package": _evidence_package(inv_id, t_start, parsed, identity, dna, fusion, rules, urls, attachments, verdict),
    }


def _fuse(rules, ml_result, url_results):
    layers = {}
    for r in rules:
        layers.setdefault(r["layer"], []).append(r)
    layer_rows = []
    for name in ("identity", "authentication", "content", "links", "attachments", "html"):
        rs = layers.get(name, [])
        contribs = [r["risk_contribution"] for r in rs if r["risk_contribution"] > 0]
        layer_rows.append({"layer": name, "score": _combine(contribs), "rule_count": len(rs),
                           "contributing_rules": [r["rule_id"] for r in rs if r["risk_contribution"] > 0]})
    rule_risk = _combine([r["risk_contribution"] for r in rules])
    ml_p = ml_result.get("probability") if ml_result.get("status") == "OK" else None
    if ml_p is not None:
        final = int(round((1 - ML_WEIGHT) * rule_risk + ML_WEIGHT * ml_p * 100))
        method = f"final = {1 - ML_WEIGHT:.2f} × rule_risk + {ML_WEIGHT:.2f} × (ML probability × 100)"
    else:
        final = rule_risk
        method = "final = rule_risk (ML layer unavailable, so it does not contribute)"
    factors = [{"rule_id": r["rule_id"], "name": r["name"], "contribution": r["risk_contribution"], "severity": r["severity"]}
               for r in rules if r["risk_contribution"] > 0]
    return {
        "method": "Probabilistic OR of rule contributions: rule_risk = 100 × (1 − Π(1 − cᵢ/100)). "
                  "One strong signal can dominate; many weak observations do not simply add up. Informational rules contribute 0.",
        "formula": method,
        "rule_risk": rule_risk,
        "ml_probability": ml_p,
        "ml_weight": ML_WEIGHT if ml_p is not None else 0,
        "risk_score": max(0, min(100, final)),
        "layers": layer_rows,
        "risk_factors": factors,
    }


def _coverage(parsed, auth, sender_dns, text, html, candidates, url_results, dom_targets, domain_results,
              attachments, ml_result, options, webpage_results):
    items = []
    body_only = parsed["input_mode"] == "BODY_ONLY"
    items.append({"check": "Message headers", **(availability(UNAVAILABLE, None, "Only body text was supplied") if body_only
                  else availability(OBSERVED, len(parsed.get("header_list") or []), f"{len(parsed.get('header_list') or [])} header fields parsed"))})
    if body_only:
        items.append({"check": "Authentication results (SPF/DKIM/DMARC)", **availability(UNAVAILABLE, None, "No headers supplied")})
    elif auth.get("authentication_results_present") or parsed.get("received_spf"):
        items.append({"check": "Authentication results (SPF/DKIM/DMARC)", **availability(OBSERVED, auth.get("authserv_id"), "Reported by receiving server; not re-verified")})
    else:
        items.append({"check": "Authentication results (SPF/DKIM/DMARC)", **availability(UNAVAILABLE, None, "Authentication-Results header absent")})
    if sender_dns and sender_dns.get("domain"):
        de = sender_dns.get("domain_exists") or {}
        items.append({"check": "Sender domain DNS", **availability(de.get("state"), de.get("value"), de.get("reason"), "DNS")})
    else:
        items.append({"check": "Sender domain DNS", **availability(NOT_APPLICABLE if body_only or not (parsed.get("from")) else NOT_CHECKED, None,
                                                                   "No sender domain" if not parsed.get("from") else "Not checked")})
    items.append({"check": "Specific mailbox existence", "state": "NOT_VERIFIED", "value": None,
                  "reason": "Not verifiable without contacting the mail server; never inferred from MX records", "counted": False})
    items.append({"check": "Body text", **(availability(OBSERVED, len(text), "Text analysed") if text.strip()
                  else availability(UNAVAILABLE, None, "No readable text part (image-only or empty body)"))})
    items.append({"check": "HTML structure", **(availability(OBSERVED, None, "Static HTML inspection") if html.get("analysed")
                  else availability(NOT_APPLICABLE, None, "No HTML part"))})
    if not candidates:
        items.append({"check": "Links → URL Intelligence", **availability(NOT_APPLICABLE, 0, "No links in the message")})
    else:
        ok = sum(1 for r in url_results if r.get("status") != "ANALYSIS_UNAVAILABLE")
        items.append({"check": "Links → URL Intelligence", **(availability(INFERRED, ok, f"{ok}/{len(candidates)} link(s) analysed") if ok
                      else availability(UNAVAILABLE, 0, "URL Intelligence did not return results"))})
    if not dom_targets:
        items.append({"check": "Domains → Domain Intelligence", **availability(NOT_APPLICABLE, 0, "No domains to analyse")})
    elif not domain_results:
        items.append({"check": "Domains → Domain Intelligence", **availability(NOT_CHECKED, 0, "Not run")})
    else:
        ok = [d for d in domain_results if d.get("status") == "COLLECTED"]
        items.append({"check": "Domains → Domain Intelligence", **(availability(VERIFIED, len(ok), f"{len(ok)}/{len(dom_targets)} domain(s) collected live")
                      if ok else availability(UNAVAILABLE, 0, "; ".join(sorted({d.get('reason') or d.get('status', '') for d in domain_results}))[:200] or "Live collection failed"))})
    if candidates:
        if options.get("fetch_linked_pages"):
            ok = [w for w in webpage_results if w.get("webpage_status") == "AVAILABLE"]
            items.append({"check": "Linked webpages (opt-in)", **(availability(VERIFIED, len(ok), f"{len(ok)}/{len(webpage_results)} page(s) retrieved")
                          if ok else availability(UNAVAILABLE, 0, "No linked page could be retrieved"))})
        else:
            items.append({"check": "Linked webpages (opt-in)", "state": NOT_CHECKED, "value": None,
                          "reason": "Not retrieved (opt-in)", "counted": False})
    items.append({"check": "Attachments", **(availability(OBSERVED, attachments["count"], f"{attachments['count']} attachment(s), static analysis")
                  if attachments["count"] else availability(NOT_APPLICABLE, 0, "No attachments"))})
    items.append({"check": "Email text model (ML)", **(availability(INFERRED, ml_result.get("probability"), "Validated model")
                  if ml_result.get("status") == "OK" else availability(UNAVAILABLE, None, ml_result.get("reason")))})

    applicable = [i for i in items if i.get("state") != NOT_APPLICABLE and i.get("counted", True)]
    done = [i for i in applicable if i.get("state") in (OBSERVED, VERIFIED, INFERRED)]
    pct = int(round(100 * len(done) / len(applicable))) if applicable else 0
    return {"items": items, "applicable": len(applicable), "obtained": len(done), "percent": pct,
            "definition": "Evidence coverage = evidence sources obtained ÷ evidence sources applicable to this message "
                          "(not-applicable and opt-in checks excluded)."}


def _confidence(coverage, body_only, auth, risk):
    c = 0.35 + 0.6 * (coverage["percent"] / 100.0)
    notes = [f"base 0.35 + 0.60 × coverage ({coverage['percent']}%)"]
    if body_only:
        c -= 0.10
        notes.append("−0.10: headers not supplied")
    if risk < 40 and not auth.get("authentication_results_present"):
        c -= 0.10
        notes.append("−0.10: low risk but sender authentication could not be assessed")
    c = max(0.15, min(0.95, c))
    return {"percent": int(round(c * 100)), "method": "; ".join(notes) + " (bounded 15–95%)",
            "meaning": "How well the available evidence supports the risk score. It is not the probability of phishing."}


def _threat_dna(parsed, identity, auth, urls, attachments, language, rules):
    traits = []
    cs = identity.get("claimed_sender") or {}
    if cs.get("registered_domain"):
        traits.append(f"FROM_DOMAIN:{cs['registered_domain']}")
    for c in identity.get("comparisons", []):
        if c["relation"] == "DIFFERENT_DOMAIN" and c["field"] in ("Reply-To", "Return-Path"):
            traits.append(f"{c['field'].upper().replace('-', '_')}_DOMAIN:{registered_domain(c['domain'])}")
    for b in identity.get("brand_claims", []):
        traits.append(f"BRAND_CLAIM:{b['brand']}:{b['state']}")
    for mech in ("spf", "dkim", "dmarc"):
        r = (auth.get(mech) or {}).get("result")
        traits.append(f"AUTH_{mech.upper()}:{r or 'unavailable'}")
    for d in urls.get("external_domains", [])[:8]:
        traits.append(f"LINK_DOMAIN:{d}")
    for a in attachments.get("items", []):
        if a.get("sha256"):
            traits.append(f"ATTACHMENT_SHA256:{a['sha256'][:16]}")
        if a.get("extension"):
            traits.append(f"ATTACHMENT_EXT:{a['extension']}")
    for k in sorted(language.get("category_keys", [])):
        traits.append(f"CONTENT:{k}")
    hops = parsed.get("received") or []
    for h in reversed(hops):
        if h.get("from_ip"):
            traits.append(f"EARLIEST_HOP_IP:{h['from_ip']}")
            break
    for r in rules:
        if r["risk_contribution"] > 0:
            traits.append(f"RULE:{r['rule_id']}")
    traits = sorted(set(traits))
    h = hashlib.sha256("|".join(traits).encode()).hexdigest().upper()
    return {
        "fingerprint": f"NS-EML-{h[:4]}-{h[4:8]}-{h[8:12]}-{h[12:16]}",
        "traits": traits,
        "trait_count": len(traits),
        "readable": _dna_readable(traits),
        "disclaimer": "Threat DNA is an evidence-derived fingerprint for correlation. It is not attacker identity, "
                      "not attribution, and a shared trait does not mean two messages come from the same actor.",
    }


def _dna_readable(traits):
    groups = {}
    for t in traits:
        k = t.split(":", 1)[0]
        groups.setdefault(k, []).append(t.split(":", 1)[1] if ":" in t else "")
    return [{"group": k, "values": v} for k, v in groups.items()]


def _graph(parsed, identity, urls, attachments, domain_results, dna, url_results):
    nodes, edges, seen = [], [], set()

    def node(nid, ntype, label):
        if nid not in seen:
            seen.add(nid)
            nodes.append({"id": nid, "type": ntype, "label": truncate(label, 80)})
        return nid

    def edge(a, b, rel, evidence):
        edges.append({"source": a, "target": b, "relation": rel, "evidence": truncate(evidence, 240)})

    msg = node("email:message", "Email", parsed.get("subject") or "(no subject)")
    cs = identity.get("claimed_sender") or {}
    if cs.get("address"):
        fa = node(f"addr:{cs['address']}", "Sender address", cs["address"])
        edge(msg, fa, "claims sender", "From header")
        if cs.get("registered_domain"):
            fd = node(f"domain:{cs['registered_domain']}", "Sender domain", cs["registered_domain"])
            edge(fa, fd, "address domain", f"Domain part of {cs['address']}")
    for c in identity.get("comparisons", []):
        if c["field"] in ("Reply-To", "Return-Path", "Sender") and c.get("value") and c.get("domain"):
            a = node(f"addr:{c['value']}", f"{c['field']} address", c["value"])
            edge(msg, a, c["field"], f"{c['field']} header")
            dnode = node(f"domain:{registered_domain(c['domain'])}", "Reply-To domain" if c["field"] == "Reply-To" else "Domain",
                         registered_domain(c["domain"]))
            edge(a, dnode, "address domain", f"Domain part of {c['value']}")
        if c["field"] == "DKIM-Signature d=" and c.get("value"):
            dnode = node(f"domain:{registered_domain(c['value'])}", "Domain", registered_domain(c["value"]))
            edge(msg, dnode, "DKIM signing domain (observed)", f"DKIM-Signature d={c['value']} (signature presence observed)")
    for b in identity.get("brand_claims", []):
        bn = node(f"brand:{b['brand']}", "Brand", b["brand"].title())
        edge(msg, bn, "display name claims brand", f"Display name '{cs.get('display_name')}' → {b['state']}")
    hops = parsed.get("received") or []
    for h in reversed(hops):
        if h.get("from_ip"):
            ip = node(f"ip:{h['from_ip']}", "IP (earliest observed hop)", h["from_ip"])
            edge(msg, ip, "earliest observed relay", f"Received header #{h['index']} (sender-controllable if below your provider)")
            break
    risk_by_url = {r.get("url"): r for r in url_results}
    for u in urls.get("urls", [])[:20]:
        un = node(f"url:{u['url']}", "URL", u["url"])
        loc = ", ".join(u["locations"])
        r = risk_by_url.get(u["url"])
        edge(msg, un, "contains link", f"Found in {loc}" + (f"; URL risk {r.get('risk_score')}" if r and r.get("risk_score") is not None else ""))
        if u.get("registered_domain"):
            dn = node(f"domain:{u['registered_domain']}", "Link domain", u["registered_domain"])
            edge(un, dn, "hosted on", f"Hostname {u['host']}")
    for d in domain_results:
        for ip in (d.get("ips") or [])[:3]:
            ipn = node(f"ip:{ip}", "IP", ip)
            edge(f"domain:{d['domain']}", ipn, "resolves to", "Live DNS A record (Domain Intelligence)")
        for ns in (d.get("nameservers") or [])[:2]:
            nsn = node(f"ns:{ns}", "Nameserver", ns)
            edge(f"domain:{d['domain']}", nsn, "delegated to", "Live NS record (Domain Intelligence)")
    for a in attachments.get("items", []):
        an = node(f"att:{a.get('sha256') or a.get('filename')}", "Attachment", a.get("filename") or "(unnamed)")
        edge(msg, an, "has attachment", f"MIME part {a.get('declared_mime_type')}, sha256 {str(a.get('sha256'))[:16]}…")
    dn = node(f"dna:{dna['fingerprint']}", "Threat DNA", dna["fingerprint"])
    edge(msg, dn, "fingerprint", f"Derived from {dna['trait_count']} observed traits")
    # drop edges whose endpoints were never created (e.g. domain results for skipped domains)
    edges = [e for e in edges if e["source"] in seen and e["target"] in seen]
    return {"nodes": nodes, "edges": edges,
            "note": "Every edge is backed by the evidence shown. No edge is created from visual similarity alone."}


def _timeline(parsed, stages, t_start):
    ev = []
    hops = parsed.get("received") or []
    for h in reversed(hops):
        if h.get("timestamp"):
            ev.append({"time": h["timestamp"], "event": f"Relay {h.get('from_host') or '?'} → {h.get('by_host') or '?'}"
                       + (f" via {h['protocol']}" if h.get("protocol") else ""),
                       "source": f"Received header #{h['index']}", "state": OBSERVED})
    if parsed.get("date"):
        ev.append({"time": parsed["date"], "event": "Date claimed by sender", "source": "Date header", "state": OBSERVED})
    for s in stages:
        ev.append({"time": s.get("started_at"), "event": f"NeuraShield: {s['name']} — {s['status'].lower()}"
                   + (f" ({s['duration_ms']} ms)" if s.get("duration_ms") else ""),
                   "source": "NeuraShield", "state": "SYSTEM"})
    ev.sort(key=lambda e: e["time"] or "")
    return ev


SEV_WORD = {"CRITICAL": "critical", "HIGH": "strong", "MEDIUM": "moderate", "LOW": "weak", "INFORMATIONAL": "informational"}


def _plain_findings(rules, auth, identity, sender_dns, urls, attachments, body_only):
    out = []
    for r in rules:
        out.append({"text": f"{r['name']}. {r['evidence']}", "severity": r["severity"], "rule_id": r["rule_id"],
                    "why": r["explanation"]})
    for mech in ("spf", "dkim", "dmarc"):
        res = (auth.get(mech) or {}).get("result")
        if res == "pass":
            out.append({"text": f"{mech.upper()} passed (reported by {auth.get('authserv_id') or 'the receiving server'}). "
                                f"This supports that the message came through infrastructure authorised for "
                                f"{(auth.get(mech) or {}).get('domain') or 'the evaluated domain'} — it does not prove the content is safe.",
                        "severity": "INFORMATIONAL"})
    de = (sender_dns or {}).get("domain_exists") or {}
    if de.get("state") == VERIFIED and de.get("value"):
        mx = (sender_dns.get("mx") or {})
        out.append({"text": f"Sender domain {sender_dns['domain']} exists in DNS"
                            + (f" and publishes {len(mx.get('value') or [])} MX record(s)" if mx.get("state") == VERIFIED and mx.get("value") else "")
                            + ". This does not prove the specific mailbox exists or sent this message.", "severity": "INFORMATIONAL"})
    if not urls.get("url_count"):
        out.append({"text": "No links were found in the message.", "severity": "INFORMATIONAL"})
    if not attachments.get("count"):
        out.append({"text": "The message has no attachments.", "severity": "INFORMATIONAL"})
    return out


def _could_not_verify(coverage, auth, body_only, options, candidates):
    out = []
    for i in coverage["items"]:
        if i.get("state") in (UNAVAILABLE, NOT_CHECKED, "NOT_VERIFIED"):
            out.append({"text": f"{i['check']}: {i['state'].replace('_', ' ').lower()} — {i.get('reason') or 'no reason recorded'}",
                        "state": i["state"]})
    out.append({"text": "Who actually wrote the message cannot be proven from its content; the From header is a claim.", "state": "NOT_VERIFIED"})
    if auth.get("authentication_results_present"):
        out.append({"text": "Authentication results were read from the message, not independently re-computed.", "state": "NOT_VERIFIED"})
    if candidates and not options.get("fetch_linked_pages"):
        out.append({"text": "Final destinations of links (after redirects) were not visited.", "state": NOT_CHECKED})
    return out


def _recommendations(risk, rules, language, attachments, urls):
    ids = {r["rule_id"] for r in rules}
    recs = []
    if risk >= 40:
        recs.append("Do not click links, open attachments, or reply until the sender is confirmed through a channel you already trust.")
        recs.append("Report the message as phishing using your mail provider's \"Report phishing\" option, and to your IT/security team if this is a work account.")
    else:
        recs.append("No strong risk indicators were observed, but still verify any unexpected request through a channel you already trust.")
    if ids & {"EML-002", "EML-003", "EML-011"}:
        recs.append("If the message claims to be from a company, open that company's website or app yourself (type the address) instead of using links in the e-mail.")
    if ids & {"EML-001"}:
        recs.append("Do not reply directly: the Reply-To address sends your answer to a different organisation.")
    if ids & {"EML-015", "EML-017", "EML-018", "EML-020", "EML-022"}:
        recs.append("Delete the attachment without opening it. Never enable macros or \"content\" in documents received by e-mail.")
    if "EML-025" in ids or "payment_request" in language.get("category_keys", []):
        recs.append("Confirm any payment or bank-detail change by phone using a number you already have — never one from the e-mail.")
    if ids & {"EML-024"}:
        recs.append("Legitimate services do not ask you to send passwords or one-time codes by e-mail.")
    return recs


def _interaction_guidance():
    return [
        {"question": "Did you click a link?", "steps": [
            "Close the page; do not enter anything.", "Run your device's security scan.",
            "If a file downloaded, delete it without opening."]},
        {"question": "Did you enter a password or code?", "steps": [
            "Change that password now from the official site/app, and anywhere you reused it.",
            "Turn on two-factor authentication and sign out other sessions.",
            "Check account activity, recovery e-mail and phone for changes."]},
        {"question": "Did you download or open an attachment?", "steps": [
            "Disconnect the device from the network if you enabled macros or ran a file.",
            "Contact your IT/security team or run a full security scan before using the device for sensitive tasks."]},
        {"question": "Did you share payment or banking information?", "steps": [
            "Call your bank immediately using the number on your card and ask to block the card/transaction.",
            "In India, call the cyber-fraud helpline 1930 as soon as possible and file a report at cybercrime.gov.in."]},
        {"question": "Did you reply?", "steps": [
            "Stop the conversation; expect follow-up attempts.", "Do not send further information or money."]},
    ]


def _final_assessment(risk, verdict, key_findings, coverage):
    if key_findings:
        top = "; ".join(f"{k['name'].lower()}" for k in key_findings[:3])
        core = f"Assessment: {verdict['label']} (risk {risk}/100). The main contributing evidence: {top}."
    else:
        core = f"Assessment: {verdict['label']} (risk {risk}/100). No rule with a risk contribution fired."
    return core + f" Evidence coverage was {coverage['percent']}%; items that could not be verified are listed separately and were not treated as malicious."


def _explanation(fusion, rules, coverage, verdict, body_only):
    strong = [r for r in rules if r["severity"] in ("CRITICAL", "HIGH")]
    if strong:
        s = f"{len(strong)} strong indicator(s) were observed, led by: {strong[0]['name'].lower()}."
    elif fusion["risk_factors"]:
        s = f"{len(fusion['risk_factors'])} weaker indicator(s) were observed; none is strong on its own."
    else:
        s = "None of the security rules that contribute to risk were triggered."
    tail = " Headers were not supplied, so sender and authentication checks were not possible." if body_only else ""
    return f"{s} Evidence coverage {coverage['percent']}%.{tail}"


def _evidence_package(inv_id, t_start, parsed, identity, dna, fusion, rules, urls, attachments, verdict):
    cs = identity.get("claimed_sender") or {}
    return {
        "investigation_id": inv_id,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "investigation_started_at": t_start.isoformat(),
        "target": {"type": "email", "subject": parsed.get("subject"), "claimed_from": cs.get("address"),
                   "display_name": cs.get("display_name"), "message_id": parsed.get("message_id"),
                   "date_header": parsed.get("date_raw"), "message_sha256": parsed["sha256"]},
        "threat_dna": dna["fingerprint"],
        "risk_assessment": {"risk_score": fusion["risk_score"], "verdict": verdict["label"]},
        "findings": [{"rule_id": r["rule_id"], "name": r["name"], "severity": r["severity"], "evidence": r["evidence"]} for r in rules],
        "urls": [u["url"] for u in urls.get("urls", [])][:50],
        "attachments": [{"filename": a.get("filename"), "sha256": a.get("sha256"), "size_bytes": a.get("size_bytes")}
                        for a in attachments.get("items", [])],
        "headers": parsed.get("header_list"),
        "incident_description_template": (
            f"On [date/time] I received an e-mail with subject \"{parsed.get('subject') or '(no subject)'}\" claiming to be from "
            f"{cs.get('display_name') or ''} <{cs.get('address') or 'unknown'}>. NeuraShield investigation {inv_id} rated it "
            f"{verdict['label'].lower()} (risk {fusion['risk_score']}/100). [Describe any action you took: clicked / entered details / paid.]"),
        "reporting_portal": {"name": "National Cyber Crime Reporting Portal (India)", "url": PORTAL_URL,
                             "helpline": "1930 (financial cyber fraud)",
                             "submission_status": "NOT SUBMITTED — NeuraShield does not file complaints automatically. Use the portal yourself."},
        "note": "Screenshots are not included because none were captured for e-mail investigations.",
    }
