"""Flask wiring for MODULE 4 (Email Intelligence), the capability registry,
persistent investigations and the Investigation Center list.

Registered from backend/app.py via register_email_routes(app, deps) so the
existing app keeps working unchanged if this file is removed."""
import json
import threading
import time
from collections import defaultdict, deque
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime

from flask import jsonify, redirect, render_template, request, session

try:
    from backend.capabilities import get_capabilities
except ImportError:  # running backend/app.py directly
    from capabilities import get_capabilities

from model.email_intelligence.analyzer import run_email_investigation
from model.email_intelligence.parser import EmailParseError, MAX_EMAIL_BYTES

ERROR_STATUS = {"INVALID_INPUT": 400, "UNSUPPORTED_FORMAT": 415, "CONTENT_TOO_LARGE": 413,
                "PARSER_ERROR": 422, "AUTHENTICATION_REQUIRED": 401, "RATE_LIMITED": 429,
                "ANALYSIS_UNAVAILABLE": 500, "NOT_FOUND": 404}
RATE_WINDOW_S, RATE_MAX = 300, 20


def _err(code, message):
    return jsonify({"error": {"code": code, "message": message}}), ERROR_STATUS.get(code, 400)


class _RateLimiter:
    def __init__(self):
        self._hits = defaultdict(deque)
        self._lock = threading.Lock()

    def allow(self, key):
        now = time.time()
        with self._lock:
            q = self._hits[key]
            while q and now - q[0] > RATE_WINDOW_S:
                q.popleft()
            if len(q) >= RATE_MAX:
                return False
            q.append(now)
            return True


def init_investigation_tables(get_db_connection):
    conn = get_db_connection()
    c = conn.cursor()
    c.execute("""CREATE TABLE IF NOT EXISTS investigations (
        investigation_id TEXT PRIMARY KEY,
        investigation_type TEXT NOT NULL,
        user_id INTEGER,
        target_display TEXT,
        risk_score INTEGER,
        risk_level TEXT,
        verdict TEXT,
        threat_dna TEXT,
        created_at TEXT NOT NULL,
        payload_json TEXT NOT NULL)""")
    c.execute("CREATE INDEX IF NOT EXISTS idx_investigations_user ON investigations(user_id, created_at)")
    c.execute("CREATE INDEX IF NOT EXISTS idx_investigations_type ON investigations(investigation_type)")
    c.execute("""CREATE TABLE IF NOT EXISTS email_analyses (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        investigation_id TEXT NOT NULL,
        user_id INTEGER,
        message_sha256 TEXT,
        subject TEXT,
        claimed_from TEXT,
        from_domain TEXT,
        spf_result TEXT, dkim_result TEXT, dmarc_result TEXT,
        url_count INTEGER, attachment_count INTEGER,
        risk_score INTEGER, confidence INTEGER, evidence_coverage INTEGER,
        rules_hit TEXT, dna_traits TEXT,
        analysis_timestamp TEXT NOT NULL)""")
    c.execute("CREATE INDEX IF NOT EXISTS idx_email_analyses_sha ON email_analyses(message_sha256)")
    c.execute("CREATE INDEX IF NOT EXISTS idx_email_analyses_user ON email_analyses(user_id)")
    conn.commit()
    conn.close()


def save_investigation(get_db_connection, inv, user_id=None):
    """Persist any investigation payload (URL, webpage, email) so reports survive restarts."""
    inv_type = inv.get("investigation_type") or "url"
    if inv_type == "email":
        s = inv.get("summary", {})
        risk, level, verdict = s.get("risk_score"), s.get("risk_level"), s.get("verdict_label")
        target = (inv.get("target") or {}).get("display")
        dna = (inv.get("threat_dna") or {}).get("fingerprint")
    else:
        r = inv.get("risk") or {}
        risk, level, verdict = r.get("composite_score"), r.get("composite_level"), r.get("prediction")
        target = (inv.get("target") or {}).get("original_url") or inv.get("domain")
        dna = inv.get("threat_dna") if isinstance(inv.get("threat_dna"), str) else None
    conn = get_db_connection()
    try:
        conn.execute("""INSERT OR REPLACE INTO investigations
            (investigation_id, investigation_type, user_id, target_display, risk_score, risk_level, verdict, threat_dna, created_at, payload_json)
            VALUES (?,?,?,?,?,?,?,?,?,?)""",
                     (inv["investigation_id"], inv_type, user_id, (target or "")[:500], risk, level, verdict, dna,
                      inv.get("timestamp") or datetime.now().isoformat(), json.dumps(inv, default=str)))
        conn.commit()
    finally:
        conn.close()


def load_investigation(get_db_connection, inv_id):
    conn = get_db_connection()
    try:
        row = conn.execute("SELECT payload_json, user_id FROM investigations WHERE investigation_id=?", (inv_id,)).fetchone()
    finally:
        conn.close()
    if not row:
        return None, None
    try:
        return json.loads(row[0]), row[1]
    except Exception:
        return None, None


def register_email_routes(app, deps):
    get_db = deps["get_db_connection"]
    init_investigation_tables(get_db)
    limiter = _RateLimiter()

    # ── service adapters around Modules 1–3 ──────────────────────────────
    def url_analyzer(url):
        prediction, probability = deps["classify_url"](url)
        features = deps["extract_features"](url)
        intel = deps["build_url_intelligence"](url, prediction, probability, features)
        rules = (intel.get("security_rules") or {}).get("rules_hit") or []
        return {"status": "ANALYSED", "risk_score": intel.get("composite_risk"), "risk_level": intel.get("composite_level"),
                "prediction": prediction, "ml_probability": probability,
                "rules": [{"rule_id": r.get("rule_id") or r.get("rule"), "label": r.get("label") or r.get("name"),
                           "severity": r.get("severity") or r.get("sev")} for r in rules][:10],
                "top_signals": (intel.get("top_signals") or [])[:4],
                "report_link": f"/report?url={url}"}

    def domain_analyzer(domain):
        cache = deps["domain_cache"]
        cached = cache.get(domain)
        if cached:
            di, dr = cached.get("domain_intelligence"), cached.get("domain_rules")
        else:
            di = deps["analyze_domain"](domain)
            dr = deps["evaluate_domain_rules"](di) if di and not di.get("error") else None
            if di and not di.get("error"):
                cache.put(domain, {"domain": domain, "domain_intelligence": di, "domain_rules": dr, "domain_ml": None})
        if not di or di.get("error"):
            return {"status": "ANALYSIS_UNAVAILABLE", "reason": (di or {}).get("error") or "No result"}
        if di.get("overall_status") == "failed":
            dns_status = (di.get("dns") or {}).get("collection_status")
            return {"status": "ANALYSIS_UNAVAILABLE", "reason": f"Live collection failed (DNS: {dns_status})",
                    "telemetry": di.get("telemetry_categories")}
        reg = di.get("registration") or {}
        ssl = di.get("ssl") or {}
        return {"status": "COLLECTED", "overall_status": di.get("overall_status"),
                "ips": ((di.get("ip") or {}).get("resolved_ipv4") or [])[:5],
                "nameservers": ((di.get("nameservers") or {}).get("nameserver_list") or [])[:4],
                "domain_age_days": reg.get("domain_age_days"), "registrar": reg.get("registrar"),
                "tls": ssl.get("transport_status"), "certificate_issuer": ssl.get("certificate_issuer"),
                "risk_score": (dr or {}).get("risk_score"), "rules_hit": [r.get("rule_id") or r.get("id") for r in (dr or {}).get("threat_rules_hit", [])][:8],
                "evidence_coverage": di.get("evidence_coverage"), "telemetry": di.get("telemetry_categories"),
                "report_link": f"/domain-intelligence?domain={domain}"}

    def webpage_analyzer(url):
        fetch = deps["safe_fetch_webpage"](url)
        if fetch.get("fetch_status") != deps["FETCH_SUCCESS"]:
            return {"webpage_status": "UNAVAILABLE", "reason": fetch.get("fetch_status"),
                    "detail": fetch.get("fetch_status_detail"),
                    "message": "Webpage could not be retrieved, so webpage-level analysis was not performed."}
        wa = deps["analyze_webpage"](fetch)
        wr = deps["evaluate_webpage_rules"](wa, fetch, url)
        forms = wa.get("form_analysis") or {}
        return {"webpage_status": "AVAILABLE", "final_url": fetch.get("final_url"), "http_status": fetch.get("http_status"),
                "title": ((wa.get("html_analysis") or {}).get("title")), "has_password_field": forms.get("has_password_field"),
                "cross_domain_form": forms.get("has_cross_domain_action"), "risk_score": wr.get("risk_score"),
                "rules_hit": [r.get("rule_id") for r in wr.get("rules_hit", [])][:8]}

    services = {"url_analyzer": url_analyzer, "domain_analyzer": domain_analyzer, "webpage_analyzer": webpage_analyzer}

    def _similar(inv, user_id):
        traits = set((inv.get("threat_dna") or {}).get("traits") or [])
        # only compare meaningful traits (not generic auth=unavailable)
        traits = {t for t in traits if not t.startswith("AUTH_") or not t.endswith(":unavailable")}
        if len(traits) < 3:
            return []
        conn = get_db()
        try:
            rows = conn.execute("""SELECT investigation_id, subject, dna_traits, risk_score, analysis_timestamp FROM email_analyses
                                   WHERE investigation_id != ? AND (user_id IS ? OR user_id = ?) ORDER BY id DESC LIMIT 500""",
                                (inv["investigation_id"], user_id, user_id)).fetchall()
        finally:
            conn.close()
        out = []
        for iid, subj, tj, risk, ts in rows:
            try:
                other = {t for t in json.loads(tj or "[]") if not t.startswith("AUTH_") or not t.endswith(":unavailable")}
            except Exception:
                continue
            shared = traits & other
            union = traits | other
            if len(shared) >= 3 and union and len(shared) / len(union) >= 0.5:
                out.append({"investigation_id": iid, "subject": subj, "risk_score": risk, "timestamp": ts,
                            "jaccard": round(len(shared) / len(union), 2), "shared_traits": sorted(shared)[:12]})
        out.sort(key=lambda x: -x["jaccard"])
        return out[:5]

    # ── pages ────────────────────────────────────────────────────────────
    @app.route("/email-intelligence")
    def email_intelligence_page():
        return render_template("email_intelligence.html",
                               username=session.get("username", "Guest Analyst"),
                               role=session.get("role", "guest"),
                               max_mb=MAX_EMAIL_BYTES // (1024 * 1024))

    @app.route("/investigations")
    def investigations_page():
        return render_template("investigations.html",
                               username=session.get("username", "Guest Analyst"),
                               role=session.get("role", "guest"))

    # ── APIs ─────────────────────────────────────────────────────────────
    @app.route("/api/capabilities")
    def api_capabilities():
        return jsonify(get_capabilities())

    @app.route("/api/investigations")
    def api_investigations():
        try:
            page = max(1, int(request.args.get("page", 1)))
        except ValueError:
            page = 1
        per = 25
        conn = get_db()
        try:
            uid = session.get("user_id")
            if uid:
                rows = conn.execute("""SELECT investigation_id, investigation_type, target_display, risk_score, risk_level, verdict, threat_dna, created_at
                                       FROM investigations WHERE user_id=? ORDER BY created_at DESC LIMIT ? OFFSET ?""",
                                    (uid, per + 1, (page - 1) * per)).fetchall()
            else:
                rows = conn.execute("""SELECT investigation_id, investigation_type, target_display, risk_score, risk_level, verdict, threat_dna, created_at
                                       FROM investigations ORDER BY created_at DESC LIMIT ? OFFSET ?""",
                                    (per + 1, (page - 1) * per)).fetchall()
        finally:
            conn.close()
        items = [dict(zip(["investigation_id", "investigation_type", "target", "risk_score", "risk_level", "verdict", "threat_dna", "created_at"], r))
                 for r in rows[:per]]
        return jsonify({"items": items, "page": page, "has_more": len(rows) > per})

    @app.route("/api/email/investigate", methods=["POST"])
    def api_email_investigate():
        rate_key = session.get("user_id") or request.remote_addr or "guest"
        if request.content_length and request.content_length > MAX_EMAIL_BYTES + 512 * 1024:
            return _err("CONTENT_TOO_LARGE", f"Upload exceeds the {MAX_EMAIL_BYTES // (1024 * 1024)} MB limit.")
        if not limiter.allow(rate_key):
            return _err("RATE_LIMITED", f"Too many e-mail investigations. Limit is {RATE_MAX} per {RATE_WINDOW_S // 60} minutes.")

        raw, filename = None, None
        f = request.files.get("email_file")
        if f and f.filename:
            filename = f.filename.replace("\\", "/").rsplit("/", 1)[-1][:200]   # never used as a path
            raw = f.read(MAX_EMAIL_BYTES + 1)
        else:
            data = request.get_json(silent=True) or {}
            text = data.get("raw_email") if data else None
            if text is None:
                text = request.form.get("raw_email")
            if text:
                raw = text.encode("utf-8", errors="replace")
        if not raw:
            return _err("INVALID_INPUT", "Provide an .eml file (field 'email_file') or raw e-mail source (field 'raw_email').")

        opts_src = request.form if request.form else (request.get_json(silent=True) or {})
        options = {"fetch_linked_pages": str(opts_src.get("fetch_linked_pages", "")).lower() in ("1", "true", "on", "yes"),
                   "domain_intel": str(opts_src.get("domain_intel", "true")).lower() not in ("0", "false", "off", "no")}
        try:
            inv = run_email_investigation(raw, filename, options, services)
        except EmailParseError as e:
            return _err(e.code, e.message)
        except Exception as e:
            app.logger.exception("Email investigation failed")
            return _err("ANALYSIS_UNAVAILABLE", "The e-mail investigation could not be completed due to an internal error.")

        inv = deps["sanitize_for_json"](inv)
        user_id = session.get("user_id")
        try:
            inv["similar_investigations"] = _similar(inv, user_id)
            inv["similarity_note"] = ("Similarity = shared Threat DNA traits (Jaccard ≥ 0.5, ≥ 3 shared). "
                                      "It indicates overlapping evidence, not the same attacker.")
        except Exception:
            inv["similar_investigations"] = []
        try:
            save_investigation(get_db, inv, user_id)
            em = inv["layers"]["email"]
            auth = em.get("authentication") or {}
            conn = get_db()
            conn.execute("""INSERT INTO email_analyses (investigation_id, user_id, message_sha256, subject, claimed_from, from_domain,
                            spf_result, dkim_result, dmarc_result, url_count, attachment_count, risk_score, confidence, evidence_coverage,
                            rules_hit, dna_traits, analysis_timestamp) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                         (inv["investigation_id"], user_id, em["message"]["sha256"], (em["message"].get("subject") or "")[:300],
                          (em["identity"]["claimed_sender"] or {}).get("address"), (em["identity"]["claimed_sender"] or {}).get("registered_domain"),
                          (auth.get("spf") or {}).get("result"), (auth.get("dkim") or {}).get("result"), (auth.get("dmarc") or {}).get("result"),
                          em["urls"]["url_count"], em["attachments"]["count"], inv["summary"]["risk_score"], inv["summary"]["confidence"],
                          inv["summary"]["evidence_coverage"], json.dumps([r["rule_id"] for r in inv["rules"]]),
                          json.dumps(inv["threat_dna"]["traits"]), inv["timestamp"]))
            conn.commit()
            conn.close()
            inv["persisted"] = True
        except Exception:
            app.logger.exception("Could not persist e-mail investigation")
            inv["persisted"] = False
        deps["investigation_store"].put(inv["investigation_id"], inv)
        return jsonify(inv)

    return {"save_investigation": lambda inv, uid=None: save_investigation(get_db, inv, uid),
            "load_investigation": lambda iid: load_investigation(get_db, iid)}
