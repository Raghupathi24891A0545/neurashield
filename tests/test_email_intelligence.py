"""Module 4 tests (master prompt §60.9) + security regressions.
Run:  python -m pytest tests/test_email_intelligence.py -q
Fixtures are SYNTHETIC (tests/fixtures/email/make_fixtures.py)."""
import io
import os
import sys
import tempfile

import pytest

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, ROOT)
FX = os.path.join(ROOT, "tests", "fixtures", "email")
os.environ.setdefault("DATABASE_DIR", tempfile.mkdtemp(prefix="ns_test_db_"))

from model.email_intelligence.analyzer import run_email_investigation  # noqa: E402
from model.email_intelligence.parser import EmailParseError, MAX_EMAIL_BYTES  # noqa: E402
from model.email_intelligence.content import extract_urls, analyze_language  # noqa: E402


def fx(name):
    with open(os.path.join(FX, name), "rb") as f:
        return f.read()


def run(name, **opts):
    return run_email_investigation(fx(name), name, {"live_dns": False, **opts})


def ids(inv):
    return {r["rule_id"] for r in inv["rules"]}


# 1 valid .eml with complete headers / 9 legitimate e-mail
def test_legitimate_authenticated_email():
    inv = run("legit_authenticated.eml")
    s = inv["summary"]
    assert s["risk_score"] < 20 and s["verdict"] == "NO_SIGNIFICANT_INDICATORS"
    auth = inv["layers"]["email"]["authentication"]
    assert auth["spf"]["result"] == "pass" and auth["dkim"]["result"] == "pass" and auth["dmarc"]["result"] == "pass"
    assert auth["independently_reverified"] is False
    assert "safe" not in s["verdict_label"].lower()   # never claims safety


# 2 missing optional headers / 7 missing authentication headers
def test_missing_headers_reported_unavailable_not_malicious():
    inv = run("missing_headers.eml")
    em = inv["layers"]["email"]
    assert em["authentication"]["spf"]["state"] == "UNAVAILABLE"
    assert "Authentication-Results header absent" in em["authentication"]["spf"]["reason"]
    assert em["message"]["message_id"] is None
    r7 = [r for r in inv["rules"] if r["rule_id"] == "EML-007"][0]
    assert r7["risk_contribution"] == 0 and r7["severity"] == "INFORMATIONAL"
    assert inv["summary"]["risk_score"] < 20


# 3 malformed e-mail
def test_malformed_eml_fails_safely():
    with pytest.raises(EmailParseError) as e:
        run_email_investigation(fx("malformed.eml"), "malformed.eml", {"live_dns": False})
    assert e.value.code == "PARSER_ERROR"


# 4 From/Reply-To mismatch, 8 suspicious display name
def test_reply_to_mismatch_and_display_name():
    inv = run("phish_paypal.eml")
    assert {"EML-001", "EML-006", "EML-011"} <= ids(inv)
    inv2 = run("display_spoof.eml")
    assert {"EML-002", "EML-003"} <= ids(inv2)


def test_brand_consistent_when_domain_matches():
    inv = run("phish_paypal.eml")      # From really is @paypal.com → brand claim consistent; DMARC fail is what matters
    b = inv["layers"]["email"]["identity"]["brand_claims"][0]
    assert b["state"] == "CONSISTENT" and "EML-002" not in ids(inv)


# 5 multiple URLs
def test_multiple_urls_ip_and_shortener():
    inv = run("multi_urls.eml")
    u = inv["layers"]["email"]["urls"]
    assert u["url_count"] >= 4
    assert {"EML-012", "EML-013"} <= ids(inv)


# 6 attachment metadata (static only)
def test_attachment_static_analysis():
    inv = run("attachments.eml")
    items = {a["filename"]: a for a in inv["layers"]["email"]["attachments"]["items"]}
    z = items["invoice.zip"]
    assert z["archive"]["readable"] and any("invoice_0923.exe" in e for e in z["archive"]["dangerous_entries"])
    assert len(z["sha256"]) == 64 and z["static_only"] is True
    assert "VBA_MACRO_PRESENT" in {f["flag"] for f in items["Remittance.docm"]["flags"]}
    assert {"EML-022", "EML-017"} <= ids(inv)


def test_double_extension_html_attachment():
    inv = run("phish_paypal.eml")
    assert {"EML-018", "EML-020"} <= ids(inv)


# 13 HTML with scripts (never executed)
def test_html_scripts_forms_hidden_text():
    inv = run("html_script.eml")
    h = inv["layers"]["email"]["content"]["html"]
    assert h["script_count"] == 1 and h["form_count"] == 1 and h["password_inputs"] == 1
    assert {"EML-027", "EML-028", "EML-029"} <= ids(inv)


# 14 encoded content
def test_encoded_subject_and_base64_body():
    inv = run("encoded.eml")
    em = inv["layers"]["email"]
    assert em["message"]["subject"].startswith("Votre facture")
    assert em["identity"]["claimed_sender"]["display_name"].startswith("Équipe")
    assert any("docs.example.org" in u["url"] for u in em["urls"]["urls"])


# 11 unsupported format / 12 oversized file
def test_unsupported_and_oversized():
    with pytest.raises(EmailParseError) as e:
        run_email_investigation(fx("outlook.msg"), "outlook.msg", {})
    assert e.value.code == "UNSUPPORTED_FORMAT"
    with pytest.raises(EmailParseError) as e:
        run_email_investigation(b"From: a@b.c\n\n" + b"x" * (MAX_EMAIL_BYTES + 1), "big.eml", {})
    assert e.value.code == "CONTENT_TOO_LARGE"
    with pytest.raises(EmailParseError) as e:
        run_email_investigation(b"x", "evil.exe", {})
    assert e.value.code == "UNSUPPORTED_FORMAT"


def test_body_only_paste_has_no_invented_headers():
    inv = run_email_investigation(fx("body_only.txt"), None, {"live_dns": False})
    em = inv["layers"]["email"]
    assert inv["target"]["input_mode"] == "BODY_ONLY"
    assert em["identity"]["claimed_sender"]["address"] is None and em["headers"] == []
    assert em["authentication"]["dmarc"]["state"] == "UNAVAILABLE"


# 17 safe failure of network operations: DNS off / services missing → truthful states
def test_no_services_no_fabrication():
    inv = run("phish_paypal.eml")
    cov = {i["check"]: i for i in inv["coverage"]["items"]}
    assert cov["Links → URL Intelligence"]["state"] == "UNAVAILABLE"
    assert cov["Specific mailbox existence"]["state"] == "NOT_VERIFIED"
    assert cov["Email text model (ML)"]["state"] in ("UNAVAILABLE", "INFERRED")
    if cov["Email text model (ML)"]["state"] == "INFERRED":
        assert inv["summary"]["ml_probability"] is not None
    else:
        assert inv["summary"]["ml_probability"] is None
    assert inv["layers"]["url"] == [] and inv["layers"]["domain"] == []


def test_service_failure_is_reported():
    def boom(_):
        raise TimeoutError("simulated")
    inv = run_email_investigation(fx("phish_paypal.eml"), "p.eml", {"live_dns": False},
                                  {"url_analyzer": boom, "domain_analyzer": boom})
    assert all(r["status"] == "ANALYSIS_UNAVAILABLE" for r in inv["layers"]["url"])
    assert all(d["status"] == "ANALYSIS_UNAVAILABLE" for d in inv["layers"]["domain"])


def test_mailbox_never_claimed_to_exist():
    from model.email_intelligence.sender_dns import MAILBOX_NOT_VERIFIED
    assert MAILBOX_NOT_VERIFIED["state"] == "NOT_VERIFIED"


def test_risk_confidence_coverage_are_separate_and_bounded():
    for f in ("phish_paypal.eml", "legit_authenticated.eml", "html_script.eml"):
        s = run(f)["summary"]
        assert 0 <= s["risk_score"] <= 100 and 15 <= s["confidence"] <= 95 and 0 <= s["evidence_coverage"] <= 100


def test_single_keyword_does_not_trigger_content_rules():
    lang = analyze_language("Please reply urgently about lunch")
    assert lang["category_keys"] == ["urgency"]
    inv = run_email_investigation(b"From: a@example.org\nTo: b@example.org\nSubject: lunch\nDate: Wed, 23 Sep 2026 06:00:00 +0000\n\nurgent: lunch moved to 1pm\n",
                                  "x.eml", {"live_dns": False})
    assert not ({"EML-024", "EML-025", "EML-026"} & ids(inv))


def test_every_graph_edge_has_evidence():
    g = run("phish_paypal.eml")["graph"]
    node_ids = {n["id"] for n in g["nodes"]}
    assert g["edges"] and all(e["evidence"] and e["source"] in node_ids and e["target"] in node_ids for e in g["edges"])


def test_threat_dna_deterministic_for_same_evidence():
    assert run("phish_paypal.eml")["threat_dna"]["fingerprint"] == run("phish_paypal.eml")["threat_dna"]["fingerprint"]


def test_anchor_mismatch_detection():
    r = extract_urls("", '<a href="http://evil.example.net/x">https://www.paypal.com</a>', "paypal.com")
    assert r["anchor_mismatches"][0]["actual_domain"] == "example.net"


# ── Flask integration & security ─────────────────────────────────────────
@pytest.fixture(scope="module")
def client():
    from backend.app import app
    app.config["TESTING"] = True
    c = app.test_client()
    c.post("/register", data={"username": "pytest_user", "password": "pytest-pass-123"})
    c.post("/login", data={"username": "pytest_user", "password": "pytest-pass-123"})
    return c


def test_api_requires_login():
    from backend.app import app
    c = app.test_client()
    r = c.post("/api/email/investigate", data={"raw_email": "From: a@b.c\n\nhi"})
    assert r.status_code == 401 and r.get_json()["error"]["code"] == "AUTHENTICATION_REQUIRED"


def test_api_end_to_end_and_persistence(client):
    r = client.post("/api/email/investigate", data={"email_file": (io.BytesIO(fx("phish_paypal.eml")), "phish.eml")},
                    content_type="multipart/form-data")
    j = r.get_json()
    assert r.status_code == 200 and j["summary"]["risk_score"] >= 60 and j["persisted"] is True
    assert client.get(f"/api/investigation/{j['investigation_id']}").status_code == 200
    assert client.get(f"/report?id={j['investigation_id']}").status_code == 200


def test_api_error_codes(client):
    r = client.post("/api/email/investigate", data={"email_file": (io.BytesIO(fx("outlook.msg")), "outlook.msg")},
                    content_type="multipart/form-data")
    assert r.status_code == 415
    r = client.post("/api/email/investigate", data={})
    assert r.status_code == 400 and r.get_json()["error"]["code"] == "INVALID_INPUT"


def test_other_user_cannot_read_email_investigation(client):
    from backend.app import app, investigation_store
    r = client.post("/api/email/investigate", json={"raw_email": fx("legit_authenticated.eml").decode()})
    iid = r.get_json()["investigation_id"]
    other = app.test_client()
    other.post("/register", data={"username": "pytest_other", "password": "other-pass-123"})
    other.post("/login", data={"username": "pytest_other", "password": "other-pass-123"})
    investigation_store._store.pop(iid, None)
    assert other.get(f"/api/investigation/{iid}").status_code == 404


def test_passwords_are_hashed_and_legacy_rows_upgrade():
    import sqlite3
    from backend.app import app, DATABASE_PATH
    con = sqlite3.connect(DATABASE_PATH)
    con.execute("INSERT OR IGNORE INTO users (username, password, role) VALUES ('legacy_user', 'legacy-plain-1', 'user')")
    con.commit()
    c = app.test_client()
    assert c.post("/login", data={"username": "legacy_user", "password": "legacy-plain-1"}).status_code == 302
    stored = con.execute("SELECT password FROM users WHERE username='legacy_user'").fetchone()[0]
    assert stored.startswith(("scrypt:", "pbkdf2:"))
    assert con.execute("SELECT password FROM users WHERE username='pytest_user'").fetchone()[0].startswith(("scrypt:", "pbkdf2:"))
    con.close()


def test_capability_registry_and_no_simulated_demo_by_default(client):
    caps = client.get("/api/capabilities").get_json()
    assert caps["status_map"]["email"] in ("ACTIVE", "IN_DEVELOPMENT") and caps["status_map"]["qr"] == "COMING_SOON"
    assert caps["simulated_demos_enabled"] is False
    r = client.post("/api/webpage/investigate", json={"url": "https://auth-portal-update.demo/login"})
    j = r.get_json()
    assert j.get("simulated") is False and j.get("webpage_status") == "UNAVAILABLE"


def test_digit_in_domain_is_not_a_hard_phishing_rule():
    from backend.app import classify_url
    pred, prob = classify_url("https://office365.com")
    assert "rule match" not in pred.lower() and prob is not None


def test_ssrf_blocks_private_targets():
    from model.webpage_intelligence.fetcher import safe_fetch_webpage
    for u in ("http://127.0.0.1/", "http://169.254.169.254/latest/meta-data", "http://10.0.0.1/", "http://localhost:5000/"):
        assert safe_fetch_webpage(u)["fetch_status"] in ("SSRF_BLOCKED", "DNS_FAILURE")


def test_redirect_to_private_ip_blocked_before_connecting(monkeypatch):
    """The fetcher must validate a redirect target BEFORE requesting it."""
    import requests
    from model.webpage_intelligence import fetcher
    calls = []

    class FakeResp:
        status_code, url, is_redirect = 302, "https://public.example/", True
        headers = {"Location": "http://127.0.0.1:8080/admin"}
        raw = None
        history = []
        def close(self): pass

    def fake_get(self, url, **kw):
        calls.append(url)
        assert kw.get("allow_redirects") is False
        return FakeResp()

    monkeypatch.setattr(fetcher, "_validate_url", lambda u: (True, u, "OK"))
    monkeypatch.setattr(requests.Session, "get", fake_get)
    r = fetcher.safe_fetch_webpage("https://public.example/")
    assert r["fetch_status"] == "SSRF_BLOCKED" and "127.0.0.1" in r["fetch_status_detail"]
    assert calls == ["https://public.example/"]   # the private target was never requested
