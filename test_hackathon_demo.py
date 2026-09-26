"""
Test script to verify all 3 Hackathon Demo Showcase stories in NeuraShield:
1. Demo 1: The "Aha!" Story (auth-portal-update.demo/login)
2. Demo 2: The Existence Guard (nonexistent-phishing-host.org)
3. Demo 3: Threat DNA Campaign Correlation (support-login-apple.demo & icloud-session-check.demo)
"""
import sys
import os
import unittest
import json

project_root = os.path.abspath(os.path.dirname(__file__))
sys.path.insert(0, project_root)

from backend.app import app

class TestHackathonDemoShowcase(unittest.TestCase):
    def setUp(self):
        self.client = app.test_client()
        self.client.testing = True

    def test_demo_1_aha_story(self):
        """Verify the 'Aha!' story: URL scanner fooled (24% risk) but Webpage layer catches exfiltration (95% risk)."""
        res = self.client.post("/api/webpage/investigate", json={"url": "https://auth-portal-update.demo/login"})
        self.assertEqual(res.status_code, 200)
        data = res.get_json()

        # Webpage must be AVAILABLE
        self.assertEqual(data.get("webpage_status"), "AVAILABLE")
        self.assertTrue(data.get("webpage_available"))

        # Form analysis must catch password field and cross-domain exfil
        wp = data.get("webpage_analysis", {})
        forms = wp.get("form_analysis", {})
        self.assertTrue(forms.get("has_password_field"))
        self.assertTrue(forms.get("has_cross_domain_action"))
        form_list = forms.get("forms", [])
        self.assertTrue(len(form_list) > 0)
        self.assertIn("exfil-cred-harvester.xyz", form_list[0].get("action", "") or form_list[0].get("action_domain", ""))

        # Webpage risk must be CRITICAL (>= 80)
        wp_risk = data.get("webpage_risk_score", 0)
        self.assertGreaterEqual(wp_risk, 80)

        # Composite risk must be elevated (blends 24% URL + 35% Domain + 80% Webpage)
        comp_risk = data.get("risk_score", 0)
        self.assertGreaterEqual(comp_risk, 50)

        # Showcase metadata must be present
        showcase = data.get("showcase_demo")
        self.assertIsNotNone(showcase)
        self.assertEqual(showcase.get("type"), "aha")
        self.assertIn("exfil-cred-harvester.xyz", showcase.get("exfil_target", ""))
        print("\n[OK] Demo 1 ('Aha!' Story) Passed:")
        print(f"     URL Risk: 24% -> Webpage Risk: {wp_risk}% -> Composite: {comp_risk}%")
        print(f"     Exfiltration detected to: {showcase.get('exfil_target')}")

    def test_demo_2_existence_guard(self):
        """Verify the Existence Guard: Dead/offline domain marked UNAVAILABLE with Reduced Evidence Coverage."""
        res = self.client.post("/api/webpage/investigate", json={"url": "https://nonexistent-phishing-host.org"})
        self.assertEqual(res.status_code, 200)
        data = res.get_json()

        # Webpage must be UNAVAILABLE
        self.assertEqual(data.get("webpage_status"), "UNAVAILABLE")
        self.assertFalse(data.get("webpage_available"))
        self.assertEqual(data.get("evidence_coverage_label"), "Reduced")
        self.assertEqual(data.get("evidence_coverage"), 0)

        # Webpage analysis must be empty / None
        wp = data.get("webpage_analysis", {})
        self.assertIsNone(wp.get("html_analysis"))
        self.assertIsNone(wp.get("form_analysis"))
        self.assertIsNone(wp.get("script_analysis"))

        # Showcase metadata must be present
        showcase = data.get("showcase_demo")
        self.assertIsNotNone(showcase)
        self.assertEqual(showcase.get("type"), "existence_guard")
        self.assertEqual(showcase.get("status"), "UNAVAILABLE")
        print("\n[OK] Demo 2 (Existence Guard) Passed:")
        print(f"     Status: {data.get('webpage_status')}, Reason: {data.get('webpage_reason')}")
        print(f"     Coverage: {data.get('evidence_coverage_label')} ({data.get('evidence_coverage')}%), Zero forms fabricated.")

    def test_demo_3_threat_dna_campaign(self):
        """Verify Threat DNA: Two distinct domains share the exact same NS-4C8E-92B1 Threat DNA fingerprint."""
        res_a = self.client.post("/api/webpage/investigate", json={"url": "https://support-login-apple.demo/verify"})
        self.assertEqual(res_a.status_code, 200)
        data_a = res_a.get_json()

        res_b = self.client.post("/api/webpage/investigate", json={"url": "https://icloud-session-check.demo/verify"})
        self.assertEqual(res_b.status_code, 200)
        data_b = res_b.get_json()

        dna_a = data_a.get("threat_dna")
        dna_b = data_b.get("threat_dna")

        self.assertIsNotNone(dna_a)
        self.assertIsNotNone(dna_b)
        self.assertEqual(dna_a, dna_b)
        self.assertEqual(dna_a, "NS-4C8E-92B1-FA07-E391")

        showcase_a = data_a.get("showcase_demo")
        self.assertEqual(showcase_a.get("type"), "threat_dna")
        self.assertEqual(showcase_a.get("threat_actor"), "Storm-0822 (Credential Harvester Syndicate)")

        print("\n[OK] Demo 3 (Threat DNA Campaign Correlation) Passed:")
        print(f"     Target A (support-login-apple.demo) DNA: {dna_a}")
        print(f"     Target B (icloud-session-check.demo) DNA: {dna_b}")
        print(f"     Identical Match: {dna_a == dna_b} (Actor: {showcase_a.get('threat_actor')})")

    def test_demo_4_identity_consistency(self):
        """Verify Demo 04: What The Page Claims vs What It Does (account-security-microsoft.demo/verify)."""
        res = self.client.post("/api/webpage/investigate", json={"url": "https://account-security-microsoft.demo/verify"})
        self.assertEqual(res.status_code, 200)
        data = res.get_json()

        # Webpage must be AVAILABLE
        self.assertEqual(data.get("webpage_status"), "AVAILABLE")
        self.assertTrue(data.get("webpage_available"))

        # Identity consistency payload must be present and marked INCONSISTENT
        idc = data.get("identity_consistency", {})
        self.assertIsNotNone(idc)
        self.assertEqual(idc.get("state"), "INCONSISTENT")
        self.assertEqual(idc.get("verdict"), "IDENTITY INCONSISTENCY DETECTED")

        # Claimed identity assertions
        claimed = idc.get("claimed_identity", {})
        self.assertEqual(claimed.get("page_title"), "Microsoft Account Security Verification")
        self.assertIn("microsoft", claimed.get("detected_brands", []))
        self.assertIn("login", claimed.get("login_language", []))

        # Observed behavior assertions
        observed = idc.get("observed_behavior", {})
        self.assertEqual(observed.get("page_registered_domain"), "account-security-microsoft.demo")
        self.assertTrue(observed.get("has_password_field"))
        self.assertTrue(observed.get("has_cross_domain_action"))
        self.assertIn("sync-telemetry-portal.xyz", observed.get("cross_domain_destinations", []))
        self.assertIn("cdn-metrics-tracker.xyz", observed.get("external_domains", []))

        # Showcase metadata must be present
        showcase = data.get("showcase_demo")
        self.assertIsNotNone(showcase)
        self.assertEqual(showcase.get("type"), "identity_mismatch")

        print("\n[OK] Demo 4 (What The Page Claims vs What It Does) Passed:")
        print(f"     Claimed: Title='{claimed.get('page_title')}', Brand='{claimed.get('detected_brands')}'")
        print(f"     Observed: Host='{observed.get('page_registered_domain')}', Exfil='{observed.get('cross_domain_destinations')}'")
        print(f"     Consistency State: {idc.get('state')} -> {idc.get('verdict')}")

if __name__ == "__main__":
    unittest.main()
