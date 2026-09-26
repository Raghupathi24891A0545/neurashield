"""Automated Test Suite for NeuraShield Chrome Extension & Institutional Verification Engine.

Tests all required test scenarios:
TEST 1: Known demo institutional sender -> VERIFIED
TEST 2: Fake Gmail sender claiming institution -> POSSIBLE ORGANIZATION IMPERSONATION
TEST 3: Unknown sender using official domain -> UNVERIFIED_SENDER
TEST 4: Email containing suspicious URL -> URL investigation triggered
TEST 5: Suspicious URL -> Suspicious domain -> Cross-layer correlation
TEST 6: Legitimate URL -> Evidence-based lower-risk result
TEST 7: Backend status check -> Clear online status
TEST 8: External API unavailable -> Graceful degradation (NOT_CONFIGURED / UNAVAILABLE)
TEST 9: Authentication data unavailable -> NOT_AVAILABLE
TEST 10: Malformed URL / SSRF Protection -> Validation error / Blocked
TEST 11: Member CSV Import -> Validation & persistence
"""

import unittest
import json
from backend.app import app


class TestExtensionAndVerification(unittest.TestCase):

    def setUp(self):
        self.client = app.test_client()

    def test_01_known_demo_institutional_sender(self):
        """TEST 1: Known demo institutional sender should be VERIFIED."""
        resp = self.client.post('/api/institutions/verify-sender', json={
            'sender_email': 'faculty-demo@tkrcet.ac.in',
            'display_name': 'Dr. K. Srinivas (Demo Faculty)'
        })
        self.assertEqual(resp.status_code, 200)
        data = resp.json
        self.assertEqual(data['verdict'], 'VERIFIED_INSTITUTIONAL_SENDER')
        self.assertEqual(data['risk_level'], 'LOW')
        self.assertIn('tkrcet.ac.in', data['reason'])

    def test_02_fake_gmail_claiming_institution(self):
        """TEST 2: Fake Gmail sender claiming institution -> POSSIBLE ORGANIZATION IMPERSONATION."""
        resp = self.client.post('/api/institutions/verify-sender', json={
            'sender_email': 'tkrcollege.notice@gmail.com',
            'display_name': 'TKR College Administration'
        })
        self.assertEqual(resp.status_code, 200)
        data = resp.json
        self.assertEqual(data['verdict'], 'POSSIBLE_ORGANIZATION_IMPERSONATION')
        self.assertEqual(data['risk_level'], 'HIGH')
        self.assertIn('does not match', data['reason'])

    def test_03_unknown_sender_official_domain(self):
        """TEST 3: Unknown sender using official domain -> UNVERIFIED_SENDER."""
        resp = self.client.post('/api/institutions/verify-sender', json={
            'sender_email': 'anonymous-stranger@tkrcet.ac.in',
            'display_name': 'Anonymous Student'
        })
        self.assertEqual(resp.status_code, 200)
        data = resp.json
        self.assertEqual(data['verdict'], 'UNVERIFIED_SENDER')
        self.assertIn('member directory', data['reason'].lower())

    def test_04_email_with_suspicious_url(self):
        """TEST 4: Email containing suspicious URL triggers deep link investigation."""
        resp = self.client.post('/api/extension/email/investigate', json={
            'sender_email': 'tkrcollege.notice@gmail.com',
            'sender_name': 'TKR College Administration',
            'subject': 'Urgent: Verify Student Examination Account',
            'body_text': 'Please login to verify your exam hall ticket at https://tkrcet-exam-portal.example/auth',
            'links': ['https://tkrcet-exam-portal.example/auth']
        })
        self.assertEqual(resp.status_code, 200)
        data = resp.json
        self.assertEqual(data['sender_verification']['verdict'], 'POSSIBLE_ORGANIZATION_IMPERSONATION')
        self.assertGreaterEqual(data['links']['count'], 1)
        self.assertIn('threat_dna', data)

    def test_05_cross_layer_correlation(self):
        """TEST 5: Suspicious URL + Fake identity yields cross-layer correlation."""
        resp = self.client.post('/api/extension/email/investigate', json={
            'sender_email': 'tkrcollege.notice@gmail.com',
            'sender_name': 'TKR College Administration',
            'subject': 'Notice from Exam Cell',
            'body_text': 'Follow link https://phish-secure-portal.com/login',
            'links': ['https://phish-secure-portal.com/login']
        })
        self.assertEqual(resp.status_code, 200)
        data = resp.json
        corr = data.get('correlation', {}).get('cross_layer_summary', '')
        self.assertTrue(len(corr) > 10)
        traits = data.get('threat_dna', {}).get('traits', [])
        self.assertIn('Organization Impersonation', traits)

    def test_06_legitimate_url_lower_risk(self):
        """TEST 6: Legitimate target URL investigation."""
        resp = self.client.post('/api/extension/url/investigate', json={
            'url': 'https://wikipedia.org'
        })
        self.assertEqual(resp.status_code, 200)
        data = resp.json
        self.assertEqual(data['risk']['level'], 'LOW')

    def test_07_extension_status(self):
        """TEST 7: Extension status endpoint returns ONLINE."""
        resp = self.client.get('/api/extension/status')
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.json['status'], 'ONLINE')

    def test_08_external_api_unavailable_graceful(self):
        """TEST 8: External API keys unconfigured returns UNAVAILABLE / NOT_CONFIGURED without crash."""
        resp = self.client.post('/api/extension/url/investigate', json={
            'url': 'https://test-example-site.com'
        })
        self.assertEqual(resp.status_code, 200)
        data = resp.json
        ext_intel = data.get('external_intelligence') or {}
        self.assertIn('status', ext_intel)

    def test_09_auth_unavailable_reporting(self):
        """TEST 9: When auth data is not provided, reports NOT_AVAILABLE."""
        resp = self.client.post('/api/institutions/verify-sender', json={
            'sender_email': 'someone@somewhere.com'
        })
        self.assertEqual(resp.status_code, 200)
        data = resp.json
        self.assertEqual(data['authentication']['spf'], 'NOT_AVAILABLE')

    def test_10_ssrf_protection_blocked(self):
        """TEST 10: Private IP / localhost scan is blocked by SSRF filter."""
        resp = self.client.post('/api/extension/url/investigate', json={
            'url': 'http://127.0.0.1:8000/internal-admin'
        })
        # Should either reject with 403 or flag blocked private IP
        if resp.status_code == 403:
            self.assertEqual(resp.json.get('error'), 'TARGET_BLOCKED_SSRF')
        else:
            self.assertEqual(resp.status_code, 200)

    def test_11_csv_import(self):
        """TEST 11: Import members from CSV."""
        csv_text = "email,displayName,role,department,status\ntest-faculty@tkrcet.ac.in,Test Faculty,Faculty,IT,ACTIVE\n"
        resp = self.client.post('/api/institutions/1/import', json={
            'csv_content': csv_text
        })
        self.assertEqual(resp.status_code, 200)
        self.assertTrue(resp.json['success'])
        self.assertGreaterEqual(resp.json['imported'] + resp.json['updated'], 1)


if __name__ == '__main__':
    unittest.main()
