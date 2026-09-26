"""
Comprehensive verification test script for NeuraShield Module 2: Domain Intelligence.
Tests:
1. GET /domain-intelligence
2. POST /api/domain/analyze for khanacademy.org (verifying domain age, SSL transport verified, auditable vector, 6 telemetry categories)
3. POST /api/domain/analyze for nonexistent domain (verifying NXDOMAIN graceful handling)
4. SSRF security policy block (127.0.0.1, localhost -> 403)
5. POST /api/scan integration (verifying Module 1 + Module 2 risk fusion and investigation)
6. GET /api/investigation/<id> and GET /report?id=<id> verification
"""
import urllib.request
import urllib.error
import json
import sys

BASE_URL = "http://127.0.0.1:5000"

def post_json(path, payload):
    data = json.dumps(payload).encode('utf-8')
    req = urllib.request.Request(
        f"{BASE_URL}{path}",
        data=data,
        headers={"Content-Type": "application/json"}
    )
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            return resp.status, json.loads(resp.read().decode('utf-8'))
    except urllib.error.HTTPError as e:
        body = e.read().decode('utf-8')
        try:
            return e.code, json.loads(body)
        except Exception:
            return e.code, {"raw_error": body}
    except Exception as e:
        return 0, {"error": str(e)}

def get_url(path):
    req = urllib.request.Request(f"{BASE_URL}{path}")
    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            return resp.status, resp.read().decode('utf-8')
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode('utf-8')
    except Exception as e:
        return 0, str(e)

def run_tests():
    print("================================================================")
    print("NEURASHIELD MODULE 2 COMPREHENSIVE VERIFICATION")
    print("================================================================")

    passed = 0
    total = 6

    # Test 1: GET /domain-intelligence
    print("\n[TEST 1] GET /domain-intelligence (standalone interface)")
    status, body = get_url("/domain-intelligence")
    if status == 200 and ("Domain" in body or "Intelligence" in body):
        print("  [PASS] Standalone Domain Intelligence interface rendered successfully (HTTP 200).")
        passed += 1
    else:
        print(f"  [FAIL] Status: {status}, preview: {str(body)[:100]}")

    # Test 2: POST /api/domain/analyze - Legitimate Domain (khanacademy.org)
    print("\n[TEST 2] POST /api/domain/analyze (Target: khanacademy.org)")
    status, res = post_json("/api/domain/analyze", {"domain": "khanacademy.org", "refresh": True})
    if status == 200:
        telemetry = res.get("domain_intelligence", {})
        reg = telemetry.get("registration", {})
        ssl_info = telemetry.get("ssl", {})
        dns_info = telemetry.get("dns", {})
        categories = telemetry.get("telemetry_categories", {})
        ml = res.get("domain_ml", {})
        prob_disp = ml.get("probability_display", "")

        age_days = reg.get("domain_age_days")
        print(f"  - Domain Age Days: {age_days}")
        print(f"  - WHOIS Creation Date: {reg.get('creation_date')}")
        print(f"  - SSL Transport State: {ssl_info.get('transport_state')}")
        print(f"  - SSL Valid: {ssl_info.get('ssl_valid')}")
        print(f"  - ML Probability Display: '{prob_disp}' (Raw prob: {ml.get('probability')})")
        print(f"  - SSRF Policy: {telemetry.get('ssrf_policy')}")
        print(f"  - Telemetry Categories Count: {len(categories)}")
        print(f"  - Auditable Features Count: {len(res.get('features_auditable', []))}")

        test2_ok = (
            age_days is not None and age_days > 3000 and
            (ssl_info.get("transport_state") == "CERTIFICATE_VALID" or ssl_info.get("transport_status") == "CERTIFICATE_VALID") and
            (prob_disp in ["<1%", "0.0%", "0.1%"] or (prob_disp != "0%" and prob_disp != "")) and
            len(categories) == 6 and
            len(res.get("features_auditable", [])) > 20
        )
        if test2_ok:
            print("  [PASS] Real telemetry verified without fabrication; age, SSL transport, ML calibration valid.")
            passed += 1
        else:
            print(f"  [FAIL] Telemetry validation check failed.")
    else:
        print(f"  [FAIL] HTTP {status} - {res}")

    # Test 3: POST /api/domain/analyze - NXDOMAIN (nonexistent domain)
    print("\n[TEST 3] POST /api/domain/analyze (Target: nxdomain-nonexistent-xyz987654.org)")
    status, res = post_json("/api/domain/analyze", {"domain": "nxdomain-nonexistent-xyz987654.org", "refresh": True})
    if status == 200:
        dns_st = res.get("domain_intelligence", {}).get("dns", {}).get("collection_status")
        print(f"  - DNS Collection Status: {dns_st}")
        if dns_st in ["nxdomain", "timeout", "no_nameservers"]:
            print("  [PASS] Nonexistent domain handled gracefully with structured DNS state.")
            passed += 1
        else:
            print(f"  [FAIL] Unexpected DNS status {dns_st}")
    else:
        print(f"  [FAIL] HTTP {status} - {res}")

    # Test 4: SSRF Security Policy Protection
    print("\n[TEST 4] SSRF Security Protection (Target: 127.0.0.1, localhost)")
    status_ip, res_ip = post_json("/api/domain/analyze", {"domain": "127.0.0.1"})
    status_lh, res_lh = post_json("/api/domain/analyze", {"domain": "localhost"})
    print(f"  - 127.0.0.1 response code: {status_ip}")
    print(f"  - localhost response code: {status_lh}")
    if status_ip == 403 and status_lh == 403:
        print("  [PASS] Both loopback/private destinations blocked by SSRF policy with HTTP 403.")
        passed += 1
    else:
        print("  [FAIL] SSRF protection failed to enforce HTTP 403.")

    # Test 5: POST /api/scan (Unified Module 1 + Module 2 Scan Flow)
    print("\n[TEST 5] POST /api/scan (Full Pipeline Target: https://www.khanacademy.org)")
    status, res = post_json("/api/scan", {"url": "https://www.khanacademy.org"})
    inv_id = None
    if status == 200:
        inv = res.get("investigation", {})
        inv_id = inv.get("investigation_id")
        d_intel = inv.get("domain_intelligence", {})
        coverage = inv.get("coverage", {})
        fusion = inv.get("risk_fusion", {})

        print(f"  - Investigation ID: {inv_id}")
        print(f"  - Prediction: {inv.get('risk', {}).get('prediction')}")
        print(f"  - Composite Score: {inv.get('risk', {}).get('composite_score')}")
        print(f"  - Coverage: {coverage.get('completed')}/{coverage.get('total_applicable')} capabilities active")
        print(f"  - Fusion Weights: {[str(l.get('name')) + ': ' + str(round(float(l.get('weight', 0))*100)) + '%' for l in fusion.get('layers', [])]}")
        print(f"  - Domain Intel Present: {d_intel is not None and bool(d_intel)}")

        if inv_id and d_intel and coverage.get("completed", 0) >= 6:
            print("  [PASS] Unified scan produced correlated investigation with Module 2 layers.")
            passed += 1
        else:
            print("  [FAIL] Scan did not produce complete correlation.")
    else:
        print(f"  [FAIL] HTTP {status} - {res}")

    # Test 6: Report Page & Investigation API
    print("\n[TEST 6] GET /report and GET /api/investigation/<id>")
    if inv_id:
        status_rep, html_rep = get_url(f"/report?id={inv_id}")
        status_api, api_data = get_url(f"/api/investigation/{inv_id}")
        print(f"  - Report Page HTTP Status: {status_rep}")
        print(f"  - Investigation API HTTP Status: {status_api}")
        if status_rep == 200 and status_api == 200 and "Threat Relationship Graph" in html_rep:
            print("  [PASS] Full threat investigation report renders successfully with Section 05 & Graph.")
            passed += 1
        else:
            print("  [FAIL] Report or API returned error status.")
    else:
        print("  [SKIP] No inv_id available from Test 5.")

    print("\n================================================================")
    print(f"SUMMARY: {passed}/{total} TESTS PASSED ({round(passed/total*100)}%)")
    print("================================================================")
    return passed == total

if __name__ == "__main__":
    success = run_tests()
    sys.exit(0 if success else 1)
