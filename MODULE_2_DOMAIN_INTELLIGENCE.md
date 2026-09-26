# NEURASHIELD — MODULE 2: DOMAIN INTELLIGENCE & INFRASTRUCTURE ANALYSIS SPECIFICATION & ARCHITECTURE

> **Module Status:** `IMPLEMENTED`  
> **Module Version:** `2.0.0`  
> **Feature Schema Version:** `domain-v1`  
> **Platform:** NeuraShield — Adaptive Multi-Layer Cyber Threat Investigation & Resilience Platform  

---

## 1. Overview & Architecture

**Module 2 (Domain Intelligence & Infrastructure Analysis)** expands NeuraShield beyond static URL lexical boundaries into live network telemetry, domain registration verification, cryptographic validation, and infrastructure graph correlation. 

Module 2 systematically queries and evaluates authoritative infrastructure across **6 Analytical Categories**, enforces strict Server-Side Request Forgery (SSRF) controls, runs a deterministic 10-rule security engine, executes a calibrated machine learning model (32 engineering features), and dynamically fuses these signals into the NeuraShield Composite Threat Risk Engine (30% weight allocation).

```
                            [ TARGET DOMAIN / URL INPUT ]
                                          │
                         ┌────────────────┴────────────────┐
                         ▼                                 ▼
                 Registered Domain Extraction         SSRF Security Gate
                 (tldextract root isolation)       (Block private/cloud IPs)
                         │                                 │
                         └────────────────┬────────────────┘
                                          │
         ┌────────────────────────────────┴────────────────────────────────┐
         │             MODULE 2: 6 TELEMETRY & ANALYTICAL CATEGORIES       │
         │                                                                 │
         │  [Category 1] DNS Resolution & Routing                          │
         │               • A, AAAA, MX, NS, TXT record enumeration         │
         │               • Multi-homed IP distribution & IPv6 deployment   │
         │                                                                 │
         │  [Category 2] Domain Registration & WHOIS Verification          │
         │               • Creation / Expiration timestamps                │
         │               • Domain registration age (days) & remaining life │
         │               • Authoritative registrar identification          │
         │                                                                 │
         │  [Category 3] SSL/TLS Cryptographic Validation                  │
         │               • Certificate validity, validity window, expiry   │
         │               • Subject Alternative Names (SAN) count           │
         │               • Hostname match & wildcard identification        │
         │               • Certificate authority & Free CA detection       │
         │                                                                 │
         │  [Category 4] Nameserver Infrastructure & Diversity             │
         │               • Authoritative NS count & diversity metric       │
         │               • Bulletproof / Disposable NS heuristic           │
         │                                                                 │
         │  [Category 5] Deterministic Security Rule Engine (DOM-001..010) │
         │               • Young domains (<30d), expired/invalid TLS       │
         │               • Missing MX, hostname mismatch, free CA pairing  │
         │                                                                 │
         │  [Category 6] Machine Learning Classification                   │
         │               • 32-feature normalized vector (`domain-v1`)      │
         │               • Calibrated probability output                   │
         └────────────────────────────────┬────────────────────────────────┘
                                          │
                         ┌────────────────┴────────────────┐
                         ▼                                 ▼
             [ COMPOSITE RISK FUSION ]         [ THREAT RELATIONSHIP GRAPH ]
            M1 (70%) + M2 Domain (30%)         Nodes: URL, Domain, IP, NS, SSL
                         │                     Edges: hosted_on, resolves_to,
                         ▼                            delegated_to, secured_by
            [ MULTI-LAYER THREAT DNA ]
        Cryptographic correlation hash
```

---

## 2. Feature Schema (`domain-v1`)

Module 2 extracts 32 continuous, discrete, and boolean features across infrastructure domains. All features are documented in `data/domain_intelligence/feature_definitions.json` and schema-locked in `model/domain_intelligence/feature_schema.json`.

### 2.1 Feature Dictionary (32 Features)

| Feature Name | Type | Unit / Range | Category | Description |
|---|---|---|---|---|
| `dns_resolution` | Boolean | 0 or 1 | DNS | 1 if domain resolved to at least one IPv4/IPv6 address |
| `a_record_count` | Integer | $\ge 0$ | DNS | Count of resolved IPv4 (A) records |
| `aaaa_record_count` | Integer | $\ge 0$ | DNS | Count of resolved IPv6 (AAAA) records |
| `mx_record_count` | Integer | $\ge 0$ | DNS | Count of Mail Exchange (MX) records |
| `ns_record_count` | Integer | $\ge 0$ | DNS | Count of authoritative nameserver records |
| `txt_record_count` | Integer | $\ge 0$ | DNS | Count of TXT records (SPF, DKIM, domain verification) |
| `ip_count` | Integer | $\ge 0$ | DNS | Total distinct IP addresses associated with domain |
| `has_mx` | Boolean | 0 or 1 | DNS | 1 if domain possesses valid mail routing records |
| `has_multiple_ips` | Boolean | 0 or 1 | DNS | 1 if domain resolves to $>1$ IP (CDN or load-balanced) |
| `domain_age_days` | Float | $\ge 0$ | WHOIS | Days elapsed since domain registration date |
| `domain_remaining_days` | Float | $\ge 0$ | WHOIS | Days until domain registration expiration |
| `registrar_present` | Boolean | 0 or 1 | WHOIS | 1 if authoritative registrar name was returned |
| `expiration_available` | Boolean | 0 or 1 | WHOIS | 1 if expiration date could be verified |
| `nameserver_count` | Integer | $\ge 0$ | NS | Number of active nameservers |
| `nameserver_diversity` | Float | $0.0 - 1.0$ | NS | Ratio of unique second-level domains among nameservers |
| `ssl_available` | Boolean | 0 or 1 | SSL/TLS | 1 if port 443 handshake succeeded and presented a cert |
| `ssl_valid` | Boolean | 0 or 1 | SSL/TLS | 1 if certificate is currently valid and unexpired |
| `certificate_age_days` | Float | $\ge 0$ | SSL/TLS | Days elapsed since certificate issuance (`notBefore`) |
| `certificate_remaining_days`| Float | $\ge 0$ | SSL/TLS | Days remaining until certificate expiration (`notAfter`) |
| `certificate_san_count` | Integer | $\ge 0$ | SSL/TLS | Total Subject Alternative Names (SANs) covered by cert |
| `certificate_hostname_match`| Boolean | 0 or 1 | SSL/TLS | 1 if domain name matches cert CN or SAN entries |
| `certificate_is_wildcard` | Boolean | 0 or 1 | SSL/TLS | 1 if certificate is a wildcard certificate (`*.domain`) |
| `tld_length` | Integer | $\ge 1$ | Syntax | Character length of top-level domain extension |
| `domain_name_length` | Integer | $\ge 1$ | Syntax | Character length of registered domain label |
| `domain_name_entropy` | Float | $\ge 0.0$ | Syntax | Shannon entropy of domain label characters |
| `domain_has_digits` | Boolean | 0 or 1 | Syntax | 1 if numeric digits appear in registered domain name |
| `domain_digit_ratio` | Float | $0.0 - 1.0$ | Syntax | Proportion of numeric characters in domain name |
| `domain_hyphen_count` | Integer | $\ge 0$ | Syntax | Count of hyphens in registered domain name |
| `dns_collection_success` | Boolean | 0 or 1 | Telemetry | 1 if DNS collection completed without hard timeouts |
| `whois_collection_success`| Boolean | 0 or 1 | Telemetry | 1 if WHOIS response was received and parsed |
| `ssl_collection_success` | Boolean | 0 or 1 | Telemetry | 1 if TLS handshake completed without socket timeout |
| `evidence_coverage` | Float | $0.0 - 1.0$ | Telemetry | Proportion of 3 primary telemetry sources successfully queried |

---

## 3. Security Rule Engine Catalog (`model/domain_intelligence/domain_rule_engine.py`)

Module 2 implements 10 deterministic security rules. Each triggered rule provides a structured finding with actionable evidence, category, severity, and confidence weight.

| Rule ID | Category | Severity | Title | Trigger Condition | Confidence |
|---|---|---|---|---|---|
| `DOM-001` | Domain Age | **HIGH** | Extremely Young Domain | `domain_age_days < 30` | 0.75 |
| `DOM-002` | Registration | **MEDIUM** | No Registrar Information Available | WHOIS query succeeded but registrar is absent | 0.50 |
| `DOM-003` | DNS | **MEDIUM** | No MX Records | Domain resolves via A records but has 0 MX records | 0.45 |
| `DOM-004` | SSL/TLS | **HIGH** | Certificate Hostname Mismatch | SSL certificate SAN/CN does not cover target domain | 0.80 |
| `DOM-005` | SSL/TLS | **MEDIUM** | Invalid or Expired Certificate | Certificate expired, not yet valid, or untrusted | 0.65 |
| `DOM-006` | Domain Lifecycle | **INFORMATIONAL** | Near Registration Expiry | `domain_remaining_days < 90` | 0.30 |
| `DOM-007` | DNS | **HIGH** | DNS Resolution Failed | Domain has no active A/AAAA records | 0.70 |
| `DOM-008` | DNS Infrastructure | **INFORMATIONAL** | Nameserver Provider Concentration | `nameserver_diversity <= 1` with multiple NS records | 0.25 |
| `DOM-009` | SSL/TLS | **MEDIUM** | No SSL/TLS Certificate Available | Port 443 closed or connection refused | 0.50 |
| `DOM-010` | Domain Age | **MEDIUM** | Young Domain with Free TLS | `domain_age_days < 90` AND free CA issuer (e.g. Let's Encrypt, ZeroSSL) | 0.60 |

---

## 4. Machine Learning Model & Evaluation

- **Model Type:** Scikit-Learn `LogisticRegression` (L2 regularization, balanced class weights).
- **Evaluated Models (5-Fold Cross-Validation):**
  - `LogisticRegression`: **Accuracy: 92.0%, Precision: 96.7%, Recall: 88.7%, F1: 0.9167, ROC-AUC: 0.9593** (Selected Best Model).
  - `RandomForestClassifier`: Accuracy: 83.6%, Precision: 89.1%, Recall: 81.3%, F1: 0.8456, ROC-AUC: 0.9670.
  - `HistGradientBoosting`: Accuracy: 48.2%, Precision: 22.2%, Recall: 40.0%, F1: 0.2857, ROC-AUC: 0.5000.
- **Model Artifact:** `model/domain_intelligence/domain_model.pkl`.
- **Top Predictive Features (Coefficients):**
  1. `txt_record_count` ($-1.031$): Absence of TXT/SPF records strongly correlates with disposable phishing infrastructure.
  2. `expiration_available` ($-0.952$): Valid registration lifecycle indicates legitimate operational domains.
  3. `mx_record_count` ($-0.680$): Legitimate enterprise domains maintain configured mail exchangers.
  4. `ssl_valid` ($-0.544$): Legitimate domains maintain compliant cryptographic configurations.
  5. `tld_length` ($+0.374$): Longer/niche gTLDs are disproportionately abused in phishing kits.
  6. `certificate_is_wildcard` ($+0.360$): Wildcard certificates frequently deployed to front throwaway subdomains.

---

## 5. Multi-Layer Composite Risk Fusion

With Module 2 active, the NeuraShield Composite Threat Risk Engine fuses both URL Intelligence (Module 1) and Domain Intelligence (Module 2):

$$\text{Composite Risk} = 0.15 \times S_{\text{structural}} + 0.20 \times S_{\text{lexical}} + 0.20 \times S_{\text{url\_rules}} + 0.15 \times S_{\text{url\_ml}} + 0.30 \times S_{\text{domain}}$$

Where $S_{\text{domain}}$ is calculated from Domain Rules (50%) and Domain ML (50%):
$$S_{\text{domain}} = 0.50 \times S_{\text{domain\_rules}} + 0.50 \times S_{\text{domain\_ml}}$$

### Severity Level Thresholds:
- **`CRITICAL`**: Score $\ge 70$ (or any CRITICAL security rule triggered)
- **`HIGH`**: $45 \le \text{Score} < 70$ (or any HIGH security rule triggered)
- **`MEDIUM`**: $20 \le \text{Score} < 45$
- **`LOW`**: $\text{Score} < 20$

---

## 6. Threat DNA & Infrastructure Graph

### 6.1 Multi-Layer Threat DNA Fingerprinting
NeuraShield synthesizes a deterministic SHA-256 fingerprint derived from correlated signals across URL and Domain intelligence:
$$\text{Threat DNA} = \text{SHA256}(\text{Signals}_{1..6} \parallel \text{Length} \parallel \text{Entropy} \parallel \text{Registrar} \parallel \text{Age} \parallel \text{CA} \parallel \text{IP})$$
Format: `NS-XXXX-XXXX-XXXX-XXXX` (e.g., `NS-A8F2-10E4-7B39-92C1`).

### 6.2 Threat Relationship Graph
Every investigation generates a structured node-edge graph mapping infrastructure relationships:
- **Node Types:** `url`, `domain`, `ip`, `nameserver`, `certificate`, `indicator`.
- **Edge Relationships:**
  - `url` $\xrightarrow{\text{hosted\_on}}$ `domain`
  - `domain` $\xrightarrow{\text{resolves\_to}}$ `ip`
  - `domain` $\xrightarrow{\text{delegated\_to}}$ `nameserver`
  - `domain` $\xrightarrow{\text{secured\_by}}$ `certificate`
  - `url` $\xrightarrow{\text{exhibits}}$ `indicator`

---

## 7. SSRF Protection & Security Hardening

Module 2 performs live network telemetry against untrusted user inputs. To prevent Server-Side Request Forgery (SSRF) and internal network reconnaissance, all inputs pass through strict IP and hostname validation before socket or DNS operations:

### Prohibited Address Ranges:
- IPv4 Loopback (`127.0.0.0/8`)
- RFC 1918 Private Subnets (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`)
- Link-Local Subnets (`169.254.0.0/16`)
- Cloud Metadata Services (`169.254.169.254`, `metadata.google.internal`)
- IPv6 Loopback (`::1`), Link-Local (`fe80::/10`), and Unique Local (`fc00::/7`)
- Multicast Ranges (`224.0.0.0/4`)

Any target matching these ranges is rejected immediately with HTTP `403 Forbidden` and logged with the security violation flag.

---

## 8. API Specifications

### 8.1 Standalone Domain Intelligence Analysis (`POST /api/domain/analyze`)
**Request Body:**
```json
{
  "domain": "secure-bank-login.xyz",
  "refresh": false
}
```

**Response Body:**
```json
{
  "domain": "secure-bank-login.xyz",
  "input": "secure-bank-login.xyz",
  "risk_score": 75,
  "risk_level": "CRITICAL",
  "domain_intelligence": {
    "domain": "secure-bank-login.xyz",
    "analysis_timestamp": "2026-09-20T07:05:00.000Z",
    "dns": {
      "has_dns": true,
      "a_records": ["198.51.100.45"],
      "mx_records": [],
      "txt_records": []
    },
    "registration": {
      "domain_age_days": 14,
      "registrar": "NameCheap, Inc."
    },
    "ssl": {
      "ssl_available": true,
      "ssl_valid": false,
      "certificate_issuer": "Let's Encrypt"
    },
    "nameservers": {
      "nameserver_list": ["ns1.dnshost.com", "ns2.dnshost.com"],
      "diversity": 1.0
    },
    "evidence_coverage": 1.0
  },
  "domain_rules": {
    "count": 3,
    "rules_hit": [
      {
        "rule_id": "DOM-001",
        "severity": "HIGH",
        "title": "Extremely Young Domain",
        "evidence": "Domain registered 14 days ago (< 30 days)."
      },
      {
        "rule_id": "DOM-003",
        "severity": "MEDIUM",
        "title": "No MX Records",
        "evidence": "Domain resolves to IP but has 0 MX records."
      }
    ],
    "risk_score": 70
  },
  "domain_ml": {
    "status": "success",
    "prediction": "Phishing",
    "probability": 0.88,
    "risk_score": 88
  },
  "coverage": 1.0
}
```

### 8.2 Unified Scan Endpoint (`POST /api/scan`)
Executes full multi-layer scan returning:
- `url_intelligence` (Module 1 breakdown)
- `domain_intelligence` (Module 2 telemetry)
- `risk_fusion` (Fused composite score & breakdown)
- `threat_dna` (Fingerprint)
- `threat_graph` (Relationship nodes and edges)
- `coverage` (Active capabilities: 6 of 7)

---

## 9. Frontend Synchronization Matrix

| Frontend View | Status | Integration Details |
|---|---|---|
| `frontend/domain_intelligence.html` | **ACTIVE** | Dedicated investigation dashboard with real-time domain query bar, 6 telemetry category cards, rule findings feed, raw features inspector, and radar score gauge. |
| `frontend/landing.html` | **SYNCHRONIZED** | Domain Intelligence feature card updated to "✓ Active Module"; interactive architecture flow node activated. |
| `frontend/user_dashboard.html` | **SYNCHRONIZED** | Added Domain Intel sidebar navigation; scan result card now displays live Domain Telemetry strip (Age, Registrar, IP, SSL) and 5-layer coverage badge. |
| `frontend/admin_dashboard.html` | **SYNCHRONIZED** | Added Domain Intel sidebar link; admin quick scan displays integrated domain risk metrics. |
| `frontend/upload.html` | **SYNCHRONIZED** | Bulk scanner UI updated with Domain Intel nav and multi-layer feature columns. |
| `frontend/report.html` | **SYNCHRONIZED** | Full Threat Investigation Report Section 05 ("Domain & Infrastructure Intelligence") promoted from placeholder to live data tables (DNS, WHOIS, SSL, NS, Rules) and Threat Relationship Graph canvas. |

---

## 10. Transparent Limitations & Data Disclosure

NeuraShield adheres to strict truth-in-reporting standards:
- **DNS Resolution Failures:** Clearly distinguished between unregistered domains, non-responsive authoritative servers, and network timeouts.
- **WHOIS Privacy / Redaction:** When registrant data is protected by GDPR or privacy guards, the system flags the presence of redaction rather than assuming missing ownership.
- **SSL Port Inaccessibility:** When port 443 is unreachable, the system transparently notes "No SSL service active" rather than inferring a malicious certificate.
- **Future Module Boundaries:**
  - Webpage DOM & form scraping handled by **Module 3: Webpage Intelligence**.
  - Email header and DKIM/SPF alignment handled by **Module 4: Email Intelligence**.

---

## 11. Verification & Test Execution

Run the complete verification suite from the project root:
```bash
python test_module2_full.py
```
Validates:
1. Flask app initialization & route registration
2. `GET /domain-intelligence` UI rendering
3. SSRF blocklist enforcement (`127.0.0.1`, `169.254.169.254`, etc. return `403 Forbidden`)
4. Real-time domain telemetry collection and categorization
5. Multi-layer risk fusion (Module 1 + Module 2 weights)
6. Threat Relationship Graph generation (nodes & edges)
7. SQLite database persistence in `domain_analyses` and `logs` tables
