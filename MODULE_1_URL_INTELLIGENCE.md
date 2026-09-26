# NEURASHIELD — MODULE 1: URL INTELLIGENCE SPECIFICATION & ARCHITECTURE

> **Module Status:** `IMPLEMENTED`  
> **Module Version:** `1.0.0`  
> **Feature Schema Version:** `url-v2`  
> **Platform:** NeuraShield — Adaptive Multi-Layer Cyber Threat Investigation & Resilience Platform  

---

## 1. Overview & Architecture

**Module 1 (URL Intelligence)** is the foundational analytical layer of NeuraShield. Rather than functioning as a black-box URL classifier, Module 1 extracts multi-dimensional structural, lexical, statistical, and deterministic signals from the target URL, executes a traceable Security Rule Engine, evaluates an inference-calibrated Random Forest machine learning model, and fuses these indicators into a preliminary Composite Threat Risk Assessment with explainable evidence.

```
                         [ TARGET URL INPUT ]
                                  │
                  ┌───────────────┴───────────────┐
                  ▼                               ▼
          Original URL Preserved          Normalized URL
                  │                               │
        ┌─────────┴───────────────────────────────┴─────────┐
        │       MODULE 1: 4 ANALYTICAL PROCESSING LAYERS     │
        │                                                   │
        │  [Layer 1] Structural Decomposition               │
        │            • Protocol, authority, domain, port    │
        │            • Subdomains & depth, path & queries   │
        │            • Raw IPv4/IPv6 host trap detection    │
        │                                                   │
        │  [Layer 2] Lexical & Obfuscation Intelligence     │
        │            • Shannon entropy (URL, Domain, Path)  │
        │            • Punycode (xn--) & Unicode homoglyphs │
        │            • Percent / Double-encoding (%25)      │
        │            • Target brand impersonation tokens    │
        │                                                   │
        │  [Layer 3] Deterministic Security Rule Engine     │
        │            • Traceable rule catalog (20+ rules)   │
        │            • Structured findings & severity flags │
        │            • Confidence-weighted scoring          │
        │                                                   │
        │  [Layer 4] Random Forest Machine Learning         │
        │            • 12-feature locked baseline vector    │
        │            • 100-tree ensemble probability        │
        │            • Fast-path rule pre-emption           │
        └─────────────────────────┬─────────────────────────┘
                                  │
                                  ▼
                [ COMPOSITE THREAT RISK FUSION ]
          Formula: Struct(20%) + Lex(30%) + Rules(25%) + ML(25%)
                                  │
                                  ▼
                [ EXPLAINABLE EVIDENCE GENERATION ]
                   • Structured WHAT, WHERE, WHY
                   • Top Contributing Threat Signals
                   • Explicit Operational Limitations
                                  │
                                  ▼
           [ SECTION 26 REUSABLE ARCHITECTURAL OUTPUT ]
             (Ready for Module 2: Domain Intelligence)
```

---

## 2. Feature Schema (`url-v2`)

Feature extraction is version-controlled to guarantee reproducibility and prevent training-inference feature drift.

### 2.1 Model-Locked Inference Features (`MODEL_FEATURE_KEYS`)
These 12 features match the exact order and types expected by the pre-trained scikit-learn Random Forest model:

| Key | Type | Description |
|---|---|---|
| `url_length` | Integer | Total character length of URL |
| `dot_count` | Integer | Total period (`.`) count in URL |
| `hyphen_count` | Integer | Total hyphen (`-`) count in URL |
| `at_count` | Integer | Total `@` symbol count (credential delimiter) |
| `question_count` | Integer | Total question mark (`?`) count |
| `equal_count` | Integer | Total equals sign (`=`) count |
| `digit_count` | Integer | Total numeric character count |
| `https` | Binary (0/1) | 1 if URL begins with https, 0 otherwise |
| `has_ip` | Binary (0/1) | 1 if hostname is a raw IPv4 address |
| `suspicious_word` | Binary (0/1) | 1 if any high-risk security keyword is found |
| `homograph` | Binary (0/1) | 1 if homoglyph or lookalike pattern detected |
| `digit_in_domain` | Binary (0/1) | 1 if digits appear inside the domain label |

### 2.2 Extended Intelligence Features
Extracted for in-depth analyst explainability, rule matching, and downstream consumption:
- **Structural:** `protocol`, `domain`, `subdomain`, `tld`, `domain_length`, `path`, `path_length`, `query`, `fragment`, `url_depth`, `subdomain_count`, `has_port`, `port_number`.
- **Lexical & Obfuscation:** `slash_count`, `ampersand_count`, `special_char_density`, `digit_ratio`, `percent_count`, `double_encoding`, `encoded_separators`, `nested_url`.
- **Statistical Entropy:** `url_entropy`, `domain_entropy`, `path_entropy`, `query_entropy` (calculated via Shannon entropy: $H(X) = -\sum P(x) \log_2 P(x)$).
- **Brand Intelligence:** `brand_in_domain`, `brand_list`, `brand_impersonation` (brand appears in subdomain/host but is not registered root domain).
- **Keywords & TLDs:** `suspicious_word_count`, `suspicious_word_list`, `suspicious_tld`, `is_url_shortener`, `has_redirect`, `query_params`.

---

## 3. Security Rule Engine Catalog

The deterministic Rule Engine is defined in `model/rule_engine.py`. Each triggered rule produces an auditable, structured finding:

```json
{
  "rule_id": "BRAND-001",
  "category": "Brand Impersonation Signal",
  "severity": "CRITICAL",
  "title": "Targeted Brand Impersonation",
  "description": "A recognized high-value brand name appears in the subdomain or host but is not the root domain.",
  "evidence": "Brand token 'paypal' found in host 'secure-paypal.xyz' without matching registered domain.",
  "confidence": 0.92
}
```

### Full Rule Catalog:

| Rule ID | Category | Severity | Title |
|---|---|---|---|
| `HOMO-001` | Unicode / Homoglyph | **CRITICAL** | Homoglyph / Visual Confusable Attack |
| `BRAND-001` | Brand Impersonation | **CRITICAL** | Targeted Brand Impersonation |
| `STRUC-001` | IP Host | **HIGH** | Direct IP Address Hostname |
| `IDN-001` | Unicode / Punycode | **HIGH** | Punycode / IDN Encoded Domain (`xn--`) |
| `ENCOD-001` | Encoding & Obfuscation | **HIGH** | Double URL Percent-Encoding (`%25`) |
| `REDIR-002` | Redirect / Nesting | **HIGH** | Open Redirect Parameter Pattern |
| `REDIR-003` | Redirect / Nesting | **HIGH** | Nested Destination URL in Query |
| `STRUC-002` | Credential Targeting | **HIGH** | Credential Delimiter (`@` Symbol) |
| `LEXI-002` | Domain Syntax | **HIGH** | Digit Substitution in Hostname |
| `KW-001` | Credential Targeting | **HIGH** | Suspicious Keyword Cluster (2+ tokens) |
| `KW-002` | Keyword Anomaly | **MEDIUM** | Suspicious Keyword Present |
| `TLD-001` | Domain Syntax | **MEDIUM** | High-Abuse Top-Level Domain (TLD) |
| `REDIR-001` | Redirect / Nesting | **MEDIUM** | URL Shortener Intermediary |
| `STRUC-003` | URL Structure | **MEDIUM** | Excessive Subdomain Depth (3+ levels) |
| `STRUC-004` | Suspicious Port | **MEDIUM** | Non-Standard Web Service Port |
| `ENCOD-002` | Encoding & Obfuscation | **MEDIUM** | Obfuscated Path Separators (`%2F`, `%3A`) |
| `LEXI-006` | Anomaly | **MEDIUM** | Elevated Domain Character Entropy (>3.6) |
| `STRUC-005` | URL Structure | **LOW** | Elevated URL Length (>75 chars) |
| `STRUC-006` | URL Structure | **LOW** | Deep Path Hierarchy (>4 segments) |
| `LEXI-007` | Domain Syntax | **LOW** | Excessive Domain Hyphenation (2+ hyphens) |

---

## 4. Machine Learning & Probability Calibration

- **Model Type:** Random Forest Classifier (100 estimators).
- **Artifact:** `model/phishing_model.pkl`.
- **Pre-emption Fast-Path:** Severe deterministic rules (e.g. homograph attack, digit spoofing) pre-empt the ML classifier to ensure zero false negatives on known adversarial signatures.
- **Probability Usage:** Model class probability is reported as `probability` (e.g. `99.07%`) and distinguishes raw classifier probability from overall multi-layer threat confidence.

---

## 5. Composite Risk Fusion Scoring

Module 1 calculates a weighted preliminary risk score:

$$\text{Composite Risk} = 0.20 \times S_{\text{structural}} + 0.30 \times S_{\text{lexical}} + 0.25 \times S_{\text{rules}} + 0.25 \times S_{\text{ml}}$$

### Severity Level Thresholds:
- **`CRITICAL`**: Score $\ge 70$ (or any CRITICAL security rule triggered)
- **`HIGH`**: $45 \le \text{Score} < 70$ (or any HIGH security rule triggered)
- **`MEDIUM`**: $20 \le \text{Score} < 45$
- **`LOW`**: $\text{Score} < 20$

---

## 6. Structured Evidence Format (WHAT, WHERE, WHY)

Every detected threat indicator generates structured evidence for SOC analysts:
```json
{
  "signal": "double_url_encoding",
  "severity": "high",
  "source": "url_intelligence",
  "what": "Double percent-encoding (%25) present in target URL.",
  "where": "URL string / query parameters",
  "why": "Double encoding is often used to bypass Web Application Firewalls and boundary inspection filters."
}
```

---

## 7. API Contracts

### 7.1 Single URL Analysis (`POST /api/scan` & `POST /api/demo-scan`)
**Request Body:**
```json
{
  "url": "http://secure-paypal-login.verify-account.xyz/update"
}
```

**Response Body (Unified Section 26 Schema):**
```json
{
  "url": "http://secure-paypal-login.verify-account.xyz/update",
  "prediction": "Phishing",
  "probability": 100.0,
  "target": {
    "original_url": "http://secure-paypal-login.verify-account.xyz/update",
    "normalized_url": "http://secure-paypal-login.verify-account.xyz/update"
  },
  "url_intelligence": {
    "parsed_components": {
      "protocol": "http",
      "domain": "secure-paypal-login.verify-account.xyz",
      "subdomain": "secure-paypal-login",
      "tld": ".xyz",
      "port": 80,
      "path": "/update",
      "query": "",
      "fragment": "",
      "url_depth": 1
    },
    "features": { ... },
    "entropy": {
      "url_entropy": 4.1873,
      "domain_entropy": 3.6645,
      "path_entropy": 2.1281,
      "query_entropy": 0.0
    },
    "encoding": {
      "percent_count": 0,
      "double_encoding": false,
      "encoded_separators": false,
      "nested_url": false
    },
    "unicode": {
      "punycode": false,
      "non_ascii_count": 0,
      "homograph": false
    },
    "rules": [ ... ],
    "evidence": [ ... ],
    "top_signals": [
      "High-profile brand 'paypal' detected outside registered domain.",
      "High-risk keyword cluster: login, verify, account, secure.",
      "Abuse-prone TLD extension .xyz."
    ],
    "risk": {
      "composite_risk": 73,
      "composite_level": "CRITICAL",
      "structural_score": 10,
      "lexical_score": 82,
      "rules_score": 100,
      "ml_score": 100
    },
    "ml": {
      "prediction": "Phishing",
      "probability": 100.0,
      "method": "Random Forest ML",
      "model_version": "1.0.0",
      "feature_schema_version": "url-v2"
    }
  },
  "metadata": {
    "analysis_timestamp": "2026-09-18T10:03:09.123456",
    "module_version": "1.0.0",
    "feature_schema_version": "url-v2"
  },
  "limitations": [
    "URL-level analysis does not verify live DNS resolution or IP routing.",
    "Domain registration age and WHOIS ownership are handled by Domain Intelligence (Module 2).",
    "Webpage DOM inspection and SSL certificates are handled by Webpage Intelligence (Module 3).",
    "Email sender verification (SPF/DKIM/DMARC) is handled by Email Intelligence (Module 4)."
  ],
  "composite_risk": 73,
  "composite_level": "CRITICAL"
}
```

### 7.2 Bulk CSV Scan (`POST /api/bulk-scan`)
- Accepts standard CSV with `url` column.
- Processes each entry through the 4 analytical layers.
- Returns batch summary metrics + array of itemized results with embedded `intel` payloads.

---

## 8. Frontend Synchronization Matrix

| Frontend Page | Synchronization Status | Implementation Details |
|---|---|---|
| `landing.html` | **SYNCHRONIZED** | Architecture flow: Module 1 active, future modules marked planned. Interactive demo renders URL breakdown, composite gauge, 4 layer cards, signal breakdown, login CTA. |
| `user_dashboard.html` | **SYNCHRONIZED** | Neural scan visualizer (4 stages), real-time composite risk gauge, 4 analytical layer cards, exportable report actions, recent operations feed. |
| `admin_dashboard.html` | **SYNCHRONIZED** | 4-stage pipeline visualizer, elevated quick scan result card with full 4-layer breakdown, traceable rules hit, and limitations notice. |
| `upload.html` | **SYNCHRONIZED** | Re-labeled to Module 1's 4 Analytical Layers; interactive "Inspect ▾" row drawer to inspect individual intelligence breakdowns. |
| `neurashield.css` | **SYNCHRONIZED** | Dedicated `.m1-*` design system classes, responsive grids, severity badges, elevated buttons with 3D lift. |

---

## 9. Limitations Disclosure

As required by Section 25 & 54 of the Master Design Document:
- Module 1 performs **URL-level intelligence** only.
- It does not verify live DNS resolution or IP routing.
- It does not verify domain registration age or WHOIS ownership (handled by **Module 2: Domain Intelligence**).
- It does not inspect live webpage DOM, HTML forms, or SSL/TLS certificates (handled by **Module 3: Webpage Intelligence**).
- It does not inspect email headers or SPF/DKIM/DMARC (handled by **Module 4: Email Intelligence**).

---

## 10. Verification & Test Execution

Run the complete test suite anytime from the project root:
```bash
python test_module1_full.py
```
Outputs passing checks for:
1. Server connectivity & brand consistency
2. Legitimate URL detection & low risk scoring
3. Brand impersonation & high-risk TLD phishing
4. Raw IP address as hostname detection
5. Non-standard port extraction
6. Punycode (IDN) homograph detection
7. Double percent-encoding detection
8. Malformed & edge-case URL handling
9. Section 26 unified JSON schema conformance
10. Evidence generation (WHAT, WHERE, WHY)
11. Bulk CSV upload processing
