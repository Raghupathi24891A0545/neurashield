"""Single source of truth for NeuraShield module status.

Landing page, dashboard, navigation and reports read this via /api/capabilities.
ACTIVE          = implemented end-to-end and reachable from the UI
IN_DEVELOPMENT  = partially implemented (limitations listed)
COMING_SOON     = planned, no working backend
"""
import os

ACTIVE, IN_DEVELOPMENT, COMING_SOON = "ACTIVE", "IN_DEVELOPMENT", "COMING_SOON"


def _email_ml_available() -> bool:
    here = os.path.dirname(os.path.abspath(__file__))
    root = os.path.abspath(os.path.join(here, ".."))
    base = os.path.join(root, "model", "email_intelligence")
    return os.path.exists(os.path.join(base, "email_text_model.pkl")) and os.path.exists(os.path.join(base, "email_model_card.json"))


def get_capabilities() -> dict:
    email_ml = _email_ml_available()
    modules = [
        {"key": "investigation_center", "name": "Investigation Center", "status": ACTIVE, "route": "/investigation-center",
         "summary": "Unified AI-powered cybersecurity investigation center coordinating URL, domain, webpage, email, and QR intelligence."},
        {"key": "investigation_history", "name": "Investigation History", "status": ACTIVE, "route": "/investigations",
         "summary": "Audit trail and archive of past multi-layer threat investigations and reports."},
        {"key": "url", "name": "URL Intelligence", "status": ACTIVE, "route": "/dashboard",
         "summary": "Structural, lexical and encoding analysis with security rules and a Random Forest model."},
        {"key": "domain", "name": "Domain Intelligence", "status": ACTIVE, "route": "/domain-intelligence",
         "summary": "Live DNS, IP, RDAP/WHOIS, nameserver and TLS evidence with domain rules and a domain model."},
        {"key": "webpage", "name": "Webpage Intelligence", "status": ACTIVE, "route": "/webpage-intelligence",
         "summary": "SSRF-guarded retrieval and static inspection of forms, scripts, iframes and resources."},
        {"key": "email", "name": "Email Intelligence", "status": ACTIVE if email_ml else IN_DEVELOPMENT, "route": "/email-intelligence",
         "summary": "Header, sender-consistency, SPF/DKIM/DMARC evidence, content, link and static attachment analysis.",
         "limitations": [] if email_ml else ["Email text ML model not trained yet — rules-only risk."]},
        {"key": "qr", "name": "QR Intelligence", "status": ACTIVE, "route": "/investigation-center?type=qr",
         "summary": "Decode QR payloads and automatically route payload to URL, domain, email, or credential analysis."},
        {"key": "brand", "name": "Brand Impersonation", "status": ACTIVE, "route": "/brand-impersonation",
         "summary": "Evidence-grounded brand impersonation and typo-squatting detection against authorized institutional and corporate registries."},
        {"key": "dna", "name": "Threat DNA", "status": ACTIVE, "route": "/investigation-center#dna",
         "summary": "Evidence-derived genetic threat fingerprints and attack archetype categorization."},
        {"key": "graph", "name": "Threat Relationship Graph", "status": ACTIVE, "route": "/investigation-center#graph",
         "summary": "Interactive multi-entity relationship graph mapping evidence connections."},
        {"key": "threat_intel", "name": "Threat Intelligence", "status": ACTIVE, "route": "/threat-intelligence",
         "summary": "Threat intelligence lookup, indicator enrichment, and multi-source reputation analysis."},
        {"key": "monitoring", "name": "Continuous Monitoring", "status": ACTIVE, "route": "/monitoring",
         "summary": "Automated baseline tracking and change detection for domains, IP addresses, SSL certificates, and web content."},
        {"key": "incident_response", "name": "Incident Response", "status": ACTIVE, "route": "/threat-intelligence#incidents",
         "summary": "Case and incident management with evidence preservation and response guidance."},
        {"key": "reports", "name": "Reports", "status": ACTIVE, "route": "/investigations",
         "summary": "Comprehensive forensic investigation reports with 22-section forensic dossiers and JSON export packages."},
        {"key": "evidence_packages", "name": "Evidence Packages", "status": ACTIVE, "route": "/evidence-packages",
         "summary": "Official-ready forensic evidence dossiers with SHA-256 integrity seal for cybercrime reporting."},
        {"key": "resilience", "name": "Adversarial Resilience Lab", "status": ACTIVE, "route": "/adversarial-resilience",
         "summary": "Controlled defensive perturbation testing evaluating detection robustness against obfuscation and evasion."},
        {"key": "self_audit", "name": "Model Self-Audit", "status": ACTIVE, "route": "/model-self-audit",
         "summary": "Real evaluation metrics (Precision, Recall, F1, ROC-AUC, FPR, Confusion Matrix) and drift auditing."},
        {"key": "analytics", "name": "Security Analytics", "status": ACTIVE, "route": "/security-analytics",
         "summary": "Aggregated security telemetry computed strictly from real stored database investigations."},
        {"key": "news", "name": "Cybersecurity News", "status": ACTIVE, "route": "/cybersecurity-news",
         "summary": "Verified threat advisories and security intelligence from authoritative sources (CISA, CERT-In, NIST)."},
    ]
    return {
        "modules": modules,
        "status_map": {m["key"]: m["status"] for m in modules},
        "simulated_demos_enabled": os.environ.get("NEURASHIELD_SIMULATED_DEMOS") == "1",
    }
