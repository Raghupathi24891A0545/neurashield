"""NeuraShield Module 9: Brand Impersonation Intelligence.

Provides evidence-grounded brand impersonation detection by correlating:
1. Claimed or inferred brand identity
2. Sender display name and email address
3. Source and destination domain registrations
4. Typo-squatting, Levenshtein distance, and brand token extraction
5. Webpage title, header, and visual/textual brand references
6. Presence of credential collection / password input on unauthorized origins

Strict Epistemic Integrity:
- Never conclude impersonation without supporting verifiable evidence.
- Verdicts:
  - CONSISTENT: Verified official domain and identity match.
  - POTENTIAL_IMPERSONATION: Claimed brand detected on an unverified third-party domain.
  - STRONG_IMPERSONATION_EVIDENCE: Brand claimed + unauthorized origin + active credential prompt.
  - INSUFFICIENT_EVIDENCE: No recognizable brand claim or insufficient infrastructure signals.
"""

import re
from typing import Any, Dict, List, Optional, Tuple


# Known protected brand profiles with official domains & known high-risk keywords
BRAND_PROFILES = {
    "google": {
        "name": "Google",
        "official_domains": ["google.com", "google.co.in", "accounts.google.com", "gmail.com", "googlemail.com"],
        "keywords": ["google", "gmail", "workspace", "drive", "google docs", "google verify"]
    },
    "microsoft": {
        "name": "Microsoft",
        "official_domains": ["microsoft.com", "office.com", "live.com", "outlook.com", "sharepoint.com", "login.microsoftonline.com"],
        "keywords": ["microsoft", "office365", "o365", "outlook", "onedrive", "sharepoint", "azure", "msft"]
    },
    "apple": {
        "name": "Apple",
        "official_domains": ["apple.com", "icloud.com", "appleid.apple.com"],
        "keywords": ["apple", "icloud", "apple id", "itunes"]
    },
    "paypal": {
        "name": "PayPal",
        "official_domains": ["paypal.com", "paypal-communication.com"],
        "keywords": ["paypal", "pay pal", "paypal dispute", "paypal security"]
    },
    "amazon": {
        "name": "Amazon",
        "official_domains": ["amazon.com", "amazon.in", "amazon.co.uk", "aws.amazon.com"],
        "keywords": ["amazon", "aws", "prime", "amazon pay", "amazon order"]
    },
    "netflix": {
        "name": "Netflix",
        "official_domains": ["netflix.com"],
        "keywords": ["netflix", "netflix membership", "netflix billing"]
    },
    "meta": {
        "name": "Meta / Facebook",
        "official_domains": ["facebook.com", "instagram.com", "whatsapp.com", "meta.com"],
        "keywords": ["facebook", "instagram", "whatsapp", "meta business"]
    },
    "tkr college": {
        "name": "TKR College of Engineering and Technology",
        "official_domains": ["tkrcet.ac.in", "tkrce.ac.in"],
        "keywords": ["tkr college", "tkrcet", "tkr educational society", "tkr exam cell"]
    }
}


def _levenshtein_distance(s1: str, s2: str) -> int:
    """Compute Levenshtein edit distance between two strings."""
    if len(s1) < len(s2):
        return _levenshtein_distance(s2, s1)
    if len(s2) == 0:
        return len(s1)

    previous_row = range(len(s2) + 1)
    for i, c1 in enumerate(s1):
        current_row = [i + 1]
        for j, c2 in enumerate(s2):
            insertions = previous_row[j + 1] + 1
            deletions = current_row[j] + 1
            substitutions = previous_row[j] + (c1 != c2)
            current_row.append(min(insertions, deletions, substitutions))
        previous_row = current_row
    return previous_row[-1]


def detect_brand_mentions(text: str) -> List[Tuple[str, str]]:
    """Scan text (subject, title, body, URL) for known brand references."""
    if not text:
        return []
    text_lower = text.lower()
    matches = []
    for brand_key, profile in BRAND_PROFILES.items():
        for kw in profile["keywords"]:
            if re.search(r'\b' + re.escape(kw) + r'\b', text_lower):
                matches.append((brand_key, profile["name"]))
                break
    return matches


def evaluate_brand_impersonation(
    target_url: Optional[str] = None,
    domain: Optional[str] = None,
    sender_email: Optional[str] = None,
    sender_name: Optional[str] = None,
    claimed_org: Optional[str] = None,
    page_title: Optional[str] = None,
    page_text: Optional[str] = None,
    has_password_field: bool = False,
    http_status: Optional[int] = None
) -> Dict[str, Any]:
    """Execute evidence-based brand analysis against observable indicators."""
    host = (domain or "").lower().strip()
    if not host and target_url:
        m = re.search(r'https?://([^/:\?#]+)', target_url)
        if m:
            host = m.group(1).lower()

    # Aggregate text for brand discovery
    combined_signals = " ".join([
        target_url or "",
        claimed_org or "",
        sender_name or "",
        page_title or "",
        (page_text or "")[:1500]
    ]).lower()

    # Identify candidate brands
    candidate_brands = detect_brand_mentions(combined_signals)
    if claimed_org:
        # Check if claimed_org directly matches any profile
        for bk, prof in BRAND_PROFILES.items():
            if bk in claimed_org.lower() or claimed_org.lower() in bk:
                if (bk, prof["name"]) not in candidate_brands:
                    candidate_brands.insert(0, (bk, prof["name"]))

    if not candidate_brands:
        return {
            "verdict": "INSUFFICIENT_EVIDENCE",
            "verdict_label": "No Recognizable Brand Claim Detected",
            "confidence": "HIGH",
            "risk_score": 0,
            "target_host": host,
            "claimed_brand": None,
            "official_domains": [],
            "evidence": [],
            "reasons": ["No protected corporate or institutional brand references were detected in the target context."]
        }

    # Analyze primary candidate
    primary_key, primary_name = candidate_brands[0]
    profile = BRAND_PROFILES.get(primary_key, {})
    official_domains = profile.get("official_domains", [])

    evidence_items = []
    reasons = []
    verdict = "INSUFFICIENT_EVIDENCE"
    risk_score = 0
    confidence = "HIGH"

    # Check 1: Is host an official domain?
    is_official_domain = any(host == od or host.endswith("." + od) for od in official_domains)

    # Check 2: Sender domain match (if email context)
    sender_dom = (sender_email.split("@")[1].lower()) if (sender_email and "@" in sender_email) else None
    sender_is_official = any(sender_dom == od or sender_dom.endswith("." + od) for od in official_domains) if sender_dom else None

    # Check 3: Typo-squatting / Brand keyword in host
    brand_token = primary_key.split()[0]
    brand_in_host = brand_token in host.replace("-", "").replace(".", "")
    typo_distance = None
    for od in official_domains:
        root_od = od.split(".")[0]
        root_host = host.split(".")[0]
        dist = _levenshtein_distance(root_host, root_od)
        if 1 <= dist <= 2 and len(root_od) >= 4:
            typo_distance = dist
            evidence_items.append({
                "source": "Brand Impersonation Intelligence",
                "observation": f"Domain '{host}' exhibits high lexical similarity (Levenshtein distance: {dist}) to official root '{root_od}'.",
                "significance": "HIGH",
                "verification_status": "VERIFIED"
            })
            reasons.append(f"Domain '{host}' mimics legitimate brand domain '{od}' (Typo-squatting signature).")
            break

    # Verdict synthesis
    if is_official_domain:
        verdict = "CONSISTENT"
        verdict_label = f"Verified Legitimate {primary_name} Asset"
        risk_score = 5
        reasons.append(f"Destination hostname '{host}' is an officially verified domain for {primary_name}.")
        evidence_items.append({
            "source": "Brand Impersonation Intelligence",
            "observation": f"Destination hostname '{host}' matches authorized domain list for {primary_name}.",
            "significance": "LOW",
            "verification_status": "VERIFIED"
        })
    else:
        # Not official domain, but brand is claimed
        if has_password_field:
            verdict = "STRONG_IMPERSONATION_EVIDENCE"
            verdict_label = f"Strong {primary_name} Impersonation Evidence (Credential Harvesting)"
            risk_score = 92
            reasons.append(f"Target presents {primary_name} branding and requests user credentials on unauthorized domain '{host}'.")
            evidence_items.append({
                "source": "Brand Impersonation Intelligence",
                "observation": f"Credential input field detected on unauthorized domain '{host}' referencing {primary_name}.",
                "significance": "CRITICAL",
                "verification_status": "VERIFIED"
            })
        elif brand_in_host or typo_distance:
            verdict = "POTENTIAL_IMPERSONATION"
            verdict_label = f"Potential {primary_name} Impersonation (Domain Mimicry)"
            risk_score = 75
            reasons.append(f"Domain '{host}' embeds {primary_name} brand tokens without authorized registration.")
            evidence_items.append({
                "source": "Brand Impersonation Intelligence",
                "observation": f"Domain '{host}' contains unauthorized brand identifier '{brand_token}'.",
                "significance": "HIGH",
                "verification_status": "VERIFIED"
            })
        else:
            verdict = "POTENTIAL_IMPERSONATION"
            verdict_label = f"Potential {primary_name} Reference on Third-Party Origin"
            risk_score = 50
            reasons.append(f"Context references {primary_name}, but originates from third-party host '{host}'.")

    # Correlate email sender mismatch
    if sender_dom and not sender_is_official and (claimed_org or any(bk in (sender_name or "").lower() for bk in BRAND_PROFILES)):
        reasons.append(f"Sender address '{sender_email}' does not match official {primary_name} email domains ({', '.join(official_domains[:2])}).")
        evidence_items.append({
            "source": "Brand Impersonation Intelligence",
            "observation": f"Sender claims affiliation with {primary_name} but transmits from unauthorized domain '@{sender_dom}'.",
            "significance": "HIGH",
            "verification_status": "VERIFIED"
        })
        if verdict != "STRONG_IMPERSONATION_EVIDENCE":
            verdict = "POTENTIAL_IMPERSONATION"
            risk_score = max(risk_score, 78)

    return {
        "verdict": verdict,
        "verdict_label": verdict_label,
        "confidence": confidence,
        "risk_score": risk_score,
        "claimed_brand": primary_name,
        "official_domains": official_domains,
        "target_host": host,
        "is_official_domain": is_official_domain,
        "typo_squatting_detected": typo_distance is not None,
        "has_credential_collection": has_password_field,
        "reasons": reasons,
        "evidence": evidence_items
    }
