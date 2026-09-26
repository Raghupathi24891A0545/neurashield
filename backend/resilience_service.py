"""NeuraShield Module 16: Adversarial Resilience Lab Service.

Provides controlled defensive evaluation of detection robustness against:
- URL Obfuscation & Encoding Perturbations (Hex, Percent, Decimal IP, Multiple Slashes)
- Character Substitutions & Homoglyphs (0 -> o, 1 -> l, @ -> a)
- Lexical & Path Padding (Excessive subdomains, fake security tokens)
- Keyword & Brand Evasion (Brand token splitting, hyphenation)

Computes:
- Feature Shifts (exact delta between original and perturbed feature vectors)
- Rule Detection Persistence (which heuristic rules fired before vs after)
- Machine Learning Score Delta (model probability shift)
- Final Risk Evasion Status (STABLE_DETECTION, SENSITIVE_DEGRADATION, EVASION_OBSERVED)
"""

from datetime import datetime
import re
from typing import Any, Dict, List, Optional
from urllib.parse import quote, urlparse


class AdversarialResilienceService:
    def __init__(self, deps: Optional[Dict[str, Any]] = None):
        self.deps = deps or {}

    def get_supported_perturbations(self) -> List[Dict[str, Any]]:
        return [
            {
                "id": "HEX_ENCODING",
                "name": "Hexadecimal / Percent Obfuscation",
                "category": "Encoding",
                "description": "Encodes delimiter characters and brand tokens into percent-encoded hexadecimal representations."
            },
            {
                "id": "HOMOGLYPH_SUBSTITUTION",
                "name": "Homoglyph / Visual Spoofing",
                "category": "Lexical",
                "description": "Substitutes standard ASCII characters with visually confusable alternatives (e.g. 'o' -> '0', 'l' -> '1')."
            },
            {
                "id": "SUBDOMAIN_PADDING",
                "name": "Subdomain Chain Padding",
                "category": "Structure",
                "description": "Appends multiple deceptive subdomains (e.g. 'secure.login.portal.verify.') to dilute path inspection."
            },
            {
                "id": "DOUBLE_SLASH_INJECTION",
                "name": "Redirection & Double-Slash Injection",
                "category": "Path",
                "description": "Inserts path-delimiter bypasses (e.g. '//login//confirm') designed to bypass basic substring filters."
            },
            {
                "id": "KEYWORD_HYPHENATION",
                "name": "Keyword Token Hyphenation",
                "category": "Brand",
                "description": "Splits known security terms with hyphens (e.g. 'sec-ure-log-in') to evade exact word matches."
            }
        ]

    def apply_perturbation(self, original_url: str, perturbation_type: str) -> str:
        """Apply a controlled defensive perturbation to test detector resilience."""
        raw = original_url.strip()
        if not raw.startswith(("http://", "https://")):
            raw = "https://" + raw

        parsed = urlparse(raw)
        scheme = parsed.scheme or "https"
        host = parsed.hostname or raw
        path = parsed.path or ""
        query = ("?" + parsed.query) if parsed.query else ""

        if perturbation_type == "HEX_ENCODING":
            # Encode portions of path or host
            if path and len(path) > 2:
                perturbed_path = "".join(f"%{ord(c):02X}" if c.isalnum() and idx % 2 == 0 else c for idx, c in enumerate(path))
            else:
                perturbed_path = "/%73%65%63%75%72%65/%76%65%72%69%66%79"
            return f"{scheme}://{host}{perturbed_path}{query}"

        elif perturbation_type == "HOMOGLYPH_SUBSTITUTION":
            # Substitute visually similar chars in host/path
            rep_map = {"o": "0", "l": "1", "e": "3", "i": "1", "a": "4"}
            perturbed_host = "".join(rep_map.get(c, c) if idx % 3 == 0 else c for idx, c in enumerate(host))
            return f"{scheme}://{perturbed_host}{path}{query}"

        elif perturbation_type == "SUBDOMAIN_PADDING":
            return f"{scheme}://secure.auth.verify.account-update.{host}{path}{query}"

        elif perturbation_type == "DOUBLE_SLASH_INJECTION":
            clean_path = path.strip("/")
            return f"{scheme}://{host}///{clean_path}//verify//redirect{query}"

        elif perturbation_type == "KEYWORD_HYPHENATION":
            # Hyphenate common tokens in path
            hyphenated_path = path.replace("login", "log-in").replace("secure", "sec-ure").replace("verify", "ver-i-fy")
            if hyphenated_path == path:
                hyphenated_path = (path.rstrip("/") + "/sec-ure-log-in-con-firm")
            return f"{scheme}://{host}{hyphenated_path}{query}"

        return raw

    def run_resilience_test(self, original_url: str, perturbation_type: str) -> Dict[str, Any]:
        """Execute paired test between original and perturbed target."""
        extract_features = self.deps.get("extract_features")
        classify_url = self.deps.get("classify_url")
        rule_engine = self.deps.get("evaluate_security_rules")

        perturbed_url = self.apply_perturbation(original_url, perturbation_type)

        # 1. Run Original
        orig_features = extract_features(original_url) if extract_features else {}
        orig_pred, orig_prob = classify_url(original_url) if classify_url else ("Unknown", 0.5)
        orig_rules = rule_engine(original_url, orig_features) if rule_engine else {}

        # 2. Run Perturbed
        pert_features = extract_features(perturbed_url) if extract_features else {}
        pert_pred, pert_prob = classify_url(perturbed_url) if classify_url else ("Unknown", 0.5)
        pert_rules = rule_engine(perturbed_url, pert_features) if rule_engine else {}

        # 3. Compute Feature Diffs
        feature_shifts = []
        for k in set(orig_features.keys()) | set(pert_features.keys()):
            ov = orig_features.get(k)
            pv = pert_features.get(k)
            if ov != pv:
                feature_shifts.append({
                    "feature_name": k,
                    "original_value": ov,
                    "perturbed_value": pv,
                    "delta": (pv - ov) if isinstance(ov, (int, float)) and isinstance(pv, (int, float)) else None
                })

        # 4. Compare Rules Triggered
        orig_rule_ids = set(r.get("rule_id") for r in orig_rules.get("rules_hit", []))
        pert_rule_ids = set(r.get("rule_id") for r in pert_rules.get("rules_hit", []))

        persisted_rules = list(orig_rule_ids & pert_rule_ids)
        evaded_rules = list(orig_rule_ids - pert_rule_ids)
        new_triggered_rules = list(pert_rule_ids - orig_rule_ids)

        # 5. ML Probability Shift
        prob_delta = round((pert_prob or 0.0) - (orig_prob or 0.0), 4)

        # 6. Resilience Assessment
        # If original was detected as Phishing/Suspicious: did it stay detectable?
        orig_score = int((orig_prob or 0.0) * 100)
        pert_score = int((pert_prob or 0.0) * 100)

        if orig_score >= 50:
            if pert_score >= 50:
                resilience_status = "STABLE_DETECTION"
                assessment = "Detector remained resilient: Threat signals persisted through adversarial obfuscation."
            elif pert_score >= 35:
                resilience_status = "SENSITIVE_DEGRADATION"
                assessment = "Partial degradation: Threat confidence decreased under perturbation but remained flagged as suspicious."
            else:
                resilience_status = "EVASION_OBSERVED"
                assessment = "Adversarial evasion observed: Obfuscation successfully suppressed primary detection signals."
        else:
            resilience_status = "BENIGN_STABLE" if pert_score < 50 else "FALSE_POSITIVE_RISK"
            assessment = "Baseline target was benign; evaluated perturbation stability."

        return {
            "test_id": f"RES-{datetime.now().strftime('%Y%m%d%H%M%S')}",
            "perturbation_type": perturbation_type,
            "original": {
                "url": original_url,
                "prediction": orig_pred,
                "probability": orig_prob,
                "risk_score": orig_score,
                "rules_hit_count": len(orig_rules.get("rules_hit", [])),
                "rules": [r.get("rule_id") for r in orig_rules.get("rules_hit", [])]
            },
            "perturbed": {
                "url": perturbed_url,
                "prediction": pert_pred,
                "probability": pert_prob,
                "risk_score": pert_score,
                "rules_hit_count": len(pert_rules.get("rules_hit", [])),
                "rules": [r.get("rule_id") for r in pert_rules.get("rules_hit", [])]
            },
            "resilience": {
                "status": resilience_status,
                "assessment": assessment,
                "ml_probability_shift": prob_delta,
                "risk_score_delta": pert_score - orig_score,
                "feature_shifts_count": len(feature_shifts),
                "feature_shifts": feature_shifts[:15],
                "persisted_rules": persisted_rules,
                "evaded_rules": evaded_rules,
                "new_rules_triggered": new_triggered_rules
            },
            "timestamp": datetime.now().isoformat()
        }
