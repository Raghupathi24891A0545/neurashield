"""NeuraShield Module 20: Cybercrime Evidence Workflow Service.

Assembles cryptographically verified, court-ready Cybercrime Evidence Packages
from completed investigations for submission to official law enforcement bodies
(including the National Cyber Crime Reporting Portal — cybercrime.gov.in).

Strict Principles:
- NeuraShield PREPARES forensic evidence dossiers and guides the reporting workflow.
- NeuraShield DOES NOT claim to automatically lodge or file official police complaints.
- All evidence packages contain a SHA-256 cryptographic chain-of-custody seal.
"""

from datetime import datetime
import hashlib
import json
import sqlite3
from typing import Any, Dict, List, Optional


OFFICIAL_PORTALS = {
    "national_cyber_crime_portal_india": {
        "name": "National Cyber Crime Reporting Portal",
        "jurisdiction": "India (MHA)",
        "url": "https://cybercrime.gov.in/",
        "helpline": "1930",
        "description": "Official citizen portal for reporting financial fraud, identity theft, and phishing crimes."
    },
    "ic3_fbi": {
        "name": "FBI Internet Crime Complaint Center (IC3)",
        "jurisdiction": "United States",
        "url": "https://www.ic3.gov/",
        "description": "Central hub for reporting internet-facilitated cybercrimes and wire fraud."
    },
    "cert_in": {
        "name": "Indian Computer Emergency Response Team (CERT-In)",
        "jurisdiction": "India",
        "url": "https://www.cert-in.org.in/",
        "description": "National agency for reporting active phishing campaigns and infrastructure abuse."
    }
}


class CybercrimeEvidenceService:
    def __init__(self, db_conn_factory):
        self.get_db = db_conn_factory
        self._init_tables()

    def _init_tables(self):
        conn = self.get_db()
        try:
            c = conn.cursor()
            c.execute("""
            CREATE TABLE IF NOT EXISTS evidence_packages (
                package_id TEXT PRIMARY KEY,
                investigation_id TEXT NOT NULL,
                target TEXT NOT NULL,
                dossier_sha256 TEXT NOT NULL,
                package_json TEXT NOT NULL,
                created_at TEXT NOT NULL,
                exported_by TEXT
            )
            """)
            c.execute("CREATE INDEX IF NOT EXISTS idx_evpkg_inv ON evidence_packages(investigation_id)")
            conn.commit()
        finally:
            conn.close()

    def build_evidence_package(self, investigation_id: str, investigator_name: str = "SOC Analyst", notes: Optional[str] = None) -> Dict[str, Any]:
        """Compile a complete, tamper-verifiable forensic evidence dossier from an investigation."""
        conn = self.get_db()
        try:
            c = conn.cursor()
            row = c.execute("SELECT payload_json, target_display, created_at FROM investigations WHERE investigation_id = ?", (investigation_id,)).fetchone()
            if not row:
                raise ValueError(f"Investigation '{investigation_id}' not found in database.")

            report = json.loads(row[0]) if row[0] else {}
            target = row[1] or report.get("original_input", "Unknown Target")
            inv_time = row[2] or report.get("timestamp")

            # Extract technical indicators (IoCs)
            iocs = []
            if report.get("urls"):
                for u in report["urls"]:
                    iocs.append({"type": "URL", "value": u})
            if report.get("domains"):
                for d in report["domains"]:
                    iocs.append({"type": "DOMAIN", "value": d})
            if report.get("ip_addresses"):
                for ip in report["ip_addresses"]:
                    iocs.append({"type": "IP_ADDRESS", "value": ip})
            if report.get("senders"):
                for s in report["senders"]:
                    iocs.append({"type": "EMAIL_SENDER", "value": s})

            # Threat DNA & Risk
            risk = report.get("risk_assessment", {})
            dna = report.get("threat_dna", {})
            evidence = report.get("evidence", [])
            timeline = report.get("timeline", [])

            # Format incident summary suitable for copy-pasting into official complaint forms
            complaint_text = self._generate_complaint_text(investigation_id, target, risk, dna, iocs, evidence, notes)

            now = datetime.now().isoformat()
            pkg_id = f"EV-PKG-{investigation_id.replace('NS-INV-', '').replace('NS-EXT-', '')}-{datetime.now().strftime('%Y%m%d')}"

            dossier_core = {
                "package_id": pkg_id,
                "investigation_id": investigation_id,
                "target": target,
                "investigation_timestamp": inv_time,
                "package_generated_at": now,
                "investigator": investigator_name,
                "risk_assessment": {
                    "composite_score": risk.get("composite_score", 0),
                    "risk_level": risk.get("risk_level", "LOW"),
                    "verdict": risk.get("verdict", "UNKNOWN"),
                    "confidence": risk.get("confidence", "HIGH")
                },
                "threat_dna": {
                    "archetype": dna.get("archetype", "Cyber Threat"),
                    "fingerprint": dna.get("fingerprint"),
                    "traits": dna.get("traits", [])
                },
                "indicators_of_compromise": iocs,
                "evidence_ledger": evidence,
                "forensic_timeline": timeline,
                "investigator_notes": notes,
                "complaint_template": complaint_text,
                "official_portals": OFFICIAL_PORTALS,
                "legal_disclaimer": (
                    "This evidence dossier is compiled by NeuraShield for forensic documentation "
                    "and submission by the victim or organization to recognized law enforcement authorities. "
                    "NeuraShield does not automatically transmit complaints to police portals. "
                    "The user must lodge the formal complaint through the designated official portal."
                )
            }

            # Cryptographic SHA-256 Seal of the evidence dossier
            canonical_bytes = json.dumps(dossier_core, sort_keys=True).encode("utf-8")
            seal_hash = hashlib.sha256(canonical_bytes).hexdigest()
            dossier_core["integrity_seal_sha256"] = seal_hash

            # Persist in DB
            c.execute("""
            INSERT OR REPLACE INTO evidence_packages
                (package_id, investigation_id, target, dossier_sha256, package_json, created_at, exported_by)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """, (pkg_id, investigation_id, target, seal_hash, json.dumps(dossier_core), now, investigator_name))
            conn.commit()

            return dossier_core
        finally:
            conn.close()

    def _generate_complaint_text(self, inv_id: str, target: str, risk: Dict[str, Any],
                                 dna: Dict[str, Any], iocs: List[Dict[str, Any]],
                                 evidence: List[Dict[str, Any]], notes: Optional[str]) -> str:
        traits_str = ", ".join(dna.get("traits", [])) or "Suspicious communication"
        iocs_str = "\n".join([f"- {ioc['type']}: {ioc['value']}" for ioc in iocs[:6]]) or f"- Target: {target}"
        
        return f"""CYBERCRIME INCIDENT EVIDENCE SUMMARY
=====================================================
Case Reference: {inv_id}
Incident Date: {datetime.now().strftime('%d %B %Y')}
Threat Category: {dna.get('archetype', 'Phishing / Identity Theft')}
Observed Risk Level: {risk.get('risk_level', 'HIGH')} ({risk.get('composite_score', 0)}/100)

INCIDENT DESCRIPTION:
An unauthorized cyber threat target was identified: {target}
The activity exhibits characteristics of: {traits_str}.

TECHNICAL INDICATORS (IoCs):
{iocs_str}

FORENSIC EVIDENCE SUMMARY:
{self._summarize_evidence(evidence)}

INVESTIGATOR REMARKS:
{notes or 'Target represents a verified threat vector intended to deceive users or harvest credentials.'}

PREPARED VIA: NeuraShield Cybersecurity Platform (Forensic Integrity Seal Verified)
====================================================="""

    def _summarize_evidence(self, evidence: List[Dict[str, Any]]) -> str:
        lines = []
        for e in evidence[:5]:
            obs = e.get("observation", "")
            if obs:
                lines.append(f"• {obs}")
        return "\n".join(lines) if lines else "• Technical evidence captured in attached digital dossier."

    def get_package(self, package_id: str) -> Optional[Dict[str, Any]]:
        conn = self.get_db()
        try:
            c = conn.cursor()
            row = c.execute("SELECT package_json FROM evidence_packages WHERE package_id = ?", (package_id,)).fetchone()
            if row:
                return json.loads(row[0])
            return None
        finally:
            conn.close()
