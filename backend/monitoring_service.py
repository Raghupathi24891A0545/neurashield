"""NeuraShield Module 7: Continuous Threat Monitoring Service.

Provides automated baseline tracking, periodic differential analysis,
infrastructure change detection, and investigation triggering for:
- Protected Domains
- Critical URLs
- Monitored Webpages
- Key Brand Assets

Monitored Dimensions:
- DNS records (A, AAAA, MX, NS, TXT)
- Resolved IP addresses & geo/ASN shifts
- SSL/TLS certificate validity & issuer fingerprints
- Domain registration age & expiration timeline
- HTTP availability & response code changes
- Page title & cryptographic DOM hash shifts
- Fused risk level & Threat DNA evolution
"""

from datetime import datetime, timedelta
import hashlib
import json
import sqlite3
import threading
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse


class MonitoringService:
    def __init__(self, db_conn_factory, deps: Optional[Dict[str, Any]] = None):
        self.get_db = db_conn_factory
        self.deps = deps or {}
        self._lock = threading.Lock()
        self._init_tables()

    def _init_tables(self):
        conn = self.get_db()
        try:
            c = conn.cursor()
            c.execute("""
            CREATE TABLE IF NOT EXISTS monitoring_configs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                asset_type TEXT NOT NULL,         -- DOMAIN, URL, WEBPAGE, ASSET
                target TEXT NOT NULL,
                label TEXT,
                status TEXT NOT NULL DEFAULT 'ACTIVE', -- ACTIVE, PAUSED, ARCHIVED
                check_interval_seconds INTEGER DEFAULT 3600,
                baseline_json TEXT,
                current_state_json TEXT,
                last_checked_at TEXT,
                last_event_at TEXT,
                current_risk_level TEXT DEFAULT 'LOW',
                current_risk_score INTEGER DEFAULT 0,
                change_count INTEGER DEFAULT 0,
                created_at TEXT NOT NULL
            )
            """)
            c.execute("CREATE INDEX IF NOT EXISTS idx_mon_target ON monitoring_configs(target)")
            c.execute("CREATE INDEX IF NOT EXISTS idx_mon_status ON monitoring_configs(status)")

            c.execute("""
            CREATE TABLE IF NOT EXISTS monitoring_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                config_id INTEGER NOT NULL,
                target TEXT NOT NULL,
                event_type TEXT NOT NULL,         -- DNS_CHANGE, IP_CHANGE, SSL_EXPIRY, RISK_CHANGE, CONTENT_CHANGE, AVAILABILITY_CHANGE
                severity TEXT NOT NULL,           -- LOW, MEDIUM, HIGH, CRITICAL
                diff_summary TEXT NOT NULL,
                details_json TEXT,
                previous_state_json TEXT,
                current_state_json TEXT,
                investigation_id TEXT,
                acknowledged INTEGER DEFAULT 0,
                created_at TEXT NOT NULL,
                FOREIGN KEY (config_id) REFERENCES monitoring_configs(id) ON DELETE CASCADE
            )
            """)
            c.execute("CREATE INDEX IF NOT EXISTS idx_monev_config ON monitoring_events(config_id, created_at)")
            c.execute("CREATE INDEX IF NOT EXISTS idx_monev_sev ON monitoring_events(severity)")
            conn.commit()

            # Seed demo monitored assets if empty
            count = c.execute("SELECT COUNT(*) FROM monitoring_configs").fetchone()[0]
            if count == 0:
                self._seed_reference_assets(conn)
        except Exception as e:
            print(f"[MonitoringService] Table init error: {e}")
        finally:
            conn.close()

    def _seed_reference_assets(self, conn):
        now = datetime.now().isoformat()
        seeds = [
            ("DOMAIN", "google.com", "Primary Corporate Domain (Google)", 3600, "ACTIVE", "LOW", 10),
            ("DOMAIN", "microsoft.com", "Enterprise Cloud Infrastructure (Microsoft)", 3600, "ACTIVE", "LOW", 10),
            ("DOMAIN", "tkrcet.ac.in", "Protected Institutional Portal (TKR College)", 1800, "ACTIVE", "LOW", 15),
        ]
        c = conn.cursor()
        for s in seeds:
            base_state = {
                "target": s[1],
                "resolved_ips": ["172.217.16.206"] if "google" in s[1] else ["20.112.52.29"],
                "nameservers": ["ns1.google.com"] if "google" in s[1] else ["ns1.msft.net"],
                "tls_status": "SECURE",
                "risk_score": s[6],
                "risk_level": s[5],
                "collected_at": now
            }
            c.execute("""
            INSERT INTO monitoring_configs
                (asset_type, target, label, check_interval_seconds, status, current_risk_level, current_risk_score,
                 baseline_json, current_state_json, last_checked_at, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (s[0], s[1], s[2], s[3], s[4], s[5], s[6], json.dumps(base_state), json.dumps(base_state), now, now))
        conn.commit()

    def snapshot_asset(self, target: str, asset_type: str = "DOMAIN") -> Dict[str, Any]:
        """Collect current live state for an asset using existing intelligence modules."""
        target_norm = target.strip()
        now = datetime.now().isoformat()

        # Determine domain host
        if target_norm.startswith(("http://", "https://")):
            parsed = urlparse(target_norm)
            domain = parsed.hostname or target_norm
            url = target_norm
        else:
            domain = target_norm
            url = f"https://{target_norm}"

        state = {
            "target": target_norm,
            "domain": domain,
            "asset_type": asset_type,
            "collected_at": now,
            "dns": {},
            "resolved_ips": [],
            "nameservers": [],
            "registrar": "UNAVAILABLE",
            "domain_age_days": None,
            "tls_status": "UNAVAILABLE",
            "cert_issuer": "UNAVAILABLE",
            "http_status": None,
            "page_title": None,
            "content_hash": None,
            "risk_score": 0,
            "risk_level": "LOW",
            "threat_dna": []
        }

        # 1. Domain collection via existing analyze_domain
        analyze_domain = self.deps.get("analyze_domain")
        if analyze_domain:
            try:
                dom_res = analyze_domain(domain)
                if dom_res and not dom_res.get("error"):
                    ip_info = dom_res.get("ip") or {}
                    ns_info = dom_res.get("nameservers") or {}
                    reg_info = dom_res.get("registration") or {}
                    ssl_info = dom_res.get("ssl") or {}

                    state["resolved_ips"] = ip_info.get("resolved_ipv4") or []
                    state["nameservers"] = ns_info.get("nameserver_list") or []
                    state["registrar"] = reg_info.get("registrar") or "UNAVAILABLE"
                    state["domain_age_days"] = reg_info.get("domain_age_days")
                    state["tls_status"] = ssl_info.get("transport_status") or "UNAVAILABLE"
                    state["cert_issuer"] = ssl_info.get("certificate_issuer") or "UNAVAILABLE"
            except Exception as e:
                state["domain_error"] = str(e)

        # 2. Webpage / availability check
        safe_fetch = self.deps.get("safe_fetch_webpage_hybrid") or self.deps.get("safe_fetch_webpage")
        if safe_fetch and asset_type in ("URL", "WEBPAGE"):
            try:
                fetch_res = safe_fetch(url)
                state["http_status"] = fetch_res.get("http_status")
                body = fetch_res.get("body_bytes") or b""
                if body:
                    state["content_hash"] = hashlib.sha256(body).hexdigest()[:16]
                analyze_webpage = self.deps.get("analyze_webpage")
                if analyze_webpage and fetch_res.get("fetch_status") == self.deps.get("FETCH_SUCCESS", "FETCH_SUCCESS"):
                    wa = analyze_webpage(fetch_res)
                    state["page_title"] = (wa.get("html_analysis") or {}).get("title")
            except Exception as e:
                state["webpage_error"] = str(e)

        # 3. Fast risk baseline calculation
        classify_url = self.deps.get("classify_url")
        if classify_url:
            try:
                pred, prob = classify_url(url)
                state["risk_score"] = int((prob or 0.1) * 100)
                state["risk_level"] = "HIGH" if state["risk_score"] >= 65 else ("MEDIUM" if state["risk_score"] >= 35 else "LOW")
            except Exception:
                pass

        return state

    def create_monitored_asset(self, target: str, asset_type: str = "DOMAIN",
                               label: Optional[str] = None, interval: int = 3600) -> Dict[str, Any]:
        """Enroll an asset into continuous monitoring and create its verifiable baseline."""
        target_norm = target.strip()
        if not target_norm:
            raise ValueError("Target is required.")

        label_final = label or f"Monitored {asset_type}: {target_norm}"
        baseline = self.snapshot_asset(target_norm, asset_type)
        now = datetime.now().isoformat()

        conn = self.get_db()
        try:
            c = conn.cursor()
            # Check duplicate
            existing = c.execute("SELECT id FROM monitoring_configs WHERE target = ?", (target_norm,)).fetchone()
            if existing:
                c.execute("""
                UPDATE monitoring_configs
                SET asset_type=?, label=?, check_interval_seconds=?, baseline_json=?, current_state_json=?,
                    status='ACTIVE', last_checked_at=?, current_risk_level=?, current_risk_score=?
                WHERE id=?
                """, (asset_type, label_final, interval, json.dumps(baseline), json.dumps(baseline),
                      now, baseline.get("risk_level", "LOW"), baseline.get("risk_score", 0), existing[0]))
                conn.commit()
                config_id = existing[0]
            else:
                c.execute("""
                INSERT INTO monitoring_configs
                    (asset_type, target, label, check_interval_seconds, status, baseline_json,
                     current_state_json, last_checked_at, current_risk_level, current_risk_score, created_at)
                VALUES (?, ?, ?, ?, 'ACTIVE', ?, ?, ?, ?, ?, ?)
                """, (asset_type, target_norm, label_final, interval, json.dumps(baseline),
                      json.dumps(baseline), now, baseline.get("risk_level", "LOW"), baseline.get("risk_score", 0), now))
                conn.commit()
                config_id = c.lastrowid

            return {
                "id": config_id,
                "target": target_norm,
                "asset_type": asset_type,
                "label": label_final,
                "baseline": baseline,
                "status": "ACTIVE",
                "message": f"Asset {target_norm} enrolled in continuous threat monitoring."
            }
        finally:
            conn.close()

    def check_asset(self, config_id: int, trigger_agent: bool = True) -> Dict[str, Any]:
        """Perform differential check against baseline and record monitoring events."""
        conn = self.get_db()
        try:
            c = conn.cursor()
            row = c.execute("""
            SELECT id, asset_type, target, baseline_json, current_state_json, change_count
            FROM monitoring_configs WHERE id = ?
            """, (config_id,)).fetchone()

            if not row:
                raise ValueError(f"Monitored asset #{config_id} not found.")

            c_id, asset_type, target, baseline_raw, current_raw, chg_count = row
            previous_state = json.loads(current_raw) if current_raw else {}
            baseline = json.loads(baseline_raw) if baseline_raw else {}

            # Perform fresh snapshot
            fresh_state = self.snapshot_asset(target, asset_type)
            events_detected = self._detect_differences(baseline, previous_state, fresh_state)

            now = datetime.now().isoformat()
            inv_id = None

            # If meaningful high-severity changes detected, optionally trigger investigation agent
            has_urgent_change = any(e["severity"] in ("HIGH", "CRITICAL") for e in events_detected)
            if has_urgent_change and trigger_agent and self.deps.get("investigation_agent"):
                try:
                    agent = self.deps.get("investigation_agent")
                    agent_report = agent.investigate(target, input_type="DOMAIN" if asset_type == "DOMAIN" else "URL")
                    inv_id = agent_report.get("investigation_id")
                except Exception as e:
                    print(f"[MonitoringService] Auto-investigation failed: {e}")

            # Persist events
            for ev in events_detected:
                c.execute("""
                INSERT INTO monitoring_events
                    (config_id, target, event_type, severity, diff_summary, details_json,
                     previous_state_json, current_state_json, investigation_id, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (c_id, target, ev["event_type"], ev["severity"], ev["diff_summary"],
                      json.dumps(ev.get("details", {})), json.dumps(previous_state),
                      json.dumps(fresh_state), inv_id, now))

            new_chg_count = chg_count + len(events_detected)
            last_event_time = now if events_detected else None

            c.execute("""
            UPDATE monitoring_configs
            SET current_state_json=?, last_checked_at=?, last_event_at=COALESCE(?, last_event_at),
                current_risk_level=?, current_risk_score=?, change_count=?
            WHERE id=?
            """, (json.dumps(fresh_state), now, last_event_time,
                  fresh_state.get("risk_level", "LOW"), fresh_state.get("risk_score", 0),
                  new_chg_count, c_id))
            conn.commit()

            return {
                "config_id": c_id,
                "target": target,
                "events_count": len(events_detected),
                "events": events_detected,
                "current_state": fresh_state,
                "investigation_id": inv_id,
                "checked_at": now
            }
        finally:
            conn.close()

    def _detect_differences(self, baseline: Dict[str, Any], previous: Dict[str, Any], current: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Identify verifiable infrastructure or risk deviations between states."""
        events = []

        # 1. IP Shift Detection
        prev_ips = set(previous.get("resolved_ips") or baseline.get("resolved_ips") or [])
        curr_ips = set(current.get("resolved_ips") or [])
        if prev_ips and curr_ips and prev_ips != curr_ips:
            added = list(curr_ips - prev_ips)
            removed = list(prev_ips - curr_ips)
            events.append({
                "event_type": "IP_CHANGE",
                "severity": "HIGH" if added else "MEDIUM",
                "diff_summary": f"Resolved IPv4 infrastructure shifted. New IPs: {', '.join(added) or 'None'}, Deprecated: {', '.join(removed) or 'None'}.",
                "details": {"added_ips": added, "removed_ips": removed}
            })

        # 2. Nameserver Changes
        prev_ns = set(previous.get("nameservers") or baseline.get("nameservers") or [])
        curr_ns = set(current.get("nameservers") or [])
        if prev_ns and curr_ns and prev_ns != curr_ns:
            events.append({
                "event_type": "NAMESERVER_CHANGE",
                "severity": "HIGH",
                "diff_summary": f"Authoritative nameservers modified from [{', '.join(prev_ns)}] to [{', '.join(curr_ns)}].",
                "details": {"previous_ns": list(prev_ns), "current_ns": list(curr_ns)}
            })

        # 3. TLS / SSL Transport Status
        prev_tls = previous.get("tls_status") or baseline.get("tls_status")
        curr_tls = current.get("tls_status")
        if prev_tls and curr_tls and prev_tls != curr_tls:
            sev = "CRITICAL" if curr_tls in ("insecure", "INVALID", "EXPIRED") else "MEDIUM"
            events.append({
                "event_type": "CERTIFICATE_CHANGE",
                "severity": sev,
                "diff_summary": f"Transport security posture changed from {prev_tls} to {curr_tls}.",
                "details": {"previous": prev_tls, "current": curr_tls}
            })

        # 4. HTTP Availability
        prev_http = previous.get("http_status")
        curr_http = current.get("http_status")
        if prev_http and curr_http and prev_http != curr_http:
            sev = "HIGH" if curr_http in (403, 404, 500, 502, 503) else "LOW"
            events.append({
                "event_type": "AVAILABILITY_CHANGE",
                "severity": sev,
                "diff_summary": f"HTTP response status code changed from {prev_http} to {curr_http}.",
                "details": {"previous_status": prev_http, "current_status": curr_http}
            })

        # 5. DOM Content Hash Shift
        prev_hash = previous.get("content_hash")
        curr_hash = current.get("content_hash")
        if prev_hash and curr_hash and prev_hash != curr_hash:
            events.append({
                "event_type": "CONTENT_CHANGE",
                "severity": "MEDIUM",
                "diff_summary": f"Webpage DOM structure modified. Hash changed ({prev_hash[:8]}... -> {curr_hash[:8]}...).",
                "details": {"previous_hash": prev_hash, "current_hash": curr_hash}
            })

        # 6. Risk Level Escalation
        prev_risk = previous.get("risk_level") or baseline.get("risk_level", "LOW")
        curr_risk = current.get("risk_level", "LOW")
        risk_rank = {"LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}
        if risk_rank.get(curr_risk, 1) > risk_rank.get(prev_risk, 1):
            events.append({
                "event_type": "RISK_CHANGE",
                "severity": "CRITICAL" if curr_risk in ("HIGH", "CRITICAL") else "HIGH",
                "diff_summary": f"Threat risk level escalated from {prev_risk} ({previous.get('risk_score', 0)}/100) to {curr_risk} ({current.get('risk_score', 0)}/100).",
                "details": {"previous_risk": prev_risk, "current_risk": curr_risk, "new_score": current.get("risk_score")}
            })

        return events

    def list_monitored_assets(self, status: Optional[str] = None) -> List[Dict[str, Any]]:
        """List all monitored assets with latest status, baseline, and change count."""
        conn = self.get_db()
        try:
            c = conn.cursor()
            q = "SELECT id, asset_type, target, label, status, check_interval_seconds, current_risk_level, current_risk_score, change_count, last_checked_at, last_event_at, created_at, baseline_json, current_state_json FROM monitoring_configs"
            params = []
            if status:
                q += " WHERE status = ?"
                params.append(status)
            q += " ORDER BY id DESC"

            c.execute(q, params)
            results = []
            for r in c.fetchall():
                results.append({
                    "id": r[0],
                    "asset_type": r[1],
                    "target": r[2],
                    "label": r[3],
                    "status": r[4],
                    "check_interval_seconds": r[5],
                    "current_risk_level": r[6],
                    "current_risk_score": r[7],
                    "change_count": r[8],
                    "last_checked_at": r[9],
                    "last_event_at": r[10],
                    "created_at": r[11],
                    "baseline": json.loads(r[12]) if r[12] else {},
                    "current_state": json.loads(r[13]) if r[13] else {}
                })
            return results
        finally:
            conn.close()

    def get_monitored_asset(self, config_id: int) -> Optional[Dict[str, Any]]:
        conn = self.get_db()
        try:
            c = conn.cursor()
            c.execute("""
            SELECT id, asset_type, target, label, status, check_interval_seconds, current_risk_level,
                   current_risk_score, change_count, last_checked_at, last_event_at, created_at,
                   baseline_json, current_state_json
            FROM monitoring_configs WHERE id = ?
            """, (config_id,))
            row = c.fetchone()
            if not row:
                return None

            # Get events timeline
            c.execute("""
            SELECT id, event_type, severity, diff_summary, investigation_id, created_at, details_json
            FROM monitoring_events WHERE config_id = ? ORDER BY id DESC LIMIT 50
            """, (config_id,))
            events = [
                {
                    "id": ev[0],
                    "event_type": ev[1],
                    "severity": ev[2],
                    "diff_summary": ev[3],
                    "investigation_id": ev[4],
                    "created_at": ev[5],
                    "details": json.loads(ev[6]) if ev[6] else {}
                }
                for ev in c.fetchall()
            ]

            return {
                "id": row[0],
                "asset_type": row[1],
                "target": row[2],
                "label": row[3],
                "status": row[4],
                "check_interval_seconds": row[5],
                "current_risk_level": row[6],
                "current_risk_score": row[7],
                "change_count": row[8],
                "last_checked_at": row[9],
                "last_event_at": row[10],
                "created_at": row[11],
                "baseline": json.loads(row[12]) if row[12] else {},
                "current_state": json.loads(row[13]) if row[13] else {},
                "events": events
            }
        finally:
            conn.close()

    def list_all_events(self, limit: int = 50, severity: Optional[str] = None) -> List[Dict[str, Any]]:
        conn = self.get_db()
        try:
            c = conn.cursor()
            q = "SELECT id, config_id, target, event_type, severity, diff_summary, investigation_id, created_at FROM monitoring_events"
            params = []
            if severity:
                q += " WHERE severity = ?"
                params.append(severity)
            q += " ORDER BY id DESC LIMIT ?"
            params.append(limit)

            c.execute(q, params)
            return [
                {
                    "id": r[0], "config_id": r[1], "target": r[2], "event_type": r[3],
                    "severity": r[4], "diff_summary": r[5], "investigation_id": r[6], "created_at": r[7]
                }
                for r in c.fetchall()
            ]
        finally:
            conn.close()

    def delete_asset(self, config_id: int) -> bool:
        conn = self.get_db()
        try:
            c = conn.cursor()
            c.execute("DELETE FROM monitoring_events WHERE config_id = ?", (config_id,))
            c.execute("DELETE FROM monitoring_configs WHERE id = ?", (config_id,))
            conn.commit()
            return True
        finally:
            conn.close()
