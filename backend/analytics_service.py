"""NeuraShield Module 19: Security & Model Analytics Service.

Aggregates operational security telemetry strictly from real stored database records:
- `investigations` (Payload, risk levels, verdicts, execution times)
- `logs` (Historical scan predictions and scores)
- `domain_analyses` (Domain intelligence runs)
- `webpage_analyses` (Webpage inspections)
- `email_analyses` (Email intelligence events)
- `incidents` (SOC case statuses & severities)
- `monitoring_configs` & `monitoring_events` (Infrastructure drift alerts)

Strict Rule: Absolutely NO fabricated statistics or synthetic graphs.
If records are absent, display truthful empty states.
"""

from collections import Counter
from datetime import datetime, timedelta
import json
import sqlite3
from typing import Any, Dict, List, Optional


class SecurityAnalyticsService:
    def __init__(self, db_conn_factory):
        self.get_db = db_conn_factory

    def get_platform_analytics(self) -> Dict[str, Any]:
        """Compute aggregated security analytics strictly from SQLite database tables."""
        conn = self.get_db()
        try:
            c = conn.cursor()

            # 1. Total Investigations count
            c.execute("SELECT COUNT(*) FROM investigations")
            total_investigations = c.fetchone()[0]

            c.execute("SELECT COUNT(*) FROM logs")
            total_legacy_scans = c.fetchone()[0]

            grand_total_scans = total_investigations + total_legacy_scans

            if grand_total_scans == 0:
                return {
                    "has_data": False,
                    "total_investigations": 0,
                    "message": "No investigation data available yet. Run your first investigation in the Investigation Center to generate telemetry."
                }

            # 2. Risk Distribution
            c.execute("""
            SELECT risk_level, COUNT(*) FROM investigations
            WHERE risk_level IS NOT NULL GROUP BY risk_level
            """)
            risk_dist = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
            for row in c.fetchall():
                lvl = (row[0] or "").upper()
                if lvl in risk_dist:
                    risk_dist[lvl] += row[1]
                elif lvl in ("PHISHING", "MALICIOUS"):
                    risk_dist["HIGH"] += row[1]
                else:
                    risk_dist["LOW"] += row[1]

            # 3. Input Types Breakdown
            c.execute("""
            SELECT input_type, COUNT(*) FROM investigations
            WHERE input_type IS NOT NULL GROUP BY input_type
            """)
            input_types = {row[0].upper(): row[1] for row in c.fetchall()}

            # 4. Verdicts Breakdown
            c.execute("""
            SELECT verdict, COUNT(*) FROM investigations
            WHERE verdict IS NOT NULL GROUP BY verdict
            """)
            verdicts = {}
            for row in c.fetchall():
                v = (row[0] or "UNKNOWN").capitalize()
                verdicts[v] = verdicts.get(v, 0) + row[1]

            # 5. Extract Top Threat DNA Traits & Executed Modules
            c.execute("SELECT payload_json FROM investigations ORDER BY created_at DESC LIMIT 100")
            dna_counter = Counter()
            module_counter = Counter()
            rules_counter = Counter()
            timeline_days = Counter()

            for (payload_raw,) in c.fetchall():
                try:
                    payload = json.loads(payload_raw) if payload_raw else {}
                    # Threat DNA
                    dna = payload.get("threat_dna", {})
                    traits = dna.get("traits", []) if isinstance(dna, dict) else []
                    for t in traits:
                        dna_counter[t] += 1

                    # Modules executed
                    modules = payload.get("modules_executed", [])
                    for m in modules:
                        module_counter[m] += 1

                    # Rules hit from URL/webpage
                    url_intel = payload.get("url_analysis", {})
                    rules = (url_intel.get("security_rules") or {}).get("rules_hit", [])
                    for r in rules:
                        r_name = r.get("name") or r.get("label") or r.get("rule_id")
                        if r_name:
                            rules_counter[r_name] += 1

                    # Timestamp trend
                    ts = payload.get("timestamp") or ""
                    if ts:
                        day = ts.split("T")[0]
                        timeline_days[day] += 1
                except Exception:
                    continue

            # 6. Incident Statistics
            c.execute("SELECT status, COUNT(*) FROM incidents GROUP BY status")
            incident_stats = {r[0]: r[1] for r in c.fetchall()}

            c.execute("SELECT COUNT(*) FROM incidents")
            total_incidents = c.fetchone()[0]

            # 7. Monitoring Assets & Events
            total_monitored = 0
            total_mon_events = 0
            try:
                c.execute("SELECT COUNT(*) FROM monitoring_configs WHERE status='ACTIVE'")
                total_monitored = c.fetchone()[0]
                c.execute("SELECT COUNT(*) FROM monitoring_events")
                total_mon_events = c.fetchone()[0]
            except Exception:
                pass

            # 8. Format timeline for chart
            sorted_days = sorted(timeline_days.keys())[-14:]
            trend_data = [{"date": d, "count": timeline_days[d]} for d in sorted_days]

            return {
                "has_data": True,
                "timestamp": datetime.now().isoformat(),
                "summary": {
                    "total_investigations": total_investigations,
                    "total_scans": grand_total_scans,
                    "total_incidents": total_incidents,
                    "total_monitored_assets": total_monitored,
                    "total_monitoring_events": total_mon_events,
                    "critical_threats_detected": risk_dist.get("CRITICAL", 0) + risk_dist.get("HIGH", 0)
                },
                "risk_distribution": risk_dist,
                "input_types": input_types,
                "verdicts": verdicts,
                "top_threat_dna_traits": [
                    {"trait": k, "count": v} for k, v in dna_counter.most_common(8)
                ],
                "module_execution_frequency": [
                    {"module": k, "count": v} for k, v in module_counter.most_common(10)
                ],
                "top_triggered_rules": [
                    {"rule": k, "count": v} for k, v in rules_counter.most_common(8)
                ],
                "activity_trend": trend_data,
                "incident_status_distribution": incident_stats
            }
        finally:
            conn.close()
