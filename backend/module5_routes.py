"""NeuraShield Investigation Center Routes & Unified API.

Registers the unified Investigation Center page and REST APIs:
- GET  /investigation-center       (The primary unified investigation interface)
- GET  /ai-investigation           (Redirects to /investigation-center)
- GET  /investigation-history      (History and audit trail of past investigations)
- POST /api/investigate/unified    (Unified entry point for URL, DOMAIN, QR, EMAIL, WEBPAGE)
- POST /api/investigate            (Backwards-compatible alias)
- POST /api/investigate/qr         (Backwards-compatible alias)
- GET  /api/investigate/<inv_id>   (Retrieve full report)
- GET  /api/investigate/<inv_id>/status (Retrieve live progress/status)
- GET  /api/investigate/<inv_id>/graph  (Retrieve relationship graph)
- GET  /api/investigate/<inv_id>/evidence (Retrieve verified evidence list)
"""

import json
import os
import threading
import time
from collections import defaultdict, deque
from datetime import datetime

from flask import jsonify, redirect, render_template, request, session

try:
    from backend.investigation_agent import InvestigationAgent
    from backend.qr_intelligence import build_qr_analysis
except ImportError:
    from investigation_agent import InvestigationAgent
    from qr_intelligence import build_qr_analysis


RATE_WINDOW_S, RATE_MAX = 300, 20
MAX_UPLOAD_BYTES = 10 * 1024 * 1024  # 10 MB
ALLOWED_IMAGE_EXTS = {'.png', '.jpg', '.jpeg', '.gif', '.bmp', '.webp', '.tiff'}


class _RateLimiter:
    def __init__(self):
        self._hits = defaultdict(deque)
        self._lock = threading.Lock()

    def allow(self, key):
        now = time.time()
        with self._lock:
            q = self._hits[key]
            while q and now - q[0] > RATE_WINDOW_S:
                q.popleft()
            if len(q) >= RATE_MAX:
                return False
            q.append(now)
            return True


def _err(code, message, status=400):
    return jsonify({'error': {'code': code, 'message': message}}), status


def register_module5_routes(app, deps):
    """Register Investigation Center routes and APIs."""
    limiter = _RateLimiter()
    get_db = deps['get_db_connection']
    investigation_store = deps['investigation_store']
    sanitize = deps['sanitize_for_json']

    # Initialize tables
    _init_investigation_tables(get_db)

    # Initialize master agent
    agent = InvestigationAgent(deps)

    # In-memory active investigations tracker for live progress
    active_jobs = {}

    # ── Page Routes ───────────────────────────────────────────────────────

    @app.route('/investigation-center')
    def investigation_center_page():
        return render_template(
            'investigation_center.html',
            username=session.get('username', 'Analyst'),
            role=session.get('role', 'user'),
            provider_status=agent.security_intel.get_provider_status(),
            gemini_configured=agent.gemini.is_configured
        )

    @app.route('/ai-investigation')
    def redirect_ai_investigation():
        # Redirect standalone AI agent path directly to Investigation Center
        return redirect('/investigation-center')

    @app.route('/qr-intelligence')
    def qr_intelligence_page():
        # Dedicated specialist route directing to Investigation Center QR cockpit
        return redirect('/investigation-center?type=qr')

    @app.route('/api/sample/qr')
    def api_sample_qr():
        """Serve a generated test phishing QR code image for instant system testing."""
        import io
        import qrcode
        from flask import send_file

        target_url = request.args.get('url', 'https://secure-login-verify-account.com/auth')
        qr = qrcode.QRCode(version=1, box_size=10, border=3)
        qr.add_data(target_url)
        qr.make(fit=True)
        img = qr.make_image(fill_color="black", back_color="white")
        buf = io.BytesIO()
        img.save(buf, format='PNG')
        buf.seek(0)
        return send_file(buf, mimetype='image/png', download_name='sample_phish_qr.png')

    @app.route('/investigation-history')
    def investigation_history_page():
        return render_template(
            'investigations.html',
            username=session.get('username', 'Analyst'),
            role=session.get('role', 'user')
        )

    # ── Unified Investigation API ─────────────────────────────────────────

    @app.route('/api/investigate/unified', methods=['POST'])
    def api_investigate_unified():
        """Single unified investigation API accepting any supported input type:
        - URL
        - DOMAIN
        - QR_IMAGE (file upload)
        - EMAIL (.eml file upload or raw text)
        - WEBPAGE (URL for static/dynamic inspection)
        """
        user_key = session.get('user_id', request.remote_addr)
        if not limiter.allow(user_key):
            return _err('RATE_LIMITED', f'Rate limit exceeded. Maximum {RATE_MAX} investigations per {RATE_WINDOW_S // 60} minutes.', 429)

        # Detect input format (multipart form vs application/json)
        input_type = 'URL'
        target_str = ''
        image_bytes = None
        email_bytes = None

        if request.content_type and 'multipart/form-data' in request.content_type:
            input_type = (request.form.get('input_type') or 'URL').upper()
            target_str = (request.form.get('target') or request.form.get('url') or request.form.get('domain') or '').strip()

            # QR image file
            qr_file = request.files.get('qr_image') or request.files.get('file')
            if qr_file and qr_file.filename:
                input_type = 'QR_IMAGE'
                fname = qr_file.filename.replace('\\', '/').rsplit('/', 1)[-1][:200]
                ext = os.path.splitext(fname)[1].lower()
                if ext not in ALLOWED_IMAGE_EXTS:
                    return _err('INVALID_FORMAT', f'Image format not supported. Allowed: {", ".join(ALLOWED_IMAGE_EXTS)}')
                image_bytes = qr_file.read(MAX_UPLOAD_BYTES + 1)
                if len(image_bytes) > MAX_UPLOAD_BYTES:
                    return _err('CONTENT_TOO_LARGE', f'File exceeds {MAX_UPLOAD_BYTES // (1024 * 1024)} MB limit.')
                target_str = fname

            # Email file or raw text
            email_file = request.files.get('email_file')
            if email_file and email_file.filename:
                input_type = 'EMAIL'
                fname = email_file.filename.replace('\\', '/').rsplit('/', 1)[-1][:200]
                email_bytes = email_file.read(MAX_UPLOAD_BYTES + 1)
                if len(email_bytes) > MAX_UPLOAD_BYTES:
                    return _err('CONTENT_TOO_LARGE', f'Email file exceeds {MAX_UPLOAD_BYTES // (1024 * 1024)} MB limit.')
                target_str = fname
            elif request.form.get('raw_email'):
                input_type = 'EMAIL'
                email_bytes = request.form.get('raw_email').encode('utf-8', errors='replace')
                target_str = 'Raw Email Buffer'

        else:
            data = request.get_json(silent=True) or {}
            input_type = (data.get('input_type') or 'URL').upper()
            target_str = (data.get('target') or data.get('url') or data.get('domain') or '').strip()

            if data.get('raw_email'):
                input_type = 'EMAIL'
                email_bytes = data['raw_email'].encode('utf-8', errors='replace')
                target_str = 'Raw Email Buffer'

        # Validation
        if input_type in ('URL', 'DOMAIN', 'WEBPAGE') and not target_str:
            return _err('INVALID_INPUT', 'Please specify a valid URL or domain target.')
        if input_type == 'QR_IMAGE' and not image_bytes:
            return _err('INVALID_INPUT', 'Please upload a valid QR code image (PNG, JPEG, WebP).')
        if input_type == 'EMAIL' and not email_bytes:
            return _err('INVALID_INPUT', 'Please upload an .eml email file or provide raw email source.')

        # Execute investigation via unified agent
        try:
            report = agent.investigate(
                original_input=target_str,
                input_type=input_type,
                image_bytes=image_bytes,
                email_bytes=email_bytes
            )
        except Exception as e:
            app.logger.exception('Unified investigation failed')
            return _err('INVESTIGATION_FAILED', f'Investigation could not be completed: {str(e)}', 500)

        # Sanitize, store and persist
        report = sanitize(report)
        inv_id = report.get('investigation_id', '')
        investigation_store.put(inv_id, report)

        try:
            _persist_investigation(get_db, report, session.get('user_id'))
        except Exception as e:
            app.logger.warning(f'Persistence warning: {e}')

        return jsonify(report)

    @app.route('/api/investigate', methods=['POST'])
    def api_investigate_alias():
        """Alias for /api/investigate/unified."""
        return api_investigate_unified()

    @app.route('/api/investigate/qr', methods=['POST'])
    def api_investigate_qr_alias():
        """Alias for /api/investigate/unified with QR image."""
        return api_investigate_unified()

    @app.route('/api/investigate/<inv_id>', methods=['GET'])
    def api_get_investigation(inv_id):
        """Retrieve full investigation report."""
        inv = investigation_store.get(inv_id)
        if inv:
            return jsonify(sanitize(inv))

        conn = get_db()
        try:
            row = conn.execute(
                'SELECT payload_json FROM investigations WHERE investigation_id=?',
                (inv_id,)
            ).fetchone()
            if row:
                data = json.loads(row[0])
                return jsonify(sanitize(data))
        except Exception:
            pass
        finally:
            conn.close()

        return _err('NOT_FOUND', 'Investigation not found.', 404)

    @app.route('/api/investigate/<inv_id>/graph', methods=['GET'])
    def api_get_graph(inv_id):
        """Retrieve threat relationship graph."""
        inv = investigation_store.get(inv_id)
        if not inv:
            conn = get_db()
            try:
                row = conn.execute(
                    'SELECT payload_json FROM investigations WHERE investigation_id=?',
                    (inv_id,)
                ).fetchone()
                if row:
                    inv = json.loads(row[0])
            except Exception:
                pass
            finally:
                conn.close()

        if not inv:
            return _err('NOT_FOUND', 'Investigation not found.', 404)

        return jsonify(sanitize({
            'investigation_id': inv_id,
            'threat_graph': inv.get('threat_graph', {'nodes': [], 'edges': []})
        }))

    @app.route('/api/investigate/<inv_id>/evidence', methods=['GET'])
    def api_get_evidence(inv_id):
        """Retrieve verified evidence list."""
        inv = investigation_store.get(inv_id)
        if not inv:
            conn = get_db()
            try:
                row = conn.execute(
                    'SELECT payload_json FROM investigations WHERE investigation_id=?',
                    (inv_id,)
                ).fetchone()
                if row:
                    inv = json.loads(row[0])
            except Exception:
                pass
            finally:
                conn.close()

        if not inv:
            return _err('NOT_FOUND', 'Investigation not found.', 404)

        return jsonify(sanitize({
            'investigation_id': inv_id,
            'evidence': inv.get('evidence', []),
            'evidence_count': inv.get('evidence_count', 0)
        }))

    # ── Module 6: Threat Intelligence & Incident Response APIs ──────────

    @app.route('/threat-intelligence')
    @app.route('/incident-response')
    def threat_intelligence_page():
        """Dedicated Module 6 Threat Intelligence & Incident Response exploration page."""
        return render_template(
            'threat_intel_incident.html',
            username=session.get('username', 'Analyst'),
            role=session.get('role', 'user')
        )

    @app.route('/api/investigations/<inv_id>/incidents', methods=['POST'])
    def api_create_incident_for_investigation(inv_id):
        """Create a real incident from an investigation."""
        data = request.get_json(silent=True) or {}
        actor = session.get('username', 'Analyst')
        title = data.get('title')
        severity = data.get('severity')
        assigned_to = data.get('assigned_to') or actor
        notes = data.get('notes')

        current_report = investigation_store.get(inv_id)
        try:
            res = agent.incident_service.create_incident(
                investigation_id=inv_id,
                title=title,
                severity=severity,
                assigned_to=assigned_to,
                notes=notes,
                current_report=current_report,
                actor=actor
            )
            return jsonify(sanitize({'incident': res, 'incident_id': res.get('incident_id')}))
        except Exception as e:
            app.logger.exception('Incident creation failed')
            return _err('INCIDENT_CREATION_FAILED', f'Could not create incident: {str(e)}', 500)

    @app.route('/api/investigations/<inv_id>/incidents', methods=['GET'])
    def api_get_incident_for_investigation(inv_id):
        """Get incident linked to an investigation."""
        try:
            inc = agent.incident_service.get_incident_by_investigation(inv_id)
            if inc:
                return jsonify(sanitize(inc))
            return jsonify({'linked': False, 'incident': None})
        except Exception as e:
            return _err('DB_ERROR', str(e), 500)

    @app.route('/api/incidents', methods=['GET'])
    def api_list_incidents():
        """List all incidents with optional filtering."""
        status = request.args.get('status')
        limit = min(int(request.args.get('limit', 50)), 100)
        try:
            incidents = agent.incident_service.list_incidents(limit=limit, status=status)
            return jsonify(sanitize({'incidents': incidents, 'total': len(incidents)}))
        except Exception as e:
            return _err('DB_ERROR', str(e), 500)

    @app.route('/api/incidents/<inc_id>', methods=['GET'])
    def api_get_incident(inc_id):
        """Get full details of a specific incident."""
        try:
            inc = agent.incident_service.get_incident(inc_id)
            if not inc:
                return _err('NOT_FOUND', f'Incident {inc_id} not found.', 404)
            return jsonify(sanitize(inc))
        except Exception as e:
            return _err('DB_ERROR', str(e), 500)

    @app.route('/api/incidents/<inc_id>', methods=['PATCH'])
    def api_update_incident(inc_id):
        """Update incident status, assigned analyst, or add note."""
        data = request.get_json(silent=True) or {}
        actor = session.get('username', 'Analyst')
        status = data.get('status')
        assigned_to = data.get('assigned_to')
        note = data.get('note')

        try:
            updated = agent.incident_service.update_incident(
                incident_id=inc_id,
                status=status,
                assigned_to=assigned_to,
                note=note,
                actor=actor
            )
            if not updated:
                return _err('NOT_FOUND', f'Incident {inc_id} not found.', 404)
            return jsonify(sanitize(updated))
        except Exception as e:
            return _err('UPDATE_FAILED', str(e), 500)

    @app.route('/api/investigations/<inv_id>/threat-intelligence', methods=['GET'])
    def api_get_investigation_threat_intel(inv_id):
        """Retrieve threat intelligence and campaign correlation for investigation."""
        inv = investigation_store.get(inv_id)
        if not inv:
            conn = get_db()
            try:
                row = conn.execute('SELECT payload_json FROM investigations WHERE investigation_id=?', (inv_id,)).fetchone()
                if row:
                    inv = json.loads(row[0])
            except Exception:
                pass
            finally:
                conn.close()

        if not inv:
            return _err('NOT_FOUND', 'Investigation not found.', 404)

        return jsonify(sanitize({
            'investigation_id': inv_id,
            'threat_intelligence': inv.get('threat_intelligence', {}),
            'campaign_correlation': inv.get('campaign_correlation', {}),
            'incident_assessment': inv.get('incident_assessment', {}),
            'module6_summary': inv.get('module6_summary', {})
        }))

    @app.route('/api/investigations/<inv_id>/related', methods=['GET'])
    def api_get_investigation_related(inv_id):
        """Retrieve related investigations."""
        inv = investigation_store.get(inv_id)
        if not inv:
            conn = get_db()
            try:
                row = conn.execute('SELECT payload_json FROM investigations WHERE investigation_id=?', (inv_id,)).fetchone()
                if row:
                    inv = json.loads(row[0])
            except Exception:
                pass
            finally:
                conn.close()

        if not inv:
            return _err('NOT_FOUND', 'Investigation not found.', 404)

        camp = inv.get('campaign_correlation', {})
        return jsonify(sanitize({
            'investigation_id': inv_id,
            'related_investigations': camp.get('related_investigations', []),
            'shared_indicators': camp.get('shared_indicators', []),
            'total_matches': camp.get('total_matches', 0),
            'status': camp.get('campaign_status', 'NO_RELATED_ACTIVITY_FOUND')
        }))

    @app.route('/api/threat-intelligence/lookup', methods=['POST'])
    def api_lookup_threat_intel():
        """Ad-hoc indicator lookup."""
        data = request.get_json(silent=True) or {}
        itype = data.get('type', 'DOMAIN')
        val = data.get('value', '').strip()
        if not val:
            return _err('INVALID_INPUT', 'Please specify an indicator value.')
        res = agent.threat_intel.lookup_indicator(itype, val)
        return jsonify(sanitize({'indicator': res, 'status': res.get('status')}))

    return {'agent': agent}


# ── Database Helpers ─────────────────────────────────────────────────────────

def _init_investigation_tables(get_db):
    conn = get_db()
    c = conn.cursor()
    c.execute("""CREATE TABLE IF NOT EXISTS investigations (
        investigation_id TEXT PRIMARY KEY,
        investigation_type TEXT NOT NULL,
        user_id INTEGER,
        target_display TEXT,
        risk_score INTEGER,
        risk_level TEXT,
        verdict TEXT,
        threat_dna TEXT,
        created_at TEXT NOT NULL,
        payload_json TEXT NOT NULL,
        input_type TEXT,
        modules_executed TEXT,
        evidence_count INTEGER)""")
    c.execute("CREATE INDEX IF NOT EXISTS idx_inv_user ON investigations(user_id, created_at)")
    c.execute("CREATE INDEX IF NOT EXISTS idx_inv_type ON investigations(investigation_type)")
    conn.commit()
    conn.close()


def _persist_investigation(get_db, report, user_id=None):
    inv_id = report.get('investigation_id', '')
    risk = report.get('risk_assessment', {})
    summary = report.get('summary', {})
    dna = report.get('threat_dna', {})

    conn = get_db()
    try:
        conn.execute("""INSERT OR REPLACE INTO investigations
            (investigation_id, investigation_type, user_id, target_display,
             risk_score, risk_level, verdict, threat_dna, created_at, payload_json,
             input_type, modules_executed, evidence_count)
            VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)""",
            (inv_id, 'unified', user_id,
             (report.get('original_input') or '')[:500],
             risk.get('composite_score', summary.get('risk_score')),
             risk.get('risk_level', summary.get('risk_level')),
             risk.get('risk_level', summary.get('verdict_label')),
             dna.get('fingerprint') if isinstance(dna, dict) else None,
             report.get('timestamp') or datetime.now().isoformat(),
             json.dumps(report, default=str),
             report.get('input_type'),
             json.dumps(report.get('modules_executed', [])),
             report.get('evidence_count', 0)))
        conn.commit()
    finally:
        conn.close()
