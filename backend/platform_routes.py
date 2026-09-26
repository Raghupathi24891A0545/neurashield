"""NeuraShield Master Platform Unified Routes & APIs.

Registers all platform-level capabilities for Modules 7 to 21:
- Module 7: Continuous Threat Monitoring (/monitoring & /api/monitoring)
- Module 9: Brand Impersonation Intelligence (/brand-impersonation & /api/brand)
- Module 16: Adversarial Resilience Lab (/adversarial-resilience & /api/resilience)
- Module 17: Model Self-Audit (/model-self-audit & /api/model-audit)
- Module 19: Security & Model Analytics (/security-analytics & /api/analytics)
- Module 20: Cybercrime Evidence Workflow (/evidence-packages & /api/evidence-packages)
- Module 21: Cybersecurity News (/cybersecurity-news & /api/news)
"""

from datetime import datetime
import json
import os
from typing import Any, Dict
from flask import jsonify, make_response, redirect, render_template, request, session

from backend.monitoring_service import MonitoringService
from backend.brand_service import evaluate_brand_impersonation
from backend.resilience_service import AdversarialResilienceService
from backend.audit_service import ModelSelfAuditService
from backend.analytics_service import SecurityAnalyticsService
from backend.evidence_workflow import CybercrimeEvidenceService, OFFICIAL_PORTALS
from backend.news_service import CybersecurityNewsService


def register_platform_routes(app, deps: Dict[str, Any]):
    """Register all platform routes and APIs."""
    get_db = deps['get_db_connection']
    project_root = deps.get('project_root') or os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
    sanitize = deps.get('sanitize_for_json', lambda x: x)

    # Initialize Services
    monitoring_svc = MonitoringService(get_db, deps)
    resilience_svc = AdversarialResilienceService(deps)
    audit_svc = ModelSelfAuditService(project_root)
    analytics_svc = SecurityAnalyticsService(get_db)
    evidence_svc = CybercrimeEvidenceService(get_db)
    news_svc = CybersecurityNewsService(get_db)

    def _cors_json(data, status=200):
        resp = make_response(jsonify(data), status)
        resp.headers['Access-Control-Allow-Origin'] = '*'
        resp.headers['Access-Control-Allow-Methods'] = 'GET, POST, PUT, PATCH, DELETE, OPTIONS'
        resp.headers['Access-Control-Allow-Headers'] = 'Content-Type, Authorization, X-Requested-With'
        return resp

    # ══════════════════════════════════════════════════════════════════════════
    # MODULE 7: CONTINUOUS THREAT MONITORING
    # ══════════════════════════════════════════════════════════════════════════

    @app.route('/monitoring')
    def monitoring_page():
        return render_template(
            'monitoring.html',
            username=session.get('username', 'Analyst'),
            role=session.get('role', 'user')
        )

    @app.route('/api/monitoring', methods=['GET', 'POST', 'OPTIONS'])
    def api_monitoring():
        if request.method == 'OPTIONS':
            return _cors_json({'status': 'OK'})

        if request.method == 'GET':
            status_filter = request.args.get('status')
            assets = monitoring_svc.list_monitored_assets(status=status_filter)
            return _cors_json(sanitize({'assets': assets, 'total': len(assets)}))

        elif request.method == 'POST':
            data = request.get_json(silent=True) or request.form or {}
            target = (data.get('target') or '').strip()
            asset_type = (data.get('asset_type') or 'DOMAIN').upper()
            label = (data.get('label') or '').strip() or None
            interval = int(data.get('interval') or 3600)

            if not target:
                return _cors_json({'error': 'Target domain or URL is required.'}, 400)

            try:
                res = monitoring_svc.create_monitored_asset(target, asset_type, label, interval)
                return _cors_json(sanitize(res), 201)
            except Exception as e:
                return _cors_json({'error': str(e)}, 500)

    @app.route('/api/monitoring/<int:config_id>', methods=['GET', 'DELETE', 'OPTIONS'])
    def api_monitoring_asset_detail(config_id):
        if request.method == 'OPTIONS':
            return _cors_json({'status': 'OK'})

        if request.method == 'GET':
            asset = monitoring_svc.get_monitored_asset(config_id)
            if not asset:
                return _cors_json({'error': 'Monitored asset not found.'}, 404)
            return _cors_json(sanitize(asset))

        elif request.method == 'DELETE':
            monitoring_svc.delete_asset(config_id)
            return _cors_json({'success': True, 'message': f'Asset #{config_id} deleted.'})

    @app.route('/api/monitoring/<int:config_id>/check', methods=['POST', 'OPTIONS'])
    def api_monitoring_check_asset(config_id):
        if request.method == 'OPTIONS':
            return _cors_json({'status': 'OK'})
        try:
            res = monitoring_svc.check_asset(config_id, trigger_agent=True)
            return _cors_json(sanitize(res))
        except Exception as e:
            return _cors_json({'error': str(e)}, 500)

    @app.route('/api/monitoring/events', methods=['GET', 'OPTIONS'])
    def api_monitoring_events():
        if request.method == 'OPTIONS':
            return _cors_json({'status': 'OK'})
        sev = request.args.get('severity')
        limit = min(int(request.args.get('limit', 50)), 100)
        evs = monitoring_svc.list_all_events(limit=limit, severity=sev)
        return _cors_json(sanitize({'events': evs, 'total': len(evs)}))

    # ══════════════════════════════════════════════════════════════════════════
    # MODULE 9: BRAND IMPERSONATION INTELLIGENCE
    # ══════════════════════════════════════════════════════════════════════════

    @app.route('/brand-impersonation')
    def brand_impersonation_page():
        return render_template(
            'brand_impersonation.html',
            username=session.get('username', 'Analyst'),
            role=session.get('role', 'user')
        )

    @app.route('/api/brand/profiles', methods=['GET', 'OPTIONS'])
    def api_brand_profiles():
        if request.method == 'OPTIONS':
            return _cors_json({'status': 'OK'})
        from backend.brand_service import BRAND_PROFILES
        profiles = []
        for k, v in BRAND_PROFILES.items():
            profiles.append({
                'name': v.get('name', k.title()),
                'official_domain': (v.get('official_domains') or [''])[0],
                'official_domains': v.get('official_domains', []),
                'category': 'Institutional' if 'college' in k or 'tkr' in k else 'Enterprise'
            })
        return _cors_json({'status': 'AVAILABLE', 'profiles': profiles})

    @app.route('/api/brand/analyze', methods=['POST', 'OPTIONS'])
    @app.route('/api/brand/evaluate', methods=['POST', 'OPTIONS'])
    def api_brand_analyze():
        if request.method == 'OPTIONS':
            return _cors_json({'status': 'OK'})

        data = request.get_json(silent=True) or request.form or {}
        url = (data.get('url') or data.get('target') or data.get('website_url') or '').strip() or None
        domain = (data.get('domain') or data.get('sender_domain') or '').strip() or None
        sender_email = (data.get('sender_email') or data.get('sender') or data.get('sender_address') or '').strip() or None
        claimed_org = (data.get('claimed_org') or data.get('brand') or data.get('claimed_brand') or '').strip() or None
        page_title = (data.get('page_title') or '').strip() or None
        has_pwd = bool(data.get('has_password_field', False))

        if not url and not domain and not sender_email and not claimed_org:
            return _cors_json({'error': 'Specify at least a URL, domain, sender, or claimed brand.'}, 400)

        res = evaluate_brand_impersonation(
            target_url=url,
            domain=domain,
            sender_email=sender_email,
            claimed_org=claimed_org,
            page_title=page_title,
            has_password_field=has_pwd
        )
        return _cors_json(sanitize(res))

    # ══════════════════════════════════════════════════════════════════════════
    # MODULE 16: ADVERSARIAL RESILIENCE LAB
    # ══════════════════════════════════════════════════════════════════════════

    @app.route('/adversarial-resilience')
    def adversarial_resilience_page():
        return render_template(
            'resilience_lab.html',
            username=session.get('username', 'Analyst'),
            role=session.get('role', 'user')
        )

    @app.route('/api/resilience/presets', methods=['GET', 'OPTIONS'])
    def api_resilience_presets():
        if request.method == 'OPTIONS':
            return _cors_json({'status': 'OK'})
        return _cors_json({
            'perturbations': resilience_svc.get_supported_perturbations(),
            'presets': [
                {'name': 'Direct Credential Target', 'url': 'https://secure-login-account-verify.com/login'},
                {'name': 'Institutional Impersonation Target', 'url': 'https://tkrcet-exam-results-portal.net/auth'},
                {'name': 'Suspicious Financial Link', 'url': 'https://paypal-security-update-center.net/dispute'}
            ]
        })

    @app.route('/api/resilience/test', methods=['POST', 'OPTIONS'])
    def api_resilience_test():
        if request.method == 'OPTIONS':
            return _cors_json({'status': 'OK'})

        data = request.get_json(silent=True) or request.form or {}
        url = (data.get('url') or data.get('target') or '').strip()
        ptype = (data.get('perturbation_type') or 'HEX_ENCODING').upper()

        if not url:
            return _cors_json({'error': 'Target URL is required.'}, 400)

        try:
            res = resilience_svc.run_resilience_test(url, ptype)
            return _cors_json(sanitize(res))
        except Exception as e:
            return _cors_json({'error': str(e)}, 500)

    # ══════════════════════════════════════════════════════════════════════════
    # MODULE 17: MODEL SELF-AUDIT
    # ══════════════════════════════════════════════════════════════════════════

    @app.route('/model-self-audit')
    def model_self_audit_page():
        return render_template(
            'model_audit.html',
            username=session.get('username', 'Analyst'),
            role=session.get('role', 'user')
        )

    @app.route('/api/model-audit/metrics', methods=['GET', 'OPTIONS'])
    def api_model_audit_metrics():
        if request.method == 'OPTIONS':
            return _cors_json({'status': 'OK'})
        audits = audit_svc.get_all_audits()
        return _cors_json(sanitize(audits))

    # ══════════════════════════════════════════════════════════════════════════
    # MODULE 19: SECURITY & MODEL ANALYTICS
    # ══════════════════════════════════════════════════════════════════════════

    @app.route('/security-analytics')
    def security_analytics_page():
        return render_template(
            'analytics.html',
            username=session.get('username', 'Analyst'),
            role=session.get('role', 'user')
        )

    @app.route('/api/analytics', methods=['GET', 'OPTIONS'])
    def api_analytics():
        if request.method == 'OPTIONS':
            return _cors_json({'status': 'OK'})
        telemetry = analytics_svc.get_platform_analytics()
        return _cors_json(sanitize(telemetry))

    # ══════════════════════════════════════════════════════════════════════════
    # MODULE 20: CYBERCRIME EVIDENCE WORKFLOW
    # ══════════════════════════════════════════════════════════════════════════

    @app.route('/evidence-packages')
    def evidence_packages_page():
        return render_template(
            'evidence_package.html',
            username=session.get('username', 'Analyst'),
            role=session.get('role', 'user')
        )

    @app.route('/api/evidence-packages', methods=['POST', 'OPTIONS'])
    @app.route('/api/evidence-package/build', methods=['POST', 'OPTIONS'])
    def api_create_evidence_package():
        if request.method == 'OPTIONS':
            return _cors_json({'status': 'OK'})

        data = request.get_json(silent=True) or request.form or {}
        inv_id = (data.get('investigation_id') or '').strip()
        investigator = session.get('username') or data.get('investigator') or 'SOC Analyst'
        notes = (data.get('notes') or data.get('incident_description') or '').strip() or None

        if not inv_id:
            return _cors_json({'error': 'Investigation ID is required.'}, 400)

        try:
            pkg = evidence_svc.build_evidence_package(inv_id, investigator_name=investigator, notes=notes)
            return _cors_json(sanitize(pkg), 201)
        except Exception as e:
            return _cors_json({'error': str(e)}, 500)

    @app.route('/api/evidence-packages/<package_id>', methods=['GET', 'OPTIONS'])
    def api_get_evidence_package(package_id):
        if request.method == 'OPTIONS':
            return _cors_json({'status': 'OK'})
        pkg = evidence_svc.get_package(package_id)
        if not pkg:
            return _cors_json({'error': 'Evidence package not found.'}, 404)
        return _cors_json(sanitize(pkg))

    @app.route('/api/investigations/<inv_id>/evidence-package', methods=['GET', 'OPTIONS'])
    def api_investigation_evidence_package(inv_id):
        if request.method == 'OPTIONS':
            return _cors_json({'status': 'OK'})
        try:
            pkg = evidence_svc.build_evidence_package(inv_id, investigator_name=session.get('username', 'SOC Analyst'))
            return _cors_json(sanitize(pkg))
        except Exception as e:
            return _cors_json({'error': str(e)}, 404)

    # ══════════════════════════════════════════════════════════════════════════
    # MODULE 21: CYBERSECURITY NEWS & THREAT ADVISORIES
    # ══════════════════════════════════════════════════════════════════════════

    @app.route('/cybersecurity-news')
    def cybersecurity_news_page():
        return render_template(
            'news.html',
            username=session.get('username', 'Analyst'),
            role=session.get('role', 'user')
        )

    @app.route('/api/news', methods=['GET', 'OPTIONS'])
    def api_news():
        if request.method == 'OPTIONS':
            return _cors_json({'status': 'OK'})
        category = request.args.get('category')
        limit = min(int(request.args.get('limit', 20)), 50)
        news_data = news_svc.get_news(category=category, limit=limit)
        if isinstance(news_data, dict):
            news_data['news'] = news_data.get('items', [])
        return _cors_json(sanitize(news_data))

    print("Platform routes (Modules 7-21) registered successfully.")
