"""NeuraShield Institutional Directory & Email Sender Verification Engine.

Provides an enterprise institutional directory and multi-point identity verification:
- Dynamic institutional directory (Institutions, Domains, Members, Aliases)
- Sender address & domain extraction
- Claimed organization detection (via display name, signature, headers, subject)
- Institutional database correlation
- Impersonation detection vs. Authorized senders
- SPF / DKIM / DMARC verification support (or explicit NOT_AVAILABLE reporting)
- Verification audit trail (InstitutionVerificationEvents)
- CSV Import with rigorous validation
"""

import csv
import io
import re
import sqlite3
from datetime import datetime
from typing import Dict, List, Optional, Tuple, Any


def init_institution_tables(conn: sqlite3.Connection):
    """Create database tables for institutional directory if they do not exist."""
    c = conn.cursor()
    
    # 1. Institutions table
    c.execute("""
    CREATE TABLE IF NOT EXISTS institutions (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        slug TEXT UNIQUE NOT NULL,
        name TEXT NOT NULL,
        description TEXT,
        status TEXT NOT NULL DEFAULT 'ACTIVE',
        created_at TEXT NOT NULL
    )
    """)

    # 2. Institutional Domains table
    c.execute("""
    CREATE TABLE IF NOT EXISTS institution_domains (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        institution_id INTEGER NOT NULL,
        domain TEXT NOT NULL,
        domain_type TEXT NOT NULL DEFAULT 'OFFICIAL', -- OFFICIAL, PRIMARY, DEMO
        status TEXT NOT NULL DEFAULT 'ACTIVE',
        created_at TEXT NOT NULL,
        FOREIGN KEY (institution_id) REFERENCES institutions(id) ON DELETE CASCADE
    )
    """)
    c.execute("CREATE INDEX IF NOT EXISTS idx_inst_domains_domain ON institution_domains(domain)")
    c.execute("CREATE INDEX IF NOT EXISTS idx_inst_domains_inst_id ON institution_domains(institution_id)")

    # 3. Institutional Members table
    c.execute("""
    CREATE TABLE IF NOT EXISTS institution_members (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        institution_id INTEGER NOT NULL,
        email TEXT UNIQUE NOT NULL,
        display_name TEXT,
        role TEXT,
        department TEXT,
        status TEXT NOT NULL DEFAULT 'ACTIVE', -- ACTIVE, INACTIVE, SUSPENDED
        created_at TEXT NOT NULL,
        FOREIGN KEY (institution_id) REFERENCES institutions(id) ON DELETE CASCADE
    )
    """)
    c.execute("CREATE INDEX IF NOT EXISTS idx_inst_members_email ON institution_members(email)")
    c.execute("CREATE INDEX IF NOT EXISTS idx_inst_members_inst_id ON institution_members(institution_id)")

    # 4. Institutional Aliases table (e.g. "TKR College", "TKRCET", "TKR Educational Society")
    c.execute("""
    CREATE TABLE IF NOT EXISTS institution_aliases (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        institution_id INTEGER NOT NULL,
        alias TEXT NOT NULL,
        created_at TEXT NOT NULL,
        FOREIGN KEY (institution_id) REFERENCES institutions(id) ON DELETE CASCADE
    )
    """)
    c.execute("CREATE INDEX IF NOT EXISTS idx_inst_aliases_alias ON institution_aliases(alias)")

    # 5. Institutional Verification Events (Audit Log)
    c.execute("""
    CREATE TABLE IF NOT EXISTS institution_verification_events (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        institution_id INTEGER,
        email TEXT,
        domain TEXT,
        result TEXT NOT NULL,
        reason TEXT,
        raw_sender TEXT,
        claimed_org TEXT,
        confidence TEXT,
        timestamp TEXT NOT NULL,
        FOREIGN KEY (institution_id) REFERENCES institutions(id) ON DELETE SET NULL
    )
    """)
    c.execute("CREATE INDEX IF NOT EXISTS idx_inst_verif_email ON institution_verification_events(email)")
    c.execute("CREATE INDEX IF NOT EXISTS idx_inst_verif_ts ON institution_verification_events(timestamp)")

    conn.commit()


def seed_demo_institutions(conn: sqlite3.Connection):
    """Seed clearly labeled synthetic DEMO institution data for TKR College."""
    c = conn.cursor()
    c.execute("SELECT id FROM institutions WHERE slug = 'tkrcet'")
    existing = c.fetchone()
    if existing:
        return existing[0]

    now = datetime.now().isoformat()
    # Insert DEMO Institution
    c.execute("""
    INSERT INTO institutions (slug, name, description, status, created_at)
    VALUES (?, ?, ?, ?, ?)
    """, (
        'tkrcet',
        'TKR College of Engineering and Technology',
        'DEMO DATA: Synthetic test profile representing TKR College / TKR Educational Society.',
        'ACTIVE',
        now
    ))
    inst_id = c.lastrowid

    # Insert Official Domains
    demo_domains = [
        (inst_id, 'tkrcet.ac.in', 'OFFICIAL', 'ACTIVE', now),
        (inst_id, 'tkrcet.edu.in', 'OFFICIAL', 'ACTIVE', now),
        (inst_id, 'tkrcet.example', 'DEMO', 'ACTIVE', now),
    ]
    c.executemany("""
    INSERT INTO institution_domains (institution_id, domain, domain_type, status, created_at)
    VALUES (?, ?, ?, ?, ?)
    """, demo_domains)

    # Insert Aliases
    aliases = [
        (inst_id, 'TKR College', now),
        (inst_id, 'TKRCET', now),
        (inst_id, 'TKR Educational Society', now),
        (inst_id, 'TKR College of Engineering & Technology', now),
        (inst_id, 'TKR Engineering College', now),
        (inst_id, 'TKR College Administration', now),
    ]
    c.executemany("""
    INSERT INTO institution_aliases (institution_id, alias, created_at)
    VALUES (?, ?, ?)
    """, aliases)

    # Insert Clearly Labeled Synthetic Demo Members
    members = [
        (inst_id, 'faculty-demo@tkrcet.ac.in', 'Dr. K. Srinivas (Demo Faculty)', 'Faculty', 'Computer Science & Engineering', 'ACTIVE', now),
        (inst_id, 'admin-demo@tkrcet.ac.in', 'TKR College Administration (Demo)', 'Administration', 'Academic Affairs', 'ACTIVE', now),
        (inst_id, 'student-demo@tkrcet.ac.in', 'Demo Student', 'Student', 'Computer Science', 'ACTIVE', now),
        (inst_id, 'security@tkrcet.example', 'TKR Security Office (Demo)', 'IT Security', 'Information Technology', 'ACTIVE', now),
        (inst_id, 'faculty-demo@tkrcet.example', 'Demo Faculty Member', 'Faculty', 'CSE', 'ACTIVE', now),
        (inst_id, 'deactivated-demo@tkrcet.ac.in', 'Former Staff Member (Deactivated Demo)', 'Staff', 'Accounts', 'INACTIVE', now),
    ]
    c.executemany("""
    INSERT INTO institution_members (institution_id, email, display_name, role, department, status, created_at)
    VALUES (?, ?, ?, ?, ?, ?, ?)
    """, members)

    conn.commit()
    return inst_id


def extract_email_address(raw_sender: str) -> Tuple[Optional[str], Optional[str], Optional[str]]:
    """Extract display name, email address, and domain from a sender string.
    
    Examples:
        'TKR College Administration <tkrcollege.notice@gmail.com>' -> ('TKR College Administration', 'tkrcollege.notice@gmail.com', 'gmail.com')
        'security@tkrcet.example' -> (None, 'security@tkrcet.example', 'tkrcet.example')
    """
    if not raw_sender:
        return None, None, None

    raw_sender = raw_sender.strip()
    match = re.search(r'^(.*?)\s*<([^>]+)>$', raw_sender)
    if match:
        name = match.group(1).strip().strip('"\'')
        email = match.group(2).strip().lower()
    else:
        # Check if email is directly provided
        email_match = re.search(r'[\w\.-]+@[\w\.-]+\.\w+', raw_sender)
        if email_match:
            email = email_match.group(0).lower()
            name = raw_sender.replace(email, '').strip().strip('<>()"\'') or None
        else:
            email = raw_sender.strip().lower()
            name = None

    domain = email.split('@')[1].strip().lower() if '@' in email else None
    return name, email, domain


def detect_claimed_organization(
    conn: sqlite3.Connection,
    display_name: Optional[str] = None,
    explicit_claim: Optional[str] = None,
    subject: Optional[str] = None,
    body_text: Optional[str] = None
) -> Optional[Dict[str, Any]]:
    """Search institutional directory for any organization claimed in the email."""
    c = conn.cursor()

    # 1. Check explicit claim
    if explicit_claim:
        claim_clean = explicit_claim.strip().lower()
        c.execute("""
        SELECT i.id, i.name, i.slug, i.status FROM institutions i
        WHERE LOWER(i.name) = ? OR LOWER(i.slug) = ?
        """, (claim_clean, claim_clean))
        row = c.fetchone()
        if row:
            return {'id': row[0], 'name': row[1], 'slug': row[2], 'status': row[3], 'matched_by': 'explicit_claim'}

        c.execute("""
        SELECT i.id, i.name, i.slug, i.status FROM institution_aliases a
        JOIN institutions i ON a.institution_id = i.id
        WHERE LOWER(a.alias) = ?
        """, (claim_clean,))
        row = c.fetchone()
        if row:
            return {'id': row[0], 'name': row[1], 'slug': row[2], 'status': row[3], 'matched_by': 'alias_exact'}

    # 2. Fetch all active institutions and aliases for matching
    c.execute("SELECT id, name, slug, status FROM institutions WHERE status = 'ACTIVE'")
    inst_rows = c.fetchall()

    c.execute("""
    SELECT a.alias, i.id, i.name, i.slug, i.status
    FROM institution_aliases a
    JOIN institutions i ON a.institution_id = i.id
    WHERE i.status = 'ACTIVE'
    ORDER BY LENGTH(a.alias) DESC
    """)
    alias_rows = c.fetchall()

    # Search in display name
    if display_name:
        dn_lower = display_name.lower()
        # Check aliases first (often more specific or colloquial, e.g. "TKR College")
        for alias, i_id, i_name, i_slug, i_status in alias_rows:
            if re.search(r'\b' + re.escape(alias.lower()) + r'\b', dn_lower):
                return {'id': i_id, 'name': i_name, 'slug': i_slug, 'status': i_status, 'matched_by': f"display_name_alias:{alias}"}

        for i_id, i_name, i_slug, i_status in inst_rows:
            if re.search(r'\b' + re.escape(i_name.lower()) + r'\b', dn_lower):
                return {'id': i_id, 'name': i_name, 'slug': i_slug, 'status': i_status, 'matched_by': 'display_name_fullname'}

    # Search in Subject
    if subject:
        subj_lower = subject.lower()
        for alias, i_id, i_name, i_slug, i_status in alias_rows:
            if len(alias) >= 4 and re.search(r'\b' + re.escape(alias.lower()) + r'\b', subj_lower):
                return {'id': i_id, 'name': i_name, 'slug': i_slug, 'status': i_status, 'matched_by': f"subject_alias:{alias}"}

    # Search in Body (limited to top 2000 chars to avoid false positives from signatures/quotes)
    if body_text:
        body_snippet = body_text[:2000].lower()
        for alias, i_id, i_name, i_slug, i_status in alias_rows:
            if len(alias) >= 6 and re.search(r'\b' + re.escape(alias.lower()) + r'\b', body_snippet):
                return {'id': i_id, 'name': i_name, 'slug': i_slug, 'status': i_status, 'matched_by': f"body_alias:{alias}"}

    return None


def verify_sender(
    conn: sqlite3.Connection,
    raw_sender: str,
    display_name: Optional[str] = None,
    claimed_org: Optional[str] = None,
    subject: Optional[str] = None,
    body_text: Optional[str] = None,
    auth_data: Optional[Dict[str, Any]] = None
) -> Dict[str, Any]:
    """Execute the full institutional verification logic for an email sender.
    
    Returns structured verification results with checklist, evidence, and clear reason.
    """
    parsed_name, sender_email, sender_domain = extract_email_address(raw_sender)
    active_name = display_name or parsed_name or ''

    if not sender_email or not sender_domain:
        return {
            'status': 'INVALID_SENDER',
            'verdict': 'UNKNOWN',
            'confidence': 'LOW',
            'sender_email': sender_email,
            'sender_domain': sender_domain,
            'display_name': active_name,
            'claimed_organization': None,
            'reason': 'Unable to parse valid sender email address or domain from input.',
            'checklist': [],
            'evidence': []
        }

    c = conn.cursor()

    # Step 1: Detect claimed organization
    claimed_inst = detect_claimed_organization(
        conn,
        display_name=active_name,
        explicit_claim=claimed_org,
        subject=subject,
        body_text=body_text
    )

    # Step 2: Check if sender domain itself belongs to ANY institution
    c.execute("""
    SELECT i.id, i.name, i.slug, d.domain, d.domain_type, d.status
    FROM institution_domains d
    JOIN institutions i ON d.institution_id = i.id
    WHERE LOWER(d.domain) = ? AND d.status = 'ACTIVE'
    """, (sender_domain,))
    domain_match = c.fetchone()

    # Step 3: Check if sender email exists in members table
    c.execute("""
    SELECT m.id, m.institution_id, m.email, m.display_name, m.role, m.department, m.status, i.name
    FROM institution_members m
    JOIN institutions i ON m.institution_id = i.id
    WHERE LOWER(m.email) = ?
    """, (sender_email,))
    member_match = c.fetchone()

    # Authentication info handling (SPF / DKIM / DMARC)
    auth_data = auth_data or {}
    spf = (auth_data.get('spf') or 'NOT_AVAILABLE').upper()
    dkim = (auth_data.get('dkim') or 'NOT_AVAILABLE').upper()
    dmarc = (auth_data.get('dmarc') or 'NOT_AVAILABLE').upper()

    auth_summary = {
        'spf': spf,
        'dkim': dkim,
        'dmarc': dmarc,
        'has_actual_auth': any(x not in ('NOT_AVAILABLE', 'NONE', 'UNKNOWN') for x in (spf, dkim, dmarc))
    }

    # Checklist items for UI breakdown
    checklist = []
    evidence = []
    verdict = 'UNKNOWN'
    reason = ''
    matched_institution = None
    member_info = None

    # CASE A: Sender domain matches configured official domain
    if domain_match:
        inst_id, inst_name, inst_slug, matched_domain, dom_type, dom_status = domain_match
        matched_institution = {'id': inst_id, 'name': inst_name, 'slug': inst_slug, 'official_domain': matched_domain}

        checklist.append({'label': 'Institution Identified', 'status': 'PASS', 'detail': f"Matched institution: {inst_name}"})
        checklist.append({'label': 'Domain Authorized', 'status': 'PASS', 'detail': f"'{sender_domain}' is an authorized {dom_type.lower()} domain"})

        if member_match:
            m_id, m_inst_id, m_email, m_name, m_role, m_dept, m_status, m_inst_name = member_match
            member_info = {
                'id': m_id,
                'email': m_email,
                'display_name': m_name,
                'role': m_role,
                'department': m_dept,
                'status': m_status
            }

            if m_status == 'ACTIVE':
                checklist.append({'label': 'Directory Membership', 'status': 'PASS', 'detail': f"Registered member: {m_name} ({m_role}, {m_dept})"})
                checklist.append({'label': 'Account Status', 'status': 'PASS', 'detail': 'Member status is ACTIVE'})
                verdict = 'VERIFIED_INSTITUTIONAL_SENDER'
                reason = f"Verified active institutional sender for {inst_name} ({sender_domain}) ({m_name} - {m_role}, {m_dept})."
                evidence.append(f"Sender address {sender_email} is confirmed in the institutional directory of {inst_name}.")
                evidence.append(f"Domain {sender_domain} is a verified {dom_type.lower()} institutional domain.")
            else:
                checklist.append({'label': 'Directory Membership', 'status': 'WARNING', 'detail': f"Member found ({m_name}) but status is {m_status}"})
                checklist.append({'label': 'Account Status', 'status': 'FAIL', 'detail': f"Account marked {m_status}"})
                verdict = 'SUSPICIOUS'
                reason = f"Sender is registered with {inst_name}, but account status is {m_status}."
                evidence.append(f"Member account {sender_email} has non-active status: {m_status}.")
        else:
            checklist.append({'label': 'Directory Membership', 'status': 'FAIL', 'detail': f"Sender '{sender_email}' not found in active member directory"})
            checklist.append({'label': 'Account Status', 'status': 'NOT_CHECKED', 'detail': 'Not in directory'})
            verdict = 'UNVERIFIED_SENDER'
            reason = f"The sending domain '{sender_domain}' belongs to {inst_name}, but sender '{sender_email}' was not found in the member directory."
            evidence.append(f"Domain {sender_domain} is registered to {inst_name}, but sender {sender_email} is not listed in authorized member records.")

    # CASE B: Sender does NOT use official domain, BUT claims institution
    elif claimed_inst:
        inst_id = claimed_inst['id']
        inst_name = claimed_inst['name']
        inst_slug = claimed_inst['slug']

        # Get official domains for this institution
        c.execute("SELECT domain FROM institution_domains WHERE institution_id = ? AND status = 'ACTIVE'", (inst_id,))
        official_domains = [r[0] for r in c.fetchall()]
        official_str = ', '.join(official_domains) if official_domains else 'No official domain configured'

        matched_institution = {'id': inst_id, 'name': inst_name, 'slug': inst_slug, 'official_domains': official_domains}

        checklist.append({'label': 'Claimed Organization', 'status': 'PASS', 'detail': f"Identified claim to represent {inst_name}"})
        checklist.append({'label': 'Domain Authorized', 'status': 'FAIL', 'detail': f"Sender domain '{sender_domain}' does NOT match official domain(s) ({official_str})"})
        checklist.append({'label': 'Directory Membership', 'status': 'FAIL', 'detail': f"Sender '{sender_email}' not found in authorized institutional directory"})

        verdict = 'POSSIBLE_ORGANIZATION_IMPERSONATION'
        reason = (
            f"This sender could not be verified as an authorized institutional sender and the domain "
            f"('{sender_domain}') does not match the configured organization domain ({official_str})."
        )
        evidence.append(f"Display name or email content claims representation of '{inst_name}'.")
        evidence.append(f"Sender uses domain '{sender_domain}' instead of registered official domain ({official_str}).")
        evidence.append(f"Address '{sender_email}' does not exist in the institutional member directory.")

    # CASE C: Member exists in another institution or under mismatched domain
    elif member_match:
        m_id, m_inst_id, m_email, m_name, m_role, m_dept, m_status, m_inst_name = member_match
        matched_institution = {'id': m_inst_id, 'name': m_inst_name}
        checklist.append({'label': 'Directory Membership', 'status': 'PASS', 'detail': f"Member record exists for {m_inst_name}"})
        checklist.append({'label': 'Domain Authorized', 'status': 'WARNING', 'detail': f"Domain '{sender_domain}' is not registered under official domains for {m_inst_name}"})
        verdict = 'SUSPICIOUS'
        reason = f"Member is registered under {m_inst_name}, but sender domain '{sender_domain}' is not in the official domain directory."
        evidence.append(f"Sender {sender_email} is in the directory, but domain {sender_domain} is unverified.")

    # CASE D: No institutional claim and unknown domain
    else:
        checklist.append({'label': 'Institutional Affiliation', 'status': 'INFO', 'detail': 'No registered institutional affiliation claimed or detected'})
        checklist.append({'label': 'Domain Classification', 'status': 'INFO', 'detail': f"General domain: {sender_domain}"})
        verdict = 'UNKNOWN'
        reason = f"Sender does not claim affiliation with any registered institutional directory."
        evidence.append(f"No matching institutional directory records for domain '{sender_domain}' or sender '{sender_email}'.")

    # Add Authentication checklist
    if auth_summary['has_actual_auth']:
        auth_status = 'PASS' if all(x in ('PASS', 'NOT_AVAILABLE', 'NONE') for x in (spf, dkim, dmarc)) else 'FAIL'
        checklist.append({
            'label': 'Email Authentication (SPF/DKIM/DMARC)',
            'status': auth_status,
            'detail': f"SPF: {spf} | DKIM: {dkim} | DMARC: {dmarc}"
        })
    else:
        checklist.append({
            'label': 'Email Authentication (SPF/DKIM/DMARC)',
            'status': 'NOT_AVAILABLE',
            'detail': 'Authentication headers not accessible in this context'
        })

    # Log verification event to audit table
    try:
        c.execute("""
        INSERT INTO institution_verification_events
        (institution_id, email, domain, result, reason, raw_sender, claimed_org, confidence, timestamp)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            matched_institution['id'] if matched_institution else None,
            sender_email,
            sender_domain,
            verdict,
            reason,
            raw_sender[:250],
            matched_institution['name'] if matched_institution else None,
            'HIGH' if verdict in ('VERIFIED_INSTITUTIONAL_SENDER', 'POSSIBLE_ORGANIZATION_IMPERSONATION') else 'MEDIUM',
            datetime.now().isoformat()
        ))
        conn.commit()
    except Exception as e:
        print(f"Notice: Failed to log verification event: {e}")

    # Risk mapping for institutional verification
    risk_level_map = {
        'VERIFIED_INSTITUTIONAL_SENDER': 'LOW',
        'UNVERIFIED_SENDER': 'MEDIUM',
        'POSSIBLE_ORGANIZATION_IMPERSONATION': 'HIGH',
        'SUSPICIOUS': 'HIGH',
        'UNKNOWN': 'INFO',
        'INVALID_SENDER': 'MEDIUM'
    }

    return {
        'status': 'SUCCESS',
        'verdict': verdict,
        'verdict_label': verdict.replace('_', ' ').title(),
        'risk_level': risk_level_map.get(verdict, 'MEDIUM'),
        'confidence': 'HIGH' if verdict in ('VERIFIED_INSTITUTIONAL_SENDER', 'POSSIBLE_ORGANIZATION_IMPERSONATION') else 'MEDIUM',
        'sender_email': sender_email,
        'sender_domain': sender_domain,
        'display_name': active_name,
        'claimed_organization': matched_institution['name'] if matched_institution else None,
        'institution': matched_institution,
        'member': member_info,
        'reason': reason,
        'checklist': checklist,
        'evidence': evidence,
        'authentication': auth_summary,
        'timestamp': datetime.now().isoformat()
    }


def import_members_csv(conn: sqlite3.Connection, institution_id: int, csv_content: str) -> Dict[str, Any]:
    """Import institution members from a CSV string with validation.
    
    Expected CSV columns:
    email,displayName,role,department,status
    """
    c = conn.cursor()
    c.execute("SELECT id, name FROM institutions WHERE id = ?", (institution_id,))
    inst = c.fetchone()
    if not inst:
        return {'success': False, 'error': f"Institution ID {institution_id} not found."}

    reader = csv.reader(io.StringIO(csv_content.strip()))
    rows = list(reader)
    if not rows:
        return {'success': False, 'error': 'CSV content is empty.'}

    header = [h.strip().lower() for h in rows[0]]
    expected_fields = {'email'}
    if 'email' not in header:
        return {'success': False, 'error': "CSV header must include an 'email' column."}

    email_idx = header.index('email')
    name_idx = header.index('displayname') if 'displayname' in header else (header.index('name') if 'name' in header else -1)
    role_idx = header.index('role') if 'role' in header else -1
    dept_idx = header.index('department') if 'department' in header else (header.index('dept') if 'dept' in header else -1)
    status_idx = header.index('status') if 'status' in header else -1

    imported = 0
    updated = 0
    errors = []
    now = datetime.now().isoformat()

    for line_num, row in enumerate(rows[1:], start=2):
        if not row or not any(x.strip() for x in row):
            continue
        try:
            email = row[email_idx].strip().lower() if email_idx < len(row) else ''
            if not email or '@' not in email:
                errors.append(f"Line {line_num}: Invalid email '{email}'")
                continue

            name = row[name_idx].strip() if name_idx != -1 and name_idx < len(row) else email.split('@')[0]
            role = row[role_idx].strip() if role_idx != -1 and role_idx < len(row) else 'Member'
            dept = row[dept_idx].strip() if dept_idx != -1 and dept_idx < len(row) else 'General'
            status = row[status_idx].strip().upper() if status_idx != -1 and status_idx < len(row) else 'ACTIVE'
            if status not in ('ACTIVE', 'INACTIVE', 'SUSPENDED'):
                status = 'ACTIVE'

            # Upsert member
            c.execute("""
            INSERT INTO institution_members (institution_id, email, display_name, role, department, status, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(email) DO UPDATE SET
                institution_id = excluded.institution_id,
                display_name = excluded.display_name,
                role = excluded.role,
                department = excluded.department,
                status = excluded.status
            """, (institution_id, email, name, role, dept, status, now))

            if c.rowcount == 1:
                imported += 1
            else:
                updated += 1
        except Exception as e:
            errors.append(f"Line {line_num}: {str(e)}")

    conn.commit()
    return {
        'success': True,
        'institution_id': institution_id,
        'institution_name': inst[1],
        'imported': imported,
        'updated': updated,
        'errors': errors
    }
