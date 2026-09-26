"""MODULE 5 — QR Intelligence Engine.

Decodes QR codes from uploaded images, classifies the payload, and routes
the decoded content into the appropriate investigation module.

Supports: URL, domain, email, telephone, Wi-Fi, vCard, plain text payloads.
Uses Pillow + pyzbar for decoding.  Falls back to opencv-based decode if
pyzbar is unavailable.
"""

import base64
import hashlib
import io
import re
from datetime import datetime
from urllib.parse import urlparse


# ── QR Decoding ───────────────────────────────────────────────────────────────

def _decode_with_pyzbar(image_bytes: bytes) -> list[dict]:
    """Primary decoder using pyzbar."""
    try:
        from pyzbar import pyzbar
        from PIL import Image
        img = Image.open(io.BytesIO(image_bytes))
        # Convert to RGB if necessary (pyzbar handles grayscale well)
        if img.mode not in ('L', 'RGB'):
            img = img.convert('RGB')
        decoded = pyzbar.decode(img)
        results = []
        for obj in decoded:
            data = obj.data.decode('utf-8', errors='replace')
            results.append({
                'raw_data': data,
                'type': obj.type,  # QRCODE, EAN13, etc.
                'rect': {'x': obj.rect.left, 'y': obj.rect.top,
                         'w': obj.rect.width, 'h': obj.rect.height},
            })
        return results
    except ImportError:
        return None  # signal to try fallback
    except Exception as e:
        return [{'error': str(e)}]


def _decode_with_cv2(image_bytes: bytes) -> list[dict]:
    """Robust multi-pass QR decoder using OpenCV."""
    try:
        import cv2
        import numpy as np

        arr = np.frombuffer(image_bytes, dtype=np.uint8)
        gray = cv2.imdecode(arr, cv2.IMREAD_GRAYSCALE)
        if gray is None:
            return [{'error': 'Could not decode image bytes with OpenCV'}]

        detector = cv2.QRCodeDetector()

        # Multi-pass decoding strategies
        candidates = []

        # Pass 1: Direct grayscale
        candidates.append(('gray_raw', gray))

        # Pass 2: Inverted image (critical for dark mode / white-on-black QR codes)
        candidates.append(('inverted', cv2.bitwise_not(gray)))

        # Pass 3: Normalized size (optimal width around 500-600px for OpenCV detector)
        h, w = gray.shape[:2]
        if w > 800 or h > 800:
            scale = 600.0 / max(w, h)
            resized = cv2.resize(gray, (int(w * scale), int(h * scale)), interpolation=cv2.INTER_AREA)
            candidates.append(('resized', resized))
            candidates.append(('resized_inverted', cv2.bitwise_not(resized)))
        elif w < 250 or h < 250:
            scale = 400.0 / max(w, h)
            upscaled = cv2.resize(gray, (int(w * scale), int(h * scale)), interpolation=cv2.INTER_CUBIC)
            candidates.append(('upscaled', upscaled))
            candidates.append(('upscaled_inverted', cv2.bitwise_not(upscaled)))

        # Pass 4: Otsu thresholding
        _, otsu = cv2.threshold(gray, 0, 255, cv2.THRESH_BINARY + cv2.THRESH_OTSU)
        candidates.append(('otsu', otsu))
        candidates.append(('otsu_inverted', cv2.bitwise_not(otsu)))

        # Pass 5: Adaptive thresholding (for photos with shadows/gradients)
        adaptive = cv2.adaptiveThreshold(gray, 255, cv2.ADAPTIVE_THRESH_GAUSSIAN_C, cv2.THRESH_BINARY, 51, 10)
        candidates.append(('adaptive', adaptive))

        # Pass 6: Contrast enhancement via CLAHE
        clahe = cv2.createCLAHE(clipLimit=2.5, tileGridSize=(8, 8))
        enhanced = clahe.apply(gray)
        candidates.append(('clahe', enhanced))

        # Try all candidates until decode succeeds
        for pass_name, mat in candidates:
            try:
                # Try single detectAndDecode
                data, points, _ = detector.detectAndDecode(mat)
                if data and data.strip():
                    return [{'raw_data': data.strip(), 'type': 'QRCODE', 'strategy': pass_name, 'rect': None}]

                # Try multi-decode if available
                if hasattr(detector, 'detectAndDecodeMulti'):
                    retval, decoded_info, points_arr, _ = detector.detectAndDecodeMulti(mat)
                    if retval and decoded_info:
                        valid = [d.strip() for d in decoded_info if d and d.strip()]
                        if valid:
                            return [{'raw_data': d, 'type': 'QRCODE', 'strategy': f"{pass_name}_multi", 'rect': None} for d in valid]
            except Exception:
                continue

        return []
    except ImportError:
        return None
    except Exception as e:
        return [{'error': str(e)}]


def _decode_with_segno(image_bytes: bytes) -> list[dict]:
    """Last-resort fallback using PIL."""
    try:
        from PIL import Image
        img = Image.open(io.BytesIO(image_bytes))
        return []
    except Exception:
        return []


def decode_qr_image(image_bytes: bytes) -> dict:
    """Decode QR code(s) from raw image bytes with fallback chain."""
    timestamp = datetime.now().isoformat()

    if not image_bytes or len(image_bytes) < 10:
        return {
            'detected': False, 'codes': [], 'code_count': 0, 'error': 'Empty or invalid image data',
            'decoder_used': 'NONE', 'decode_timestamp': timestamp,
        }

    # Validate image format
    valid_headers = [
        b'\x89PNG',    # PNG
        b'\xff\xd8',   # JPEG
        b'GIF8',       # GIF
        b'BM',         # BMP
        b'RIFF',       # WEBP
    ]
    is_valid = any(image_bytes[:len(h)] == h for h in valid_headers)
    if not is_valid:
        try:
            from PIL import Image
            Image.open(io.BytesIO(image_bytes)).verify()
        except Exception:
            return {
                'detected': False, 'codes': [], 'code_count': 0,
                'error': 'Unsupported image format. Please upload PNG, JPEG, GIF, BMP, or WEBP.',
                'decoder_used': 'NONE', 'decode_timestamp': timestamp,
            }

    # Primary: try pyzbar if installed
    results = _decode_with_pyzbar(image_bytes)
    decoder = 'PYZBAR'

    # If pyzbar is not installed or returned no valid codes, use robust OpenCV multi-pass
    if not results or all('error' in r for r in results):
        cv_results = _decode_with_cv2(image_bytes)
        if cv_results and any('raw_data' in r for r in cv_results):
            results = cv_results
            decoder = 'OPENCV_MULTIPASS'
        elif not results:
            results = cv_results or []
            decoder = 'OPENCV'

    # Filter codes and errors
    errors = [r for r in results if 'error' in r]
    codes = [r for r in results if 'error' not in r and r.get('raw_data')]

    return {
        'detected': len(codes) > 0,
        'codes': codes,
        'code_count': len(codes),
        'error': errors[0]['error'] if errors and not codes else None,
        'decoder_used': decoder,
        'decode_timestamp': timestamp,
    }


# ── Payload Classification ────────────────────────────────────────────────────

# Patterns for QR payload types
URL_PATTERN = re.compile(r'^https?://', re.IGNORECASE)
DOMAIN_PATTERN = re.compile(r'^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$')
EMAIL_PATTERN = re.compile(r'^mailto:', re.IGNORECASE)
EMAIL_BARE_PATTERN = re.compile(r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$')
TEL_PATTERN = re.compile(r'^tel:', re.IGNORECASE)
WIFI_PATTERN = re.compile(r'^WIFI:', re.IGNORECASE)
VCARD_PATTERN = re.compile(r'^BEGIN:VCARD', re.IGNORECASE)
MECARD_PATTERN = re.compile(r'^MECARD:', re.IGNORECASE)
SMS_PATTERN = re.compile(r'^(?:sms|smsto):', re.IGNORECASE)
GEO_PATTERN = re.compile(r'^geo:', re.IGNORECASE)


def classify_payload(raw_data: str) -> dict:
    """Classify the decoded QR payload and extract relevant fields.

    Returns:
        {
            'payload_type': str,
            'payload_data': str,
            'extracted': dict,  # type-specific extracted fields
            'investigable': bool,
            'investigation_modules': list[str],
        }
    """
    if not raw_data or not raw_data.strip():
        return {
            'payload_type': 'EMPTY',
            'payload_data': '',
            'extracted': {},
            'investigable': False,
            'investigation_modules': [],
        }

    data = raw_data.strip()

    # URL
    if URL_PATTERN.match(data):
        parsed = urlparse(data)
        return {
            'payload_type': 'URL',
            'payload_data': data,
            'extracted': {
                'url': data,
                'domain': parsed.hostname or '',
                'scheme': parsed.scheme,
                'path': parsed.path,
            },
            'investigable': True,
            'investigation_modules': ['URL_INTELLIGENCE', 'DOMAIN_INTELLIGENCE', 'WEBPAGE_INTELLIGENCE'],
        }

    # Email (mailto: or bare address)
    if EMAIL_PATTERN.match(data):
        email_addr = data[7:].split('?')[0]  # strip mailto: and query params
        domain = email_addr.split('@')[-1] if '@' in email_addr else ''
        return {
            'payload_type': 'EMAIL',
            'payload_data': data,
            'extracted': {
                'email': email_addr,
                'domain': domain,
            },
            'investigable': True,
            'investigation_modules': ['DOMAIN_INTELLIGENCE'],
        }

    if EMAIL_BARE_PATTERN.match(data):
        domain = data.split('@')[-1]
        return {
            'payload_type': 'EMAIL',
            'payload_data': data,
            'extracted': {
                'email': data,
                'domain': domain,
            },
            'investigable': True,
            'investigation_modules': ['DOMAIN_INTELLIGENCE'],
        }

    # Telephone
    if TEL_PATTERN.match(data):
        phone = data[4:]
        return {
            'payload_type': 'TELEPHONE',
            'payload_data': data,
            'extracted': {'phone_number': phone},
            'investigable': False,
            'investigation_modules': [],
        }

    # Wi-Fi
    if WIFI_PATTERN.match(data):
        extracted = _parse_wifi_payload(data)
        return {
            'payload_type': 'WIFI',
            'payload_data': data,
            'extracted': extracted,
            'investigable': False,
            'investigation_modules': [],
            'security_notes': _assess_wifi_security(extracted),
        }

    # vCard
    if VCARD_PATTERN.match(data):
        return {
            'payload_type': 'VCARD',
            'payload_data': data,
            'extracted': _parse_vcard_basic(data),
            'investigable': False,
            'investigation_modules': [],
        }

    # MeCard
    if MECARD_PATTERN.match(data):
        return {
            'payload_type': 'MECARD',
            'payload_data': data,
            'extracted': {},
            'investigable': False,
            'investigation_modules': [],
        }

    # SMS
    if SMS_PATTERN.match(data):
        return {
            'payload_type': 'SMS',
            'payload_data': data,
            'extracted': {},
            'investigable': False,
            'investigation_modules': [],
        }

    # Geo
    if GEO_PATTERN.match(data):
        return {
            'payload_type': 'GEO',
            'payload_data': data,
            'extracted': {},
            'investigable': False,
            'investigation_modules': [],
        }

    # Bare domain (no protocol)
    if DOMAIN_PATTERN.match(data) and len(data) <= 253:
        return {
            'payload_type': 'DOMAIN',
            'payload_data': data,
            'extracted': {'domain': data.lower()},
            'investigable': True,
            'investigation_modules': ['DOMAIN_INTELLIGENCE'],
        }

    # Plain text (fallback)
    # Check if it looks like a URL without protocol
    if '.' in data and ' ' not in data[:50] and len(data) < 500:
        # Might be a URL without protocol
        try:
            test_url = 'https://' + data
            parsed = urlparse(test_url)
            if parsed.hostname and '.' in parsed.hostname:
                return {
                    'payload_type': 'URL_IMPLICIT',
                    'payload_data': data,
                    'extracted': {
                        'url': test_url,
                        'domain': parsed.hostname,
                        'implicit': True,
                    },
                    'investigable': True,
                    'investigation_modules': ['URL_INTELLIGENCE', 'DOMAIN_INTELLIGENCE'],
                }
        except Exception:
            pass

    return {
        'payload_type': 'TEXT',
        'payload_data': data[:2000],  # Limit stored text
        'extracted': {},
        'investigable': False,
        'investigation_modules': [],
    }


def _parse_wifi_payload(data: str) -> dict:
    """Parse WIFI:T:WPA;S:NetworkName;P:Password;; format."""
    result = {}
    parts = data[5:].rstrip(';').split(';')
    for p in parts:
        if ':' in p:
            key, val = p.split(':', 1)
            key = key.upper()
            if key == 'T':
                result['encryption'] = val
            elif key == 'S':
                result['ssid'] = val
            elif key == 'P':
                result['password_present'] = bool(val)
                # Never store actual Wi-Fi passwords
            elif key == 'H':
                result['hidden'] = val.upper() == 'TRUE'
    return result


def _assess_wifi_security(wifi_info: dict) -> list[str]:
    """Generate security notes for Wi-Fi QR payloads."""
    notes = []
    enc = wifi_info.get('encryption', '').upper()
    if enc in ('', 'NOPASS', 'NONE'):
        notes.append('Wi-Fi network has no encryption — traffic can be intercepted.')
    elif enc == 'WEP':
        notes.append('WEP encryption is deprecated and trivially breakable.')
    elif enc in ('WPA', 'WPA2', 'WPA3'):
        notes.append(f'{enc} encryption detected.')
    if wifi_info.get('hidden'):
        notes.append('Network is hidden (not broadcast). This is sometimes used for security through obscurity.')
    if wifi_info.get('password_present'):
        notes.append('A password is embedded in this QR code. Anyone scanning it gains network access.')
    return notes


def _parse_vcard_basic(data: str) -> dict:
    """Extract basic fields from a vCard."""
    result = {}
    for line in data.split('\n'):
        line = line.strip()
        if line.upper().startswith('FN:'):
            result['full_name'] = line[3:]
        elif line.upper().startswith('ORG:'):
            result['organization'] = line[4:]
        elif line.upper().startswith('TEL'):
            result['has_phone'] = True
        elif line.upper().startswith('EMAIL'):
            val = line.split(':', 1)[-1] if ':' in line else ''
            if val:
                result['email'] = val
        elif line.upper().startswith('URL'):
            val = line.split(':', 1)[-1] if ':' in line else ''
            if val:
                result['url'] = val
    return result


# ── QR Analysis Report Builder ────────────────────────────────────────────────

def build_qr_analysis(image_bytes: bytes, filename: str = None) -> dict:
    """Full QR intelligence analysis: decode + classify + observations.

    Returns a structured QR analysis dict ready for the investigation agent.
    """
    # Compute file hash for evidence tracking
    file_hash = hashlib.sha256(image_bytes).hexdigest()

    # Decode
    decode_result = decode_qr_image(image_bytes)

    analysis = {
        'qr_detected': decode_result['detected'],
        'decode_status': 'SUCCESS' if decode_result['detected'] else 'NO_QR_FOUND',
        'code_count': decode_result.get('code_count', 0),
        'decoder_used': decode_result['decoder_used'],
        'decode_timestamp': decode_result['decode_timestamp'],
        'error': decode_result.get('error'),
        'file_info': {
            'filename': filename,
            'size_bytes': len(image_bytes),
            'sha256': file_hash,
        },
        'payloads': [],
        'observations': [],
    }

    if not decode_result['detected']:
        if decode_result.get('error'):
            analysis['observations'].append({
                'category': 'QR_DECODE',
                'observation': f'QR decode error: {decode_result["error"]}',
                'status': 'FAILED',
                'confidence': 'VERIFIED',
            })
        else:
            analysis['observations'].append({
                'category': 'QR_DECODE',
                'observation': 'No QR code detected in the uploaded image.',
                'status': 'NOT_FOUND',
                'confidence': 'VERIFIED',
            })
        return analysis

    # Classify each decoded payload
    for code in decode_result['codes']:
        raw = code.get('raw_data', '')
        classification = classify_payload(raw)
        payload_entry = {
            'raw_data': raw[:2000],
            'barcode_type': code.get('type', 'QRCODE'),
            'classification': classification,
        }
        analysis['payloads'].append(payload_entry)

        # Generate observations
        ptype = classification['payload_type']
        analysis['observations'].append({
            'category': 'QR_PAYLOAD',
            'observation': f'QR payload classified as {ptype}.',
            'payload_type': ptype,
            'status': 'VERIFIED',
            'confidence': 'VERIFIED',
        })

        if ptype == 'URL':
            url = classification['extracted'].get('url', '')
            analysis['observations'].append({
                'category': 'QR_URL',
                'observation': f'QR code contains URL: {url[:100]}',
                'value': url,
                'status': 'VERIFIED',
                'confidence': 'VERIFIED',
            })
        elif ptype == 'URL_IMPLICIT':
            url = classification['extracted'].get('url', '')
            analysis['observations'].append({
                'category': 'QR_URL',
                'observation': f'QR text appears to be a URL without protocol: {raw[:100]}',
                'value': url,
                'status': 'INFERRED',
                'confidence': 'INFERRED',
            })
        elif ptype == 'EMAIL':
            analysis['observations'].append({
                'category': 'QR_EMAIL',
                'observation': f'QR code contains email address.',
                'value': classification['extracted'].get('email', ''),
                'status': 'VERIFIED',
                'confidence': 'VERIFIED',
            })
        elif ptype == 'WIFI':
            notes = classification.get('security_notes', [])
            for note in notes:
                analysis['observations'].append({
                    'category': 'QR_WIFI_SECURITY',
                    'observation': note,
                    'status': 'VERIFIED',
                    'confidence': 'VERIFIED',
                })
        elif ptype == 'TEXT':
            analysis['observations'].append({
                'category': 'QR_TEXT',
                'observation': f'QR code contains plain text ({len(raw)} characters).',
                'status': 'VERIFIED',
                'confidence': 'VERIFIED',
            })

    # Check for suspicious QR indicators
    if analysis['code_count'] > 1:
        analysis['observations'].append({
            'category': 'QR_SUSPICIOUS',
            'observation': f'Multiple QR codes detected in single image ({analysis["code_count"]}). This is unusual.',
            'status': 'VERIFIED',
            'confidence': 'VERIFIED',
        })

    return analysis
