"""Safe RFC 5322 / MIME parser for Email Intelligence.

Rules enforced here:
- Input size is capped before parsing.
- Nothing is executed or rendered. HTML is kept as text for static inspection.
- Missing headers are reported as missing — never invented.
"""
import email
import hashlib
import re
from email import policy
from email.utils import getaddresses, parsedate_to_datetime
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

from .common import domain_of, truncate

MAX_EMAIL_BYTES = 10 * 1024 * 1024        # 10 MB raw message
MAX_PARTS = 200                           # MIME parts walked
MAX_TEXT_CHARS = 500_000                  # per decoded text part
ALLOWED_EXTENSIONS = {".eml", ".txt", ""}  # raw RFC 5322 source only
UNSUPPORTED_EXTENSIONS = {
    ".msg": "Outlook .msg (OLE compound file) is not supported. Save the message as .eml (\"Save as\" / \"Download original\") and upload that.",
    ".mbox": "mbox mailboxes contain many messages. Upload a single message as .eml.",
    ".pst": "Outlook data files are not supported. Export a single message as .eml.",
}

IDENTITY_HEADERS = ["From", "Sender", "Reply-To", "Return-Path", "To", "Cc", "Bcc",
                    "Subject", "Date", "Message-ID"]
_HEADER_LINE = re.compile(rb"^[!-9;-~]+:[ \t]?", re.M)   # RFC 5322 field-name ':'


class EmailParseError(Exception):
    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code
        self.message = message


def _looks_binary(raw: bytes) -> bool:
    sample = raw[:8192]
    if not sample:
        return False
    if sample.startswith(b"\xd0\xcf\x11\xe0"):  # OLE (.msg)
        return True
    nul = sample.count(b"\x00")
    return nul > 0


def _has_header_block(raw: bytes) -> bool:
    head = raw.lstrip()[:16384]
    # header block = lines before first blank line
    block = re.split(rb"\r?\n\r?\n", head, maxsplit=1)[0]
    lines = [l for l in re.split(rb"\r?\n", block) if l and not l[:1] in (b" ", b"\t")]
    if not lines:
        return False
    header_like = sum(1 for l in lines if _HEADER_LINE.match(l))
    known = re.search(rb"^(from|to|subject|date|received|message-id|return-path|mime-version|delivered-to|authentication-results)\s*:",
                      block, re.I | re.M)
    return bool(known) and header_like >= max(1, int(len(lines) * 0.6))


def validate_input(raw: bytes, filename: Optional[str]) -> None:
    if raw is None or len(raw.strip()) == 0:
        raise EmailParseError("INVALID_INPUT", "The email input is empty.")
    if len(raw) > MAX_EMAIL_BYTES:
        raise EmailParseError("CONTENT_TOO_LARGE",
                              f"Email is {len(raw):,} bytes; the limit is {MAX_EMAIL_BYTES:,} bytes.")
    if filename:
        ext = ("." + filename.rsplit(".", 1)[-1].lower()) if "." in filename else ""
        if ext in UNSUPPORTED_EXTENSIONS:
            raise EmailParseError("UNSUPPORTED_FORMAT", UNSUPPORTED_EXTENSIONS[ext])
        if ext not in ALLOWED_EXTENSIONS:
            raise EmailParseError("UNSUPPORTED_FORMAT",
                                  f"File type '{ext}' is not accepted. Upload a raw email source file (.eml or .txt).")
    if _looks_binary(raw):
        raise EmailParseError("UNSUPPORTED_FORMAT",
                              "Input looks like a binary file, not raw email source (RFC 5322 text).")


def _addresses(values: List[str]) -> List[Dict[str, str]]:
    out = []
    for name, addr in getaddresses([v for v in values if v]):
        addr = (addr or "").strip()
        name = (name or "").strip()
        if not addr and not name:
            continue
        out.append({"display_name": name, "address": addr.lower(), "domain": domain_of(addr)})
    return out


_RCV_FROM = re.compile(r"\bfrom\s+([^\s;()]+)", re.I)
_RCV_BY = re.compile(r"\bby\s+([^\s;()]+)", re.I)
_RCV_WITH = re.compile(r"\bwith\s+([A-Za-z0-9_-]+)", re.I)
_RCV_IP = re.compile(r"\[(\d{1,3}(?:\.\d{1,3}){3}|[0-9a-fA-F:]{3,})\]")
_RCV_IP_PAREN = re.compile(r"\((?:[^()]*?\s)?(\d{1,3}(?:\.\d{1,3}){3})\)")


def _parse_date(value: Optional[str]) -> Optional[datetime]:
    if not value:
        return None
    try:
        dt = parsedate_to_datetime(value.strip())
        if dt and dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt
    except Exception:
        return None


def parse_received(values: List[str]) -> List[Dict[str, Any]]:
    """Received headers, index 0 = most recent (added by the last server)."""
    hops = []
    for idx, raw in enumerate(values):
        text = " ".join(str(raw).split())
        clause, _, date_part = text.rpartition(";")
        if not clause:
            clause, date_part = text, ""
        m_from, m_by, m_with = _RCV_FROM.search(clause), _RCV_BY.search(clause), _RCV_WITH.search(clause)
        ips = _RCV_IP.findall(clause) or _RCV_IP_PAREN.findall(clause)
        dt = _parse_date(date_part)
        hops.append({
            "index": idx,
            "from_host": m_from.group(1) if m_from else None,
            "from_ip": ips[0] if ips else None,
            "by_host": m_by.group(1) if m_by else None,
            "protocol": m_with.group(1) if m_with else None,
            "timestamp": dt.isoformat() if dt else None,
            "timestamp_parsed": dt is not None,
            "raw": truncate(text, 600),
        })
    return hops


def _decode_text(part) -> Tuple[str, Optional[str]]:
    """Decode a text/* part without executing anything. Returns (text, error)."""
    try:
        payload = part.get_payload(decode=True) or b""
    except Exception as e:
        return "", f"decode error: {type(e).__name__}"
    charset = part.get_content_charset() or "utf-8"
    try:
        text = payload.decode(charset, errors="replace")
    except LookupError:
        text = payload.decode("utf-8", errors="replace")
    if len(text) > MAX_TEXT_CHARS:
        text = text[:MAX_TEXT_CHARS]
    return text, None


def _is_attachment(part) -> bool:
    disp = (part.get_content_disposition() or "").lower()
    if disp == "attachment":
        return True
    fn = part.get_filename()
    ctype = part.get_content_type()
    if fn and not ctype.startswith("text/"):
        return True
    if fn and disp == "inline" and not ctype.startswith("text/"):
        return True
    return False


def parse_email(raw: bytes, filename: Optional[str] = None) -> Dict[str, Any]:
    validate_input(raw, filename)
    sha256 = hashlib.sha256(raw).hexdigest()
    body_only = not _has_header_block(raw)
    if body_only and filename and filename.lower().endswith(".eml"):
        # A file that claims to be an e-mail but has no RFC 5322 header block.
        raise EmailParseError("PARSER_ERROR",
                              "No RFC 5322 header block was found in this .eml file, so it cannot be parsed as an e-mail. "
                              "If you only have the message text, paste it into the text box instead.")

    if body_only:
        # The user supplied only message text: no header can be analysed or inferred.
        text = raw.decode("utf-8", errors="replace")[:MAX_TEXT_CHARS]
        is_html = bool(re.search(r"<\s*(html|body|a\s|div|table|p)\b", text, re.I))
        return {
            "input_mode": "BODY_ONLY",
            "sha256": sha256, "size_bytes": len(raw), "filename": filename,
            "headers_present": False, "header_list": [], "defects": [],
            "from": [], "sender": [], "reply_to": [], "return_path": None, "to": [], "cc": [], "bcc": [],
            "subject": None, "date": None, "date_raw": None, "message_id": None,
            "received": [], "authentication_results": [], "received_spf": [], "arc_present": False,
            "dkim_signatures": [], "x_mailer": None, "list_unsubscribe": None,
            "mime": {"content_type": "text/html" if is_html else "text/plain", "is_multipart": False,
                     "part_count": 1, "tree": []},
            "text_body": "" if is_html else text,
            "html_body": text if is_html else "",
            "attachments_raw": [],
        }

    try:
        msg = email.message_from_bytes(raw, policy=policy.default)
    except Exception as e:  # stdlib parser is lenient; this is defensive
        raise EmailParseError("PARSER_ERROR", f"Email could not be parsed: {type(e).__name__}")

    def all_values(name: str) -> List[str]:
        vals = []
        try:
            for v in msg.get_all(name) or []:
                vals.append(str(v))
        except Exception:
            # malformed header: fall back to raw bytes of the header
            for k, v in msg.raw_items():
                if k.lower() == name.lower():
                    vals.append(str(v))
        return vals

    def first(name: str) -> Optional[str]:
        v = all_values(name)
        return v[0].strip() if v else None

    defects = [type(d).__name__ for d in (msg.defects or [])]
    header_list = []
    for k, v in msg.raw_items():
        header_list.append({"name": k, "value": truncate(" ".join(str(v).split()), 2000)})

    return_path_raw = first("Return-Path")
    rp = _addresses([return_path_raw]) if return_path_raw else []

    date_raw = first("Date")
    date_dt = _parse_date(date_raw)

    dkim_sigs = []
    for sig in all_values("DKIM-Signature"):
        s = " ".join(sig.split())
        d = re.search(r"\bd=([^;\s]+)", s)
        sel = re.search(r"\bs=([^;\s]+)", s)
        algo = re.search(r"\ba=([^;\s]+)", s)
        dkim_sigs.append({"d": d.group(1).lower() if d else None, "s": sel.group(1) if sel else None,
                          "a": algo.group(1) if algo else None})

    # ── MIME walk ──
    tree, text_parts, html_parts, attachments = [], [], [], []
    count = 0
    for part in msg.walk():
        count += 1
        if count > MAX_PARTS:
            defects.append("MaxPartsExceeded")
            break
        ctype = part.get_content_type()
        entry = {"content_type": ctype, "filename": part.get_filename(),
                 "disposition": part.get_content_disposition(),
                 "transfer_encoding": part.get("Content-Transfer-Encoding")}
        tree.append(entry)
        if part.is_multipart():
            continue
        if _is_attachment(part):
            try:
                payload = part.get_payload(decode=True) or b""
            except Exception:
                payload = b""
            attachments.append({"filename": part.get_filename(), "declared_type": ctype,
                                "disposition": part.get_content_disposition(), "payload": payload})
            continue
        if ctype == "text/plain":
            t, err = _decode_text(part)
            text_parts.append(t)
        elif ctype == "text/html":
            t, err = _decode_text(part)
            html_parts.append(t)

    return {
        "input_mode": "RAW_EMAIL",
        "sha256": sha256, "size_bytes": len(raw), "filename": filename,
        "headers_present": True, "header_list": header_list, "defects": defects,
        "from": _addresses(all_values("From")),
        "sender": _addresses(all_values("Sender")),
        "reply_to": _addresses(all_values("Reply-To")),
        "return_path": rp[0] if rp else ({"display_name": "", "address": "", "domain": ""} if return_path_raw is not None else None),
        "return_path_raw": return_path_raw,
        "to": _addresses(all_values("To")),
        "cc": _addresses(all_values("Cc")),
        "bcc": _addresses(all_values("Bcc")),
        "subject": first("Subject"),
        "date_raw": date_raw,
        "date": date_dt.isoformat() if date_dt else None,
        "message_id": first("Message-ID"),
        "received": parse_received(all_values("Received")),
        "authentication_results": all_values("Authentication-Results"),
        "received_spf": all_values("Received-SPF"),
        "arc_present": bool(all_values("ARC-Authentication-Results") or all_values("ARC-Seal")),
        "dkim_signatures": dkim_sigs,
        "x_mailer": first("X-Mailer") or first("User-Agent"),
        "list_unsubscribe": first("List-Unsubscribe"),
        "mime": {"content_type": msg.get_content_type(), "is_multipart": msg.is_multipart(),
                 "part_count": count, "tree": tree[:60]},
        "text_body": "\n".join(text_parts),
        "html_body": "\n".join(html_parts),
        "attachments_raw": attachments,
    }
