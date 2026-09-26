"""Static attachment analysis. Nothing is executed, opened in an application,
or extracted to disk. Archives are only listed (central directory), never
decompressed. Office files are checked for a VBA project entry by name only."""
import hashlib
import io
import re
import zipfile
from typing import Any, Dict, List, Optional

from .common import truncate

EXECUTABLE_EXT = {"exe", "scr", "com", "pif", "bat", "cmd", "msi", "msp", "dll", "cpl", "js", "jse", "vbs", "vbe",
                  "wsf", "wsh", "hta", "ps1", "psm1", "jar", "lnk", "reg", "chm", "scf", "application", "gadget",
                  "appx", "msix", "sh", "apk", "dmg", "pkg", "app"}
DISK_IMAGE_EXT = {"iso", "img", "vhd", "vhdx"}
MACRO_EXT = {"docm", "dotm", "xlsm", "xltm", "xlam", "pptm", "potm", "ppam", "sldm"}
LEGACY_OFFICE_EXT = {"doc", "dot", "xls", "xlt", "ppt", "pot"}
HTML_EXT = {"html", "htm", "shtml", "xhtml", "svg", "mht", "mhtml"}
ARCHIVE_EXT = {"zip", "rar", "7z", "gz", "tgz", "tar", "bz2", "xz", "cab", "ace", "arj", "lzh"}
DOC_DECOY_EXT = {"pdf", "doc", "docx", "xls", "xlsx", "jpg", "jpeg", "png", "txt", "rtf", "ppt", "pptx"}
MAX_ZIP_ENTRIES = 500

MAGIC = [
    (b"MZ", "Windows executable (PE)"),
    (b"\x7fELF", "ELF executable"),
    (b"%PDF", "PDF document"),
    (b"PK\x03\x04", "ZIP container (ZIP / OOXML / JAR / APK)"),
    (b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1", "OLE compound file (legacy Office / MSI)"),
    (b"Rar!\x1a\x07", "RAR archive"),
    (b"7z\xbc\xaf\x27\x1c", "7-Zip archive"),
    (b"\x1f\x8b", "GZIP"),
    (b"\x89PNG", "PNG image"),
    (b"\xff\xd8\xff", "JPEG image"),
    (b"GIF8", "GIF image"),
    (b"{\\rtf", "RTF document"),
    (b"CD001", "ISO image"),
]
EXPECTED_MAGIC = {
    "pdf": "PDF document", "zip": "ZIP container (ZIP / OOXML / JAR / APK)",
    "docx": "ZIP container (ZIP / OOXML / JAR / APK)", "xlsx": "ZIP container (ZIP / OOXML / JAR / APK)",
    "pptx": "ZIP container (ZIP / OOXML / JAR / APK)", "docm": "ZIP container (ZIP / OOXML / JAR / APK)",
    "xlsm": "ZIP container (ZIP / OOXML / JAR / APK)", "png": "PNG image", "jpg": "JPEG image", "jpeg": "JPEG image",
    "gif": "GIF image", "doc": "OLE compound file (legacy Office / MSI)", "xls": "OLE compound file (legacy Office / MSI)",
    "ppt": "OLE compound file (legacy Office / MSI)", "rar": "RAR archive", "7z": "7-Zip archive", "gz": "GZIP",
    "exe": "Windows executable (PE)", "dll": "Windows executable (PE)", "rtf": "RTF document",
}


def _sniff(data: bytes) -> Optional[str]:
    for sig, name in MAGIC:
        if data.startswith(sig):
            return name
    if len(data) > 0x8006 and data[0x8001:0x8006] == b"CD001":
        return "ISO image"
    head = data[:512].lstrip().lower()
    if head.startswith((b"<!doctype html", b"<html", b"<svg", b"<?xml")) or b"<script" in head:
        return "HTML/XML/SVG markup"
    return None


def _extensions(filename: str) -> List[str]:
    name = filename.strip().lower().rstrip(". ")
    parts = name.split(".")
    return parts[1:] if len(parts) > 1 else []


def _zip_listing(data: bytes) -> Dict[str, Any]:
    try:
        zf = zipfile.ZipFile(io.BytesIO(data))
    except zipfile.BadZipFile:
        return {"readable": False, "reason": "Not a valid ZIP central directory"}
    except Exception as e:
        return {"readable": False, "reason": type(e).__name__}
    infos = zf.infolist()
    names, encrypted, total, dangerous, has_vba = [], False, 0, [], False
    for i in infos[:MAX_ZIP_ENTRIES]:
        n = i.filename
        # path components are only read, never written: no traversal risk
        names.append(truncate(n, 200))
        total += i.file_size
        if i.flag_bits & 0x1:
            encrypted = True
        exts = _extensions(n.rsplit("/", 1)[-1])
        if exts and (exts[-1] in EXECUTABLE_EXT or exts[-1] in DISK_IMAGE_EXT or exts[-1] in HTML_EXT):
            dangerous.append(truncate(n, 200))
        if n.lower().endswith("vbaproject.bin"):
            has_vba = True
    ratio = (total / max(1, len(data))) if data else 0
    return {"readable": True, "entry_count": len(infos), "entries": names[:50],
            "entries_truncated": len(infos) > 50, "encrypted_entries": encrypted,
            "total_uncompressed_bytes": total, "compression_ratio": round(ratio, 1),
            "possible_decompression_bomb": ratio > 200 and total > 50 * 1024 * 1024,
            "dangerous_entries": dangerous[:20], "vba_project_present": has_vba}


def _pdf_markers(data: bytes) -> List[str]:
    found = []
    for marker in (b"/JavaScript", b"/JS", b"/OpenAction", b"/AA", b"/Launch", b"/EmbeddedFile", b"/URI", b"/SubmitForm", b"/AcroForm"):
        if re.search(re.escape(marker) + rb"[\s/<\[(]", data[:5 * 1024 * 1024]):
            found.append(marker.decode())
    return found


def analyze_attachment(item: Dict[str, Any]) -> Dict[str, Any]:
    data: bytes = item.get("payload") or b""
    filename = item.get("filename") or ""
    exts = _extensions(filename) if filename else []
    last = exts[-1] if exts else ""
    sniffed = _sniff(data)
    out = {
        "filename": filename or None,
        "filename_available": bool(filename),
        "declared_mime_type": item.get("declared_type"),
        "size_bytes": len(data),
        "sha256": hashlib.sha256(data).hexdigest() if data else None,
        "md5": hashlib.md5(data).hexdigest() if data else None,
        "extension": last or None,
        "detected_type": sniffed or "Unknown / not identified by signature",
        "flags": [],
        "static_only": True,
    }
    flags = out["flags"]
    if last in EXECUTABLE_EXT:
        flags.append({"flag": "EXECUTABLE_EXTENSION", "detail": f".{last} files can run code when opened."})
    if last in DISK_IMAGE_EXT:
        flags.append({"flag": "DISK_IMAGE", "detail": f".{last} disk images can hide executables and bypass download warnings."})
    if sniffed in ("Windows executable (PE)", "ELF executable") and last not in ("exe", "dll", "scr", "com", "msi", "sys"):
        flags.append({"flag": "EXECUTABLE_CONTENT", "detail": f"Content is a {sniffed} although the name ends in .{last or '(none)'}."})
    if len(exts) >= 2 and exts[-2] in DOC_DECOY_EXT and (last in EXECUTABLE_EXT or last in HTML_EXT or last in DISK_IMAGE_EXT):
        flags.append({"flag": "DOUBLE_EXTENSION", "detail": f"Name '{filename}' shows .{exts[-2]} but the real extension is .{last}."})
    if re.search(r"[‮‭‎‏]", filename or ""):
        flags.append({"flag": "RTL_OVERRIDE", "detail": "Filename contains Unicode direction-override characters that disguise the real extension."})
    if last in MACRO_EXT:
        flags.append({"flag": "MACRO_ENABLED_OFFICE", "detail": f".{last} is a macro-enabled Office format."})
    if last in LEGACY_OFFICE_EXT:
        flags.append({"flag": "LEGACY_OFFICE", "detail": f"Legacy .{last} files can contain macros (not inspected in depth)."})
    if last in HTML_EXT or sniffed == "HTML/XML/SVG markup":
        flags.append({"flag": "HTML_ATTACHMENT", "detail": "HTML/SVG attachments open in a browser and are commonly used for credential-harvesting pages."})
    expected = EXPECTED_MAGIC.get(last)
    if expected and sniffed and sniffed != expected:
        flags.append({"flag": "TYPE_MISMATCH", "detail": f"Extension .{last} suggests '{expected}' but content signature is '{sniffed}'."})

    if sniffed and sniffed.startswith("ZIP container"):
        listing = _zip_listing(data)
        out["archive"] = listing
        if listing.get("encrypted_entries"):
            flags.append({"flag": "ENCRYPTED_ARCHIVE", "detail": "Archive is password-protected, which prevents content scanning."})
        if listing.get("dangerous_entries"):
            flags.append({"flag": "ARCHIVE_CONTAINS_EXECUTABLE", "detail": f"Archive lists: {', '.join(listing['dangerous_entries'][:5])}"})
        if listing.get("vba_project_present"):
            flags.append({"flag": "VBA_MACRO_PRESENT", "detail": "Office file contains a vbaProject.bin (VBA macro project)."})
        if listing.get("possible_decompression_bomb"):
            flags.append({"flag": "DECOMPRESSION_BOMB", "detail": "Very high compression ratio; archive was not expanded."})
    elif last in ARCHIVE_EXT:
        out["archive"] = {"readable": False, "reason": f"{last.upper()} archives are identified but not listed (static metadata only)."}
    if sniffed == "PDF document":
        markers = _pdf_markers(data)
        out["pdf_markers"] = markers
        active = [m for m in markers if m in ("/JavaScript", "/JS", "/OpenAction", "/AA", "/Launch", "/EmbeddedFile", "/SubmitForm")]
        if active:
            flags.append({"flag": "PDF_ACTIVE_CONTENT", "detail": f"PDF contains active-content markers: {', '.join(active)}"})
    if not data:
        flags.append({"flag": "EMPTY_OR_UNDECODABLE", "detail": "Attachment payload was empty or could not be decoded."})
    return out


def analyze_attachments(raw_items: List[Dict[str, Any]]) -> Dict[str, Any]:
    items = [analyze_attachment(i) for i in raw_items[:50]]
    return {"count": len(raw_items), "analysed": len(items), "items": items,
            "note": "Static analysis only. Attachments were not opened, executed or extracted."}
