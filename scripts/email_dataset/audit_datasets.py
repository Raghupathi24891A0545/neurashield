"""Audit every downloaded e-mail dataset file BEFORE any training.

    python scripts/email_dataset/audit_datasets.py [--max-raw-messages 3000]

Writes (never touching raw/):
  reports/DATASET_AUDIT_REPORT.md   per-file facts: rows, columns, labels, field availability, missing values, duplicates
  reports/LEAKAGE_CHECK_REPORT.md   exact / near-duplicate and cross-file overlap
  reports/LABEL_MAPPING.md          observed labels + documented mapping (original labels preserved)
  audited/audit_summary.json        machine-readable summary used by the training script
Archives (.zip, .tar.bz2/.tar.gz) are extracted to extracted/ with path-traversal,
link and size checks. Extracted e-mails are parsed as text only; nothing is executed."""
import argparse
import hashlib
import json
import os
import re
import sys
import tarfile
import zipfile
from collections import Counter, defaultdict

import pandas as pd

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..")))
from common import RAW, EXTRACTED, AUDITED, REPORTS, now, log_step, load_manifest  # noqa: E402

MAX_EXTRACT_BYTES = 3 * 1024 ** 3
MAX_MEMBER_BYTES = 200 * 1024 ** 2
csv_field_size = 2 ** 31 - 1

# What the column names can tell us (verified per file below, never assumed).
FIELD_PATTERNS = {
    "sender": r"^(sender|from|from_address|email_from)$", "receiver": r"^(receiver|to|recipient|email_to)$",
    "date": r"^(date|timestamp|sent_date)$", "subject": r"^(subject|title)$",
    "body": r"^(body|text|content|message|email_text|text_combined|email body)$", "urls": r"^(urls?|links?|num_urls)$",
    "label": r"^(label|class|target|is_phishing|category|type|email type)$",
    "auth_headers": r"(spf|dkim|dmarc|authentication)", "attachments": r"attach",
}
KNOWN_SOURCE_NOTES = {
    "nazario": "Nazario phishing corpus — label 1 expected to mean PHISHING (verify counts below).",
    "nigerian": "Nigerian/advance-fee fraud corpus — label 1 means FRAUD/SCAM, not credential phishing.",
    "spamassassin": "SpamAssassin — label 1 means SPAM (may include some phishing); label 0 = ham.",
    "enron": "Enron — label 1 means SPAM; label 0 = corporate ham from 2000–2002.",
    "ling": "Ling-Spam — mailing-list ham (linguistics) vs spam; strong topic/source bias.",
    "trec": "TREC spam track — label 1 means SPAM.",
    "ceas": "CEAS 2008 challenge — label 1 means SPAM.",
    "merged_dataset": "Phishing-Email-Detection-Dataset README: spam, scam and phishing were ALL grouped under label 1 — not phishing-only.",
    "balanced_dataset": "Down-sampled version of Merged_Dataset (ham reduced) — does not reflect real-world prevalence.",
}


def norm_text(t):
    t = str(t or "").lower()
    t = re.sub(r"https?://\S+|www\.\S+", " URL ", t)
    t = re.sub(r"\S+@\S+", " EMAIL ", t)
    t = re.sub(r"\d+", "0", t)
    return re.sub(r"\s+", " ", t).strip()


def near_key(t):
    """Template key: normalised text with quoted replies and signatures trimmed, first 400 chars."""
    n = norm_text(t)
    n = re.split(r"(-----original message-----| wrote: |^> )", n)[0]
    return hashlib.sha1(n[:400].encode()).hexdigest()


def safe_extract_zip(path, dest):
    total = 0
    with zipfile.ZipFile(path) as z:
        for m in z.infolist():
            name = m.filename
            if name.startswith("/") or ".." in name.replace("\\", "/").split("/") or m.file_size > MAX_MEMBER_BYTES:
                raise ValueError(f"unsafe or oversized member: {name}")
            total += m.file_size
            if total > MAX_EXTRACT_BYTES:
                raise ValueError("archive exceeds extraction budget")
        z.extractall(dest)


def safe_extract_tar(path, dest):
    total = 0
    with tarfile.open(path) as t:
        members = []
        for m in t.getmembers():
            if not (m.isfile() or m.isdir()):
                continue  # skip links, devices, fifos
            if m.name.startswith("/") or ".." in m.name.split("/") or m.size > MAX_MEMBER_BYTES:
                raise ValueError(f"unsafe or oversized member: {m.name}")
            total += m.size
            if total > MAX_EXTRACT_BYTES:
                raise ValueError("archive exceeds extraction budget")
            members.append(m)
        try:
            t.extractall(dest, members=members, filter="data")
        except TypeError:  # Python < 3.12
            t.extractall(dest, members=members)


def audit_table(path, df):
    cols = list(df.columns)
    lower = {c: str(c).strip().lower() for c in cols}
    fields = {f: [c for c in cols if re.search(p, lower[c])] for f, p in FIELD_PATTERNS.items()}
    label_col = fields["label"][0] if fields["label"] else None
    body_col = fields["body"][0] if fields["body"] else None
    res = {"file": os.path.relpath(path, RAW), "format": os.path.splitext(path)[1].lstrip("."), "size_bytes": os.path.getsize(path),
           "rows": int(len(df)), "columns": [str(c) for c in cols], "field_availability": {k: v for k, v in fields.items()},
           "missing_values": {str(c): int(df[c].isna().sum()) for c in cols},
           "label_column": label_col, "body_column": body_col}
    if label_col:
        res["label_values"] = {str(k): int(v) for k, v in df[label_col].value_counts(dropna=False).head(20).items()}
    if body_col:
        texts = df[body_col].fillna("").astype(str)
        exact = texts.map(lambda t: hashlib.sha1(t.encode(errors="ignore")).hexdigest())
        near = texts.map(near_key)
        res["exact_duplicate_rows"] = int(exact.duplicated().sum())
        res["near_duplicate_rows"] = int(near.duplicated().sum())
        res["empty_bodies"] = int((texts.str.strip() == "").sum())
        res["median_body_chars"] = int(texts.str.len().median()) if len(texts) else 0
        res["url_in_body_rows"] = int(texts.str.contains(r"https?://|www\.", regex=True).sum())
        res["looks_anonymised"] = bool(texts.head(2000).str.contains(r"\b(ENRON|\[email\]|<EMAIL>|xxxx)\b", regex=True).mean() > 0.2)
        if label_col:
            conflict = pd.DataFrame({"n": near, "y": df[label_col]}).groupby("n")["y"].nunique()
            res["near_duplicate_groups_with_conflicting_labels"] = int((conflict > 1).sum())
        res["_near_keys"] = set(near.tolist())
    res["raw_email_available"] = False
    res["headers_available"] = bool(fields["sender"] or fields["receiver"] or fields["date"])
    res["authentication_headers_available"] = bool(fields["auth_headers"])
    res["attachments_available"] = bool(fields["attachments"])
    stem = os.path.basename(path).lower()
    res["source_note"] = next((v for k, v in KNOWN_SOURCE_NOTES.items() if k in stem), "No documented label meaning on file — must be confirmed from the dataset's documentation before use.")
    return res


def read_table(path):
    if path.endswith((".parquet", ".pq")):
        return pd.read_parquet(path)
    last = None
    for enc in ("utf-8", "latin-1"):
        for kw in ({"low_memory": False}, {"engine": "python"}):   # fast C parser first, tolerant python parser second
            try:
                return pd.read_csv(path, encoding=enc, on_bad_lines="warn", **kw)
            except UnicodeDecodeError as e:
                last = e
                break
            except Exception as e:
                last = e
    raise last


def audit_raw_messages(folder, limit):
    from model.email_intelligence.parser import parse_email, EmailParseError
    stats = Counter()
    n = 0
    for dirpath, _, files in os.walk(folder):
        for fn in files:
            if fn.startswith(".") or fn == "cmds":
                continue
            p = os.path.join(dirpath, fn)
            stats["files"] += 1
            if n >= limit:
                continue
            n += 1
            try:
                with open(p, "rb") as f:
                    parsed = parse_email(f.read(), None)
            except EmailParseError as e:
                stats[f"parse_error:{e.code}"] += 1
                continue
            stats["parsed"] += 1
            stats["has_from"] += bool(parsed["from"])
            stats["has_to"] += bool(parsed["to"])
            stats["has_date"] += bool(parsed["date"])
            stats["has_received"] += bool(parsed["received"])
            stats["has_auth_results"] += bool(parsed["authentication_results"] or parsed["received_spf"])
            stats["has_html"] += bool(parsed["html_body"])
            stats["has_attachments"] += bool(parsed["attachments_raw"])
    return dict(stats)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--max-raw-messages", type=int, default=3000)
    a = ap.parse_args()
    os.makedirs(AUDITED, exist_ok=True)
    os.makedirs(REPORTS, exist_ok=True)
    manifest = load_manifest()
    files, archives = [], []
    for dirpath, _, fns in os.walk(RAW):
        for fn in fns:
            p = os.path.join(dirpath, fn)
            if fn.endswith((".csv", ".parquet", ".pq")):
                files.append(p)
            elif fn.endswith((".zip", ".tar.bz2", ".tar.gz", ".tgz")):
                archives.append(p)
    extracted_tables, raw_dirs, errors = [], [], []
    for arc in archives:
        dest = os.path.join(EXTRACTED, os.path.relpath(arc, RAW).replace(os.sep, "__"))
        if not os.path.exists(dest):
            try:
                os.makedirs(dest)
                (safe_extract_zip if arc.endswith(".zip") else safe_extract_tar)(arc, dest)
            except Exception as e:
                errors.append({"archive": os.path.relpath(arc, RAW), "error": str(e)})
                continue
        for dp, _, fns in os.walk(dest):
            for fn in fns:
                if fn.endswith((".csv", ".parquet")):
                    extracted_tables.append(os.path.join(dp, fn))
        if "spamassassin" in arc:
            raw_dirs.append(dest)

    audits, key_sets = [], {}
    for p in files + extracted_tables:
        try:
            df = read_table(p)
        except Exception as e:
            errors.append({"file": p, "error": f"{type(e).__name__}: {e}"})
            continue
        r = audit_table(p, df)
        key_sets[r["file"]] = r.pop("_near_keys", set())
        audits.append(r)
    raw_audits = [{"folder": os.path.relpath(d, EXTRACTED), **audit_raw_messages(d, a.max_raw_messages)} for d in raw_dirs]

    overlap = []
    names = list(key_sets)
    for i in range(len(names)):
        for j in range(i + 1, len(names)):
            inter = len(key_sets[names[i]] & key_sets[names[j]])
            if inter:
                overlap.append({"a": names[i], "b": names[j], "shared_near_duplicate_templates": inter})

    summary = {"generated_at": now(), "tables": audits, "raw_message_folders": raw_audits, "cross_file_overlap": overlap,
               "errors": errors, "manifest_files": manifest.get("files", []),
               "nothing_to_audit": not (audits or raw_audits)}
    with open(os.path.join(AUDITED, "audit_summary.json"), "w") as f:
        json.dump(summary, f, indent=2, default=list)

    L = ["# DATASET_AUDIT_REPORT — Email Intelligence (Module 4)", "", f"Generated: {summary['generated_at']}", ""]
    if summary["nothing_to_audit"]:
        L += ["**No dataset files were found under `datasets/email_intelligence/raw/`.**", "",
              "Run `python scripts/email_dataset/download_datasets.py` on a machine that can reach zenodo.org and "
              "spamassassin.apache.org, then re-run this audit. No training may happen before this report lists real files.", ""]
    L += ["Legend: *raw email* = full RFC 5322 source; *CSV record* = extracted fields; field availability is inferred from column names and must be spot-checked.", ""]
    for r in audits:
        L += [f"## {r['file']}", "", f"- Format / size: {r['format']} / {r['size_bytes']:,} bytes", f"- Records: {r['rows']:,}",
              f"- Columns: {', '.join(r['columns'])}", f"- Label column: {r['label_column']} → values {r.get('label_values')}",
              f"- Documented meaning: {r['source_note']}",
              f"- Fields by column name: " + ", ".join(f"{k}={'yes' if v else 'no'}" for k, v in r["field_availability"].items()),
              f"- Raw e-mail / MIME available: no (tabular extract) · headers: {'partial' if r['headers_available'] else 'no'} · auth headers: {'yes' if r['authentication_headers_available'] else 'no'} · attachments: {'yes' if r['attachments_available'] else 'no'}",
              f"- Body stats: empty={r.get('empty_bodies')}, median chars={r.get('median_body_chars')}, rows with URLs in body={r.get('url_in_body_rows')}",
              f"- Duplicates: exact={r.get('exact_duplicate_rows')}, near={r.get('near_duplicate_rows')}, near-dup groups with conflicting labels={r.get('near_duplicate_groups_with_conflicting_labels')}",
              f"- Possibly anonymised text: {r.get('looks_anonymised')}",
              f"- Missing values: " + ", ".join(f"{k}={v}" for k, v in r["missing_values"].items() if v), ""]
    for r in raw_audits:
        L += [f"## Raw messages: {r['folder']}", "", "- " + ", ".join(f"{k}={v}" for k, v in r.items() if k != "folder"), ""]
    if errors:
        L += ["## Errors", ""] + [f"- {e}" for e in errors] + [""]
    L += ["## License & privacy", "", "Check each source page for its license before redistribution. Corpora contain real personal e-mail "
          "(e.g. Enron). Keep raw files local; do not commit them or show message bodies in the UI.", ""]
    open(os.path.join(REPORTS, "DATASET_AUDIT_REPORT.md"), "w", encoding="utf-8").write("\n".join(L))

    K = ["# LEAKAGE_CHECK_REPORT", "", f"Generated: {summary['generated_at']}", "",
         "Near-duplicate key = SHA-1 of the first 400 chars of text with URLs/e-mails/digits normalised and quoted replies trimmed.", ""]
    for r in audits:
        K.append(f"- {r['file']}: exact dups {r.get('exact_duplicate_rows')}, near dups {r.get('near_duplicate_rows')}, conflicting-label groups {r.get('near_duplicate_groups_with_conflicting_labels')}")
    K += ["", "## Cross-file template overlap", ""] + ([f"- {o['a']} ↔ {o['b']}: {o['shared_near_duplicate_templates']} shared templates" for o in overlap] or ["- none detected (or nothing audited)"])
    K += ["", "Training must group near-duplicates (campaign-aware splits). This report does NOT prove the data is leakage-free; "
          "source/style artefacts (e.g. ham from one corporate mailbox vs phishing from another collection) remain a known risk.", ""]
    open(os.path.join(REPORTS, "LEAKAGE_CHECK_REPORT.md"), "w", encoding="utf-8").write("\n".join(K))

    M = ["# LABEL_MAPPING", "", "Original labels are preserved in every derived file (`orig_label`, `source_file`). Mapped classes:", "",
         "| Source pattern | Original label | Mapped class | Used as positive for the phishing baseline? |", "|---|---|---|---|",
         "| Nazario* | 1 | phishing | yes |", "| Nigerian* | 1 | fraud_scam | yes (social-engineering fraud) |",
         "| Enron, Ling, SpamAssassin, TREC_*, CEAS_08 | 1 | spam (may contain phishing) | no — excluded by default (spam ≠ phishing) |",
         "| any source | 0 | legitimate (ham) | negative |",
         "| Merged_Dataset / Balanced_Dataset | 1 | spam_scam_or_phishing (merged by its authors) | no — comparison experiments only |", "",
         "## Observed label values", ""] + [f"- {r['file']} ({r['label_column']}): {r.get('label_values')}" for r in audits] + [""]
    open(os.path.join(REPORTS, "LABEL_MAPPING.md"), "w", encoding="utf-8").write("\n".join(M))
    log_step("audit", [r["file"] for r in audits], "Read-only audit; archives safely extracted to extracted/",
             outputs=["audited/audit_summary.json", "reports/DATASET_AUDIT_REPORT.md", "reports/LEAKAGE_CHECK_REPORT.md", "reports/LABEL_MAPPING.md"])
    print(f"Audited {len(audits)} table(s), {len(raw_audits)} raw folder(s); {len(errors)} error(s). See datasets/email_intelligence/reports/.")


if __name__ == "__main__":
    main()
