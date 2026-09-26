"""Shared paths and provenance logging for the e-mail dataset pipeline."""
import hashlib
import json
import os
from datetime import datetime, timezone

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
DS = os.path.join(ROOT, "datasets", "email_intelligence")
RAW, EXTRACTED, AUDITED = os.path.join(DS, "raw"), os.path.join(DS, "extracted"), os.path.join(DS, "audited")
CLEANED, DEDUP, FEATURES, SPLITS = (os.path.join(DS, d) for d in ("cleaned", "deduplicated", "features", "splits"))
REPORTS, CHECKSUMS = os.path.join(DS, "reports"), os.path.join(DS, "checksums")
MANIFEST = os.path.join(CHECKSUMS, "download_manifest.json")

SOURCES = {
    "zenodo_curated": {"name": "Phishing Email Curated Datasets", "kind": "zenodo", "record": "8339691",
                       "page": "https://zenodo.org/records/8339691", "doi": "https://doi.org/10.5281/zenodo.8339691"},
    "meajor": {"name": "MeAJOR email dataset", "kind": "zenodo", "record": "18471483",
               "page": "https://zenodo.org/records/18471483", "doi": "https://doi.org/10.5281/zenodo.18471483"},
    "phishing_detection": {"name": "Phishing Email Detection Dataset (Merged/Balanced)", "kind": "zenodo", "record": "17314806",
                           "page": "https://zenodo.org/records/17314806", "doi": "https://doi.org/10.5281/zenodo.17314806",
                           "repo": "https://github.com/Manar-ibr/Phishing-Email-Detection-Dataset"},
    "spamassassin": {"name": "Apache SpamAssassin public corpus", "kind": "index",
                     "page": "https://spamassassin.apache.org/old/publiccorpus/"},
}


def now():
    return datetime.now(timezone.utc).isoformat()


def sha256_file(path, chunk=1 << 20):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for b in iter(lambda: f.read(chunk), b""):
            h.update(b)
    return h.hexdigest()


def md5_file(path, chunk=1 << 20):
    h = hashlib.md5()
    with open(path, "rb") as f:
        for b in iter(lambda: f.read(chunk), b""):
            h.update(b)
    return h.hexdigest()


def log_step(step, inputs, transformation, rows_before=None, rows_after=None, removed=None, outputs=None, code=None):
    """Append one provenance entry to reports/DATA_PROCESSING_LOG.md (never rewrites history)."""
    os.makedirs(REPORTS, exist_ok=True)
    path = os.path.join(REPORTS, "DATA_PROCESSING_LOG.md")
    new = not os.path.exists(path)
    with open(path, "a", encoding="utf-8") as f:
        if new:
            f.write("# DATA_PROCESSING_LOG\n\nAppend-only provenance log for derived e-mail dataset files.\n")
        f.write(f"\n## {now()} — {step}\n")
        f.write(f"- Inputs: {json.dumps(inputs)}\n- Transformation: {transformation}\n")
        if rows_before is not None:
            f.write(f"- Rows before/after: {rows_before} → {rows_after}\n")
        if removed:
            f.write(f"- Removed: {json.dumps(removed)}\n")
        if outputs:
            f.write(f"- Outputs: {json.dumps(outputs)}\n")
        f.write(f"- Code: {code or 'scripts/email_dataset'}\n")


def load_manifest():
    if os.path.exists(MANIFEST):
        with open(MANIFEST) as f:
            return json.load(f)
    return {"files": []}


def save_manifest(m):
    os.makedirs(CHECKSUMS, exist_ok=True)
    with open(MANIFEST, "w") as f:
        json.dump(m, f, indent=2)
