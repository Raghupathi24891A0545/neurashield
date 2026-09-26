"""Download and verify the Module 4 e-mail datasets from their OFFICIAL sources.

    python scripts/email_dataset/download_datasets.py            # all sources
    python scripts/email_dataset/download_datasets.py --only spamassassin
    python scripts/email_dataset/download_datasets.py --check    # reachability only

- Zenodo files are listed via the Zenodo REST API and verified against the MD5
  checksum Zenodo publishes. SpamAssassin archives are listed from the official
  index; SHA-256 is recorded (no official checksum is published there).
- Existing files are never overwritten. A differing re-download is kept as
  <name>.redownload and reported.
- A download is only recorded as VERIFIED if the file exists, is non-empty, and
  its checksum matches (Zenodo) or was computed (SpamAssassin).
"""
import argparse
import os
import re
import sys
import time

import requests

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from common import RAW, SOURCES, now, sha256_file, md5_file, load_manifest, save_manifest, log_step  # noqa: E402

UA = {"User-Agent": "NeuraShield-dataset-downloader/1.0 (research; contact: project owner)"}
TIMEOUT = (15, 120)


def check():
    ok = True
    for key, s in SOURCES.items():
        url = f"https://zenodo.org/api/records/{s['record']}" if s["kind"] == "zenodo" else s["page"]
        try:
            r = requests.get(url, headers=UA, timeout=(10, 20))
            print(f"[{r.status_code}] {key}: {url}")
            ok &= r.ok
        except Exception as e:
            print(f"[FAIL] {key}: {url} — {type(e).__name__}: {e}")
            ok = False
    return ok


def _stream(url, dest):
    tmp = dest + ".part"
    with requests.get(url, headers=UA, stream=True, timeout=TIMEOUT) as r:
        r.raise_for_status()
        total = 0
        with open(tmp, "wb") as f:
            for chunk in r.iter_content(1 << 20):
                f.write(chunk)
                total += len(chunk)
    os.replace(tmp, dest)
    return total


def _record(manifest, entry):
    manifest["files"] = [f for f in manifest["files"] if f.get("path") != entry["path"]] + [entry]
    save_manifest(manifest)


def download_zenodo(key, manifest):
    s = SOURCES[key]
    api = f"https://zenodo.org/api/records/{s['record']}"
    r = requests.get(api, headers=UA, timeout=(10, 30))
    r.raise_for_status()
    meta = r.json()
    files = meta.get("files") or []
    if not files:
        print(f"  {key}: record lists no files (may be restricted).")
        return
    outdir = os.path.join(RAW, key)
    os.makedirs(outdir, exist_ok=True)
    for f in files:
        name = f.get("key") or f.get("filename")
        link = (f.get("links") or {}).get("self") or (f.get("links") or {}).get("download")
        checksum = f.get("checksum", "")  # "md5:<hex>"
        dest = os.path.join(outdir, os.path.basename(name))
        entry = {"source": key, "source_page": s["page"], "doi": s.get("doi"), "url": link, "filename": name,
                 "path": os.path.relpath(dest, RAW), "declared_size": f.get("size"), "declared_checksum": checksum}
        if os.path.exists(dest):
            md5 = md5_file(dest)
            if checksum.endswith(md5):
                print(f"  = {name} already present, checksum OK")
                entry.update({"status": "VERIFIED", "md5": md5, "sha256": sha256_file(dest), "size": os.path.getsize(dest), "checked_at": now()})
                _record(manifest, entry)
                continue
            dest_new = dest + ".redownload"
            print(f"  ! {name} exists with a different checksum; original kept, new copy → {os.path.basename(dest_new)}")
            dest = dest_new
            entry["path"] = os.path.relpath(dest, RAW)
        print(f"  ↓ {name} ({f.get('size')} bytes)")
        t0 = time.time()
        try:
            size = _stream(link, dest)
        except Exception as e:
            print(f"  ✕ {name}: {type(e).__name__}: {e}")
            entry.update({"status": "FAILED", "error": f"{type(e).__name__}: {e}", "attempted_at": now()})
            _record(manifest, entry)
            continue
        md5 = md5_file(dest)
        verified = bool(checksum) and checksum.endswith(md5) and size > 0
        entry.update({"status": "VERIFIED" if verified else "CHECKSUM_MISMATCH", "md5": md5, "sha256": sha256_file(dest),
                      "size": size, "downloaded_at": now(), "seconds": round(time.time() - t0, 1)})
        print(f"    {'✓ verified' if verified else '✕ CHECKSUM MISMATCH'} md5={md5}")
        _record(manifest, entry)


def download_spamassassin(manifest):
    s = SOURCES["spamassassin"]
    r = requests.get(s["page"], headers=UA, timeout=(10, 30))
    r.raise_for_status()
    names = sorted(set(re.findall(r'href="([^"]+\.tar\.bz2)"', r.text)))
    if not names:
        print("  spamassassin: no .tar.bz2 archives found on the index page")
        return
    outdir = os.path.join(RAW, "spamassassin")
    os.makedirs(outdir, exist_ok=True)
    for n in names:
        url = requests.compat.urljoin(s["page"], n)
        dest = os.path.join(outdir, os.path.basename(n))
        entry = {"source": "spamassassin", "source_page": s["page"], "url": url, "filename": os.path.basename(n),
                 "path": os.path.relpath(dest, RAW), "declared_checksum": None}
        if os.path.exists(dest) and os.path.getsize(dest) > 0:
            print(f"  = {n} already present (kept as original)")
            entry.update({"status": "PRESENT_UNVERIFIED_SOURCE_CHECKSUM", "sha256": sha256_file(dest), "size": os.path.getsize(dest), "checked_at": now()})
            _record(manifest, entry)
            continue
        print(f"  ↓ {n}")
        try:
            size = _stream(url, dest)
            entry.update({"status": "DOWNLOADED_SHA256_RECORDED", "sha256": sha256_file(dest), "size": size, "downloaded_at": now()})
        except Exception as e:
            entry.update({"status": "FAILED", "error": f"{type(e).__name__}: {e}", "attempted_at": now()})
            print(f"  ✕ {n}: {e}")
        _record(manifest, entry)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--only", choices=list(SOURCES))
    ap.add_argument("--check", action="store_true")
    a = ap.parse_args()
    if a.check:
        sys.exit(0 if check() else 1)
    manifest = load_manifest()
    for key in ([a.only] if a.only else list(SOURCES)):
        print(f"\n== {key}: {SOURCES[key]['name']}")
        try:
            if SOURCES[key]["kind"] == "zenodo":
                download_zenodo(key, manifest)
            else:
                download_spamassassin(manifest)
        except Exception as e:
            print(f"  ✕ {key}: source unreachable — {type(e).__name__}: {e}")
            manifest.setdefault("source_errors", []).append({"source": key, "error": f"{type(e).__name__}: {e}", "at": now()})
            save_manifest(manifest)
    ok = [f for f in manifest["files"] if f.get("status") in ("VERIFIED", "DOWNLOADED_SHA256_RECORDED", "PRESENT_UNVERIFIED_SOURCE_CHECKSUM")]
    bad = [f for f in manifest["files"] if f not in ok]
    log_step("download", [s["page"] for s in SOURCES.values()], "Download from official sources; checksum verification",
             outputs=[f["path"] for f in ok], removed={"failed_or_mismatched": [f["path"] for f in bad]})
    print(f"\nSummary: {len(ok)} file(s) available, {len(bad)} failed/mismatched. Manifest: datasets/email_intelligence/checksums/download_manifest.json")


if __name__ == "__main__":
    main()
