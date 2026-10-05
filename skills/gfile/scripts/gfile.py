#!/usr/bin/env python3
"""
gfile - share files through GigaFile便 (https://gigafile.nu/) from a Claude sandbox.

Subcommands
  check   PATH...                         size check against the claude.ai download limit + secret scan
  upload  PATH... --lifetime N --dlkey K  scan, (bundle), upload, set download key, verify
  pii     PATH...                         report personal information (OpenAI Privacy Filter + regex + OCR)
  delete  URL --delkey K                  delete an uploaded file

Safety rules enforced here (no override flags exist on purpose):
  * a download key is mandatory; if it cannot be set and verified, the upload is deleted
  * secret_guard must pass; anything that looks like a credential is refused
  * a PII report for exactly these files is required; if it lists anything to review,
    --pii-reviewed must be passed (only after the user has seen every finding and decided)
"""
from __future__ import annotations

import argparse
import base64
import datetime as dt
import hashlib
import json
import math
import os
import re
import secrets
import sys
import tempfile
import time
import zipfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import secret_guard  # noqa: E402
import pii_scan  # noqa: E402

try:
    import requests
except ImportError:  # pragma: no cover
    print("gfile: the 'requests' package is required (pip install requests --break-system-packages)", file=sys.stderr)
    sys.exit(10)

VERSION = "1.1.0"

# claude.ai: "The maximum file size is 30MB per file for both uploads and downloads."
# https://support.claude.com/en/articles/12111783  (checked 2026-10-05)
CLAUDE_DOWNLOAD_LIMIT_BYTES = 30_000_000

ALLOWED_LIFETIMES = (3, 5, 7, 14, 30, 60, 100)      # values offered by the GigaFile UI
DLKEY_RE = re.compile(r"^[0-9A-Za-z]{1,4}$")          # GigaFile: half-width alnum, 1-4 chars
DELKEY_RE = re.compile(r"^[0-9A-Za-z]{4}$")
SERVER_RE = re.compile(r"^[0-9]{1,3}\.gigafile\.nu$")
FILE_URL_RE = re.compile(r"^https?://([0-9]{1,3}\.gigafile\.nu)/([0-9]{4}-[0-9a-z]+)/?$")
MAX_FILE_SIZE = 300 * 1024 ** 3                      # GigaFile per-file limit
DEFAULT_CHUNK_MB = 100                               # same as the official web uploader
TOP_URL = "https://gigafile.nu/"
UA = f"Mozilla/5.0 (X11; Linux x86_64) gfile-skill/{VERSION}"
JST = dt.timezone(dt.timedelta(hours=9))
STORE_EXTS = {
    ".zip", ".apk", ".aab", ".jar", ".ipa", ".xapk", ".mp4", ".mov", ".mkv", ".webm", ".avi",
    ".mp3", ".m4a", ".aac", ".ogg", ".opus", ".flac", ".jpg", ".jpeg", ".png", ".gif", ".webp",
    ".heic", ".gz", ".tgz", ".xz", ".bz2", ".zst", ".docx", ".xlsx", ".pptx", ".pdf",
}


class GfileError(Exception):
    def __init__(self, message: str, code: int = 1):
        super().__init__(message)
        self.code = code


def log(msg: str) -> None:
    print(f"[gfile] {msg}", file=sys.stderr, flush=True)


def human(n: int) -> str:
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if n < 1000 or unit == "TB":
            return f"{n:.0f} {unit}" if unit == "B" else f"{n:.1f} {unit}"
        n /= 1000
    return str(n)


# --------------------------------------------------------------------------
# HTTP
# --------------------------------------------------------------------------
def new_session() -> requests.Session:
    s = requests.Session()
    s.headers["User-Agent"] = UA
    return s


def _explain_network_error(e: Exception, resp: "requests.Response | None" = None) -> str:
    deny = resp.headers.get("x-deny-reason") if resp is not None else None
    if deny:
        return (f"network access to gigafile.nu was denied by the sandbox proxy ({deny}). "
                "Allow gigafile.nu and *.gigafile.nu in the network egress settings.")
    return f"network error: {e.__class__.__name__}: {e}"


def get_upload_server(s: requests.Session) -> str:
    try:
        r = s.get(TOP_URL, timeout=30)
    except requests.RequestException as e:
        raise GfileError(_explain_network_error(e), 4)
    if r.status_code != 200:
        raise GfileError(_explain_network_error(Exception(f"HTTP {r.status_code}"), r), 4)
    m = re.search(r'\bserver\s*=\s*"([^"]+)"', r.text)
    if not m or not SERVER_RE.match(m.group(1)):
        raise GfileError("could not determine the GigaFile upload server (site layout changed?)", 5)
    return m.group(1)


def _post_chunk(s, url, fields, payload, attempts=5):
    last = None
    for attempt in range(1, attempts + 1):
        try:
            r = s.post(url, data=fields, files={"file": ("blob", payload, "application/octet-stream")},
                       timeout=(30, 1800))
            if r.status_code >= 500:
                last = f"HTTP {r.status_code}"
            elif r.status_code != 200:
                raise GfileError(_explain_network_error(Exception(f"HTTP {r.status_code}"), r), 4)
            else:
                try:
                    j = r.json()
                except ValueError:
                    raise GfileError(f"unexpected upload response: {r.text[:200]!r}", 5)
                if j.get("status") != 0:
                    raise GfileError(f"GigaFile rejected the chunk: {j.get('message') or j}", 5)
                return j
        except requests.RequestException as e:
            last = _explain_network_error(e)
        if attempt < attempts:
            wait = 10 * attempt
            log(f"chunk upload failed ({last}); retrying in {wait}s ({attempt}/{attempts - 1})")
            time.sleep(wait)
    raise GfileError(f"chunk upload failed after {attempts} attempts: {last}", 4)


def upload_file(s, server, path: Path, name: str, lifetime: int, chunk_size: int) -> dict:
    size = path.stat().st_size
    chunks = max(1, math.ceil(size / chunk_size))
    token = secrets.token_hex(16)
    url = f"https://{server}/upload_chunk.php"
    t0 = time.time()
    result = None
    with open(path, "rb") as f:
        for i in range(chunks):
            payload = f.read(chunk_size)
            fields = {"id": token, "name": name, "chunk": str(i), "chunks": str(chunks),
                      "lifetime": str(lifetime)}
            result = _post_chunk(s, url, fields, payload)
            done = min(size, (i + 1) * chunk_size)
            el = time.time() - t0
            rate = done / el if el > 0 else 0
            log(f"uploaded chunk {i + 1}/{chunks} ({human(done)}/{human(size)}, {human(int(rate))}/s)")
    if not result or not all(k in result for k in ("url", "delkey", "filename")):
        raise GfileError(f"upload finished but no URL was returned: {result}", 5)
    return result


def set_dlkey(s, server, filename, delkey, dlkey) -> None:
    try:
        r = s.get(f"https://{server}/set_dlkey.php",
                  params={"file": filename, "delkey": delkey, "dlkey": dlkey}, timeout=30)
        ok = r.status_code == 200 and r.json().get("status") == 0
    except (requests.RequestException, ValueError):
        ok = False
    if not ok:
        raise GfileError("failed to set the download key", 6)


def verify_dlkey(s, server, filename, dlkey) -> None:
    """Fail closed: the download page must report a key AND the key must be accepted.

    A wrong-key probe is deliberately NOT made, because repeated wrong attempts
    can lock the file for legitimate downloaders.
    """
    try:
        page = s.get(f"https://{server}/{filename}", timeout=30).text
        m = re.search(r"download\('%s',\s*(true|false)" % re.escape(filename), page)
        flag = m.group(1) if m else None
        r = s.get(f"https://{server}/check_dlkey.php",
                  params={"file": filename, "dlkey": dlkey, "is_zip": 0}, timeout=30)
        accepted = r.status_code == 200 and r.json().get("status") == 0
    except (requests.RequestException, ValueError) as e:
        raise GfileError(f"could not verify the download key ({e.__class__.__name__})", 6)
    if flag != "true" or not accepted:
        raise GfileError(f"download key verification failed (page flag={flag}, accepted={accepted})", 6)


def remove_file(s, server, filename, delkey) -> bool:
    try:
        r = s.get(f"https://{server}/remove.php", params={"file": filename, "delkey": delkey}, timeout=30)
        return r.status_code == 200 and r.json().get("status") == 0
    except (requests.RequestException, ValueError):
        return False


def expiry_from(result: dict, lifetime: int) -> str:
    """Expiry date as reported by GigaFile (JWT claim d_expiry), else computed in JST."""
    tok = result.get("jwt") or ""
    try:
        payload = tok.split(".")[1]
        payload += "=" * (-len(payload) % 4)
        d = json.loads(base64.urlsafe_b64decode(payload)).get("d_expiry")
        if d and re.match(r"^\d{4}-\d{2}-\d{2}$", d):
            return d
    except Exception:
        pass
    return (dt.datetime.now(JST).date() + dt.timedelta(days=lifetime)).isoformat()


# --------------------------------------------------------------------------
# local helpers
# --------------------------------------------------------------------------
def sha256_of(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for block in iter(lambda: f.read(8 * 1024 * 1024), b""):
            h.update(block)
    return h.hexdigest()


def total_size(paths) -> int:
    return sum(fp.stat().st_size for fp, _ in secret_guard.iter_files(paths) if fp.is_file())


def build_bundle(paths, name: str | None) -> Path:
    stamp = dt.datetime.now(JST).strftime("%Y%m%d-%H%M%S")
    zip_name = name or f"gfile_bundle_{stamp}.zip"
    if not zip_name.lower().endswith(".zip"):
        zip_name += ".zip"
    out_dir = Path(tempfile.mkdtemp(prefix="gfile_", dir="/tmp"))
    out = out_dir / zip_name
    log(f"bundling {len(paths)} input(s) into {zip_name}")
    with zipfile.ZipFile(out, "w", zipfile.ZIP_DEFLATED, compresslevel=6, allowZip64=True) as z:
        for p in paths:
            p = Path(p)
            if p.is_dir():
                base = p.parent
                for fp, _ in secret_guard.iter_files([p]):
                    if fp.is_file():
                        ct = zipfile.ZIP_STORED if fp.suffix.lower() in STORE_EXTS else zipfile.ZIP_DEFLATED
                        z.write(fp, fp.relative_to(base).as_posix(), compress_type=ct)
            else:
                ct = zipfile.ZIP_STORED if p.suffix.lower() in STORE_EXTS else zipfile.ZIP_DEFLATED
                z.write(p, p.name, compress_type=ct)
    return out


def print_findings(report) -> None:
    log("REFUSED: possible credentials / uninspectable content found. Nothing was uploaded.")
    for f in report.findings:
        log(f"  - {f.path}: {f.rule} — {f.detail}")


def write_json(path: str | None, obj: dict) -> None:
    text = json.dumps(obj, ensure_ascii=False, indent=2)
    if path:
        Path(path).write_text(text + "\n", encoding="utf-8")
    print(text)


# --------------------------------------------------------------------------
# subcommands
# --------------------------------------------------------------------------
MODEL_SKIP_OK = "no text needed model inspection"


def pii_gate(a, paths) -> None:
    if not a.pii_report:
        raise GfileError("--pii-report is required: run `gfile.py pii <paths> --json-out FILE` first", 8)
    try:
        rep = json.loads(Path(a.pii_report).read_text(encoding="utf-8"))
    except (OSError, ValueError) as e:
        raise GfileError(f"cannot read PII report: {e}", 8)
    if rep.get("fingerprint") != pii_scan.fingerprint(paths):
        raise GfileError("the PII report does not match the files being uploaded; run `gfile.py pii` again", 8)
    model = rep.get("model") or {}
    reasons = []
    if rep.get("findings_count"):
        reasons.append(f"{rep['findings_count']} finding(s)")
    if rep.get("images_for_visual_review"):
        reasons.append(f"{len(rep['images_for_visual_review'])} image(s) for visual review")
    if not model.get("used") and model.get("reason") != MODEL_SKIP_OK:
        reasons.append(f"model not used ({model.get('reason')})")
    elif model.get("not_model_scanned"):
        reasons.append("token budget exceeded")
    if reasons and not a.pii_reviewed:
        raise GfileError("the PII report needs review (" + ", ".join(reasons) + "). Show every finding to the "
                         "user, let them decide, then pass --pii-reviewed", 8)
    if reasons:
        log("PII review acknowledged: " + ", ".join(reasons))


def cmd_pii(a) -> int:
    argv = list(a.paths)
    for flag, val in (("--json-out", a.json_out), ("--md-out", a.md_out)):
        if val:
            argv += [flag, val]
    argv += ["--token-budget", str(a.token_budget), "--max-ocr", str(a.max_ocr)]
    return pii_scan.main(argv)


def cmd_check(a) -> int:
    paths = [Path(p) for p in a.paths]
    files = []
    for p in paths:
        if not p.exists():
            files.append({"path": str(p), "exists": False})
            continue
        size = total_size([p]) if p.is_dir() else p.stat().st_size
        files.append({"path": str(p), "exists": True, "is_dir": p.is_dir(), "size_bytes": size,
                      "size_human": human(size),
                      "over_claude_download_limit": size > CLAUDE_DOWNLOAD_LIMIT_BYTES})
    report = secret_guard.scan_paths(paths)
    out = {
        "claude_download_limit_bytes": CLAUDE_DOWNLOAD_LIMIT_BYTES,
        "files": files,
        "any_over_limit": any(f.get("over_claude_download_limit") for f in files),
        "secret_scan": report.as_dict(),
        "upload_allowed": not report.blocked and all(f.get("exists") for f in files),
    }
    write_json(a.json_out, out)
    return 0 if out["upload_allowed"] else 2


def cmd_upload(a) -> int:
    if not DLKEY_RE.match(a.dlkey or ""):
        raise GfileError("--dlkey is required: 1-4 half-width alphanumeric characters (uploads without a key are forbidden)", 2)
    if a.lifetime not in ALLOWED_LIFETIMES:
        raise GfileError(f"--lifetime must be one of {ALLOWED_LIFETIMES}", 2)
    if not 1 <= a.chunk_mb <= 100:
        raise GfileError("--chunk-mb must be between 1 and 100", 2)
    paths = [Path(p) for p in a.paths]
    for p in paths:
        if not p.exists():
            raise GfileError(f"no such file or directory: {p}", 2)

    pii_gate(a, paths)
    log("scanning for credentials ...")
    report = secret_guard.scan_paths(paths)
    if report.blocked:
        print_findings(report)
        write_json(a.json_out, {"ok": False, "error": "secret_guard_refused", "secret_scan": report.as_dict()})
        return 3
    log(f"scan passed ({report.files_scanned} file(s), {human(report.bytes_scanned)})")

    bundle = None
    if len(paths) > 1 or paths[0].is_dir():
        bundle = build_bundle(paths, a.name)
        target, upload_name = bundle, bundle.name
    else:
        target, upload_name = paths[0], (a.name or paths[0].name)

    size = target.stat().st_size
    if size > MAX_FILE_SIZE:
        raise GfileError(f"file is larger than GigaFile's 300 GB limit ({human(size)})", 2)
    digest = sha256_of(target)

    s = new_session()
    server = get_upload_server(s)
    log(f"uploading {upload_name} ({human(size)}) to {server}, lifetime {a.lifetime} days")
    res = upload_file(s, server, target, upload_name, a.lifetime, a.chunk_mb * 1024 * 1024)
    filename, delkey, url = res["filename"], res["delkey"], res["url"]
    try:
        set_dlkey(s, server, filename, delkey, a.dlkey)
        verify_dlkey(s, server, filename, a.dlkey)
    except GfileError as e:
        removed = remove_file(s, server, filename, delkey)
        msg = f"{e} — the upload was {'deleted' if removed else 'NOT deleted (delete it manually!)'}"
        out = {"ok": False, "error": "dlkey_failed", "message": msg}
        if not removed:  # the user must be able to clean up by hand
            out.update({"url": url, "delkey": delkey})
        write_json(a.json_out, out)
        return 6

    out = {
        "ok": True,
        "url": url,
        "file_name": upload_name,
        "size_bytes": size,
        "size_human": human(size),
        "sha256": digest,
        "lifetime_days": a.lifetime,
        "expires_on": expiry_from(res, a.lifetime),
        "dlkey": a.dlkey,
        "delkey": delkey,
        "dlkey_verified": True,
        "bundled_from": [str(p) for p in paths] if bundle else None,
    }
    write_json(a.json_out, out)
    if bundle:
        try:
            bundle.unlink()
            bundle.parent.rmdir()
        except OSError:
            pass
    return 0


def cmd_delete(a) -> int:
    m = FILE_URL_RE.match(a.url.strip())
    if not m:
        raise GfileError("URL must look like https://NN.gigafile.nu/MMDD-xxxxxxxx", 2)
    if not DELKEY_RE.match(a.delkey or ""):
        raise GfileError("--delkey must be 4 half-width alphanumeric characters", 2)
    server, filename = m.group(1), m.group(2)
    s = new_session()
    ok = remove_file(s, server, filename, a.delkey)
    still = None
    if ok:
        try:
            page = s.get(f"https://{server}/{filename}", timeout=30).text
            still = re.search(r"download\('%s'" % re.escape(filename), page) is not None
        except requests.RequestException:
            still = None
    out = {"ok": bool(ok and still is False), "url": a.url, "removed": ok, "still_downloadable": still}
    write_json(a.json_out, out)
    return 0 if out["ok"] else 7


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="gfile", description="Share files via GigaFile便 (gigafile.nu)")
    ap.add_argument("--version", action="version", version=f"gfile {VERSION}")
    sub = ap.add_subparsers(dest="cmd", required=True)

    c = sub.add_parser("check", help="size check + secret scan (no network)")
    c.add_argument("paths", nargs="+")
    c.add_argument("--json-out")
    c.set_defaults(func=cmd_check)

    u = sub.add_parser("upload", help="scan, upload, set download key, verify")
    u.add_argument("paths", nargs="+")
    u.add_argument("--lifetime", type=int, required=True, help=f"days, one of {ALLOWED_LIFETIMES}")
    u.add_argument("--dlkey", required=True, help="download key: 1-4 half-width alphanumerics (mandatory)")
    u.add_argument("--name", help="upload file name (single file) or bundle zip name (multiple inputs)")
    u.add_argument("--chunk-mb", type=int, default=DEFAULT_CHUNK_MB)
    u.add_argument("--json-out", help="also write the result JSON to this path")
    u.add_argument("--pii-report", help="JSON written by `gfile.py pii` for exactly these paths (required)")
    u.add_argument("--pii-reviewed", action="store_true",
                   help="the user has seen every PII finding and chose to upload anyway")
    u.set_defaults(func=cmd_upload)

    q = sub.add_parser("pii", help="report personal information (never modifies files)")
    q.add_argument("paths", nargs="+")
    q.add_argument("--json-out")
    q.add_argument("--md-out")
    q.add_argument("--token-budget", type=int, default=pii_scan.DEFAULT_TOKEN_BUDGET)
    q.add_argument("--max-ocr", type=int, default=pii_scan.DEFAULT_MAX_OCR)
    q.set_defaults(func=cmd_pii)

    d = sub.add_parser("delete", help="delete an uploaded file with its delete key")
    d.add_argument("url")
    d.add_argument("--delkey", required=True)
    d.add_argument("--json-out")
    d.set_defaults(func=cmd_delete)

    a = ap.parse_args(argv)
    try:
        return a.func(a)
    except GfileError as e:
        log(f"ERROR: {e}")
        write_json(getattr(a, "json_out", None), {"ok": False, "error": str(e)})
        return e.code
    except KeyboardInterrupt:
        log("interrupted")
        return 130


if __name__ == "__main__":
    sys.exit(main())
