#!/usr/bin/env python3
"""
secret_guard - refuse to upload anything that looks like a credential.

Policy of the gfile skill: API keys, tokens, passwords, private keys and other
credentials must NEVER be uploaded to GigaFile, for any reason. This module is
therefore deliberately fail-closed and has NO override flag:

  * files outside the usual sandbox work areas are refused,
  * credential-type file names (.env, auth.json, *.pem, keystores, ...) are refused,
  * file contents (including members of zip/apk/tar/gz archives, recursively)
    are scanned for well-known secret formats,
  * anything that cannot be inspected (encrypted zip members, 7z/rar,
    too-deep nesting) is refused.

Findings are reported with the secret value masked so that the secret itself
never ends up in the chat transcript.
"""
from __future__ import annotations

import bz2
import fnmatch
import gzip
import io
import lzma
import math
import os
import re
import shutil
import tarfile
import tempfile
import zipfile
import zlib
from dataclasses import dataclass, field
from pathlib import Path
from typing import BinaryIO, Iterable, List, Optional, Tuple

# --------------------------------------------------------------------------
# Locations
# --------------------------------------------------------------------------
# Only files that live in normal work areas may be uploaded. Notably this
# excludes /mnt/skills (other skills bundle credentials such as auth.json),
# /mnt/transcripts, /proc, /etc, and the like.
ALLOWED_ROOTS = (
    "/mnt/user-data/outputs",
    "/mnt/user-data/uploads",
    "/home/claude",
    "/tmp",
    "/mnt/data",  # other vendors' sandboxes use this as the work area
)

# Directory names that hold credentials. Refused wherever they appear.
DENIED_DIR_NAMES = {
    ".ssh", ".aws", ".gnupg", ".codex", ".azure", ".kube", ".docker",
    ".config", ".gcloud", ".claude", ".password-store", ".terraform.d",
}

# --------------------------------------------------------------------------
# File names
# --------------------------------------------------------------------------
DENIED_NAMES = {
    ".env", ".netrc", "_netrc", ".npmrc", ".pypirc", ".git-credentials",
    ".pgpass", ".htpasswd", "auth.json", "credentials", "credentials.json",
    "token.json", "tokens.json", "client_secret.json", "local.properties",
    "keystore.properties", "signing.properties", "secrets.json",
    "secrets.yaml", "secrets.yml", "secrets.toml", "secrets.properties",
    "google-services.json", "googleservice-info.plist",
    "terraform.tfvars", ".dockercfg",
}
DENIED_GLOBS = (
    ".env.*", "*.pem", "*.p12", "*.pfx", "*.jks", "*.keystore", "*.ppk",
    "*.kdbx", "*.tfstate", "*.tfstate.*", "client_secret*.json",
    "*credentials*.json", "service-account*.json", "*serviceaccount*.json",
    "*.p8", "*.mobileprovision", "*.gpg", "*.age", "*.ovpn",
)
# Templates that are meant to be shared (their contents are still scanned).
TEMPLATE_SUFFIXES = (".example", ".sample", ".template", ".dist", ".tmpl")
SSH_KEY_RE = re.compile(r"^id_(rsa|dsa|ecdsa|ed25519|ecdsa_sk|ed25519_sk)([._-].*)?$", re.I)

# --------------------------------------------------------------------------
# Content rules (bytes regexes)
# --------------------------------------------------------------------------
_PLACEHOLDER_RE = re.compile(
    rb"(?i)example|x{8,}|\*{4,}|0{12,}|placeholder|redacted|dummy|<[^>]*>|\$\{|\{\{"
)
_GENERIC_PLACEHOLDER_RE = re.compile(
    rb"(?i)example|your|xxxx|\*\*\*|placeholder|dummy|changeme|change_me|redacted|"
    rb"sample|<|>|\$\{|\{\{|%\(|process\.env|os\.environ|getenv|buildconfig|"
    rb"secrets\.|env\.|todo|replace|insert|password$|^password|passw0rd|1234567"
)

_PLACEHOLDER_URL_RE = re.compile(
    rb"(?i)@(?:[a-z0-9\-]+\.)*example\.(?:com|org|net)\b|://(?:user(?:name)?|login|admin|me|foo)"
    rb":(?:pass(?:word)?|secret|pwd|bar|xxx+)@"
)


@dataclass(frozen=True)
class Rule:
    """A secret format.

    `anchors` are literal byte strings that every match must contain; the
    scanner looks them up with bytes.find (fast) and only then runs the full
    regex in a small window around each hit. For `ci` rules the anchors are
    lower-case and are looked up in a lower-cased copy of the data.
    """
    name: str
    pattern: "re.Pattern[bytes]"
    anchors: Tuple[bytes, ...]
    back: int = 0              # how far before the anchor a match may start
    ci: bool = False
    generic: bool = False      # stricter placeholder / entropy filtering
    group: int = 0             # regex group that holds the secret value
    boundary: bool = True      # match must not be preceded by [A-Za-z0-9_]
    need_digit: bool = False


def _r(p: bytes) -> "re.Pattern[bytes]":
    return re.compile(p)


RULES: List[Rule] = [
    Rule("private_key_block", _r(rb"-----BEGIN (?:[A-Z0-9]+ ){0,3}PRIVATE KEY(?: BLOCK)?-----"),
         (b"-----BEGIN ",), boundary=False),
    Rule("aws_access_key_id", _r(rb"(?:AKIA|ASIA|ABIA|ACCA)[0-9A-Z]{16}(?![0-9A-Za-z])"),
         (b"AKIA", b"ASIA", b"ABIA", b"ACCA")),
    Rule("aws_secret_access_key", _r(rb"(?i)aws_?secret_?access_?key[\"']?\s*[:=]\s*[\"']?([A-Za-z0-9/+=]{40})"),
         (b"secret",), back=8, ci=True, group=1),
    Rule("anthropic_api_key", _r(rb"sk-ant-[A-Za-z0-9_\-]{20,}"), (b"sk-ant-",)),
    Rule("openai_api_key", _r(rb"sk-(?!ant-)(?:proj-|svcacct-|admin-|None-)?[A-Za-z0-9_\-]{20,}"),
         (b"sk-",), need_digit=True),
    Rule("github_token", _r(rb"(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36,}"),
         (b"ghp_", b"gho_", b"ghu_", b"ghs_", b"ghr_")),
    Rule("github_fine_grained_pat", _r(rb"github_pat_[A-Za-z0-9_]{50,}"), (b"github_pat_",)),
    Rule("gitlab_token", _r(rb"glpat-[A-Za-z0-9_\-]{20,}"), (b"glpat-",)),
    Rule("slack_token", _r(rb"xox[abposr]-[A-Za-z0-9\-]{10,}"),
         (b"xoxa-", b"xoxb-", b"xoxp-", b"xoxo-", b"xoxs-", b"xoxr-")),
    Rule("slack_webhook", _r(rb"hooks\.slack\.com/services/T[A-Za-z0-9_]+/B[A-Za-z0-9_]+/[A-Za-z0-9_]+"),
         (b"hooks.slack.com/services/",), boundary=False),
    Rule("discord_webhook", _r(rb"discord(?:app)?\.com/api/webhooks/\d+/[A-Za-z0-9_\-]+"),
         (b"/api/webhooks/",), back=16, boundary=False),
    Rule("google_api_key", _r(rb"AIza[0-9A-Za-z_\-]{35}"), (b"AIza",)),
    Rule("google_oauth_client_secret", _r(rb"GOCSPX-[A-Za-z0-9_\-]{20,}"), (b"GOCSPX-",)),
    Rule("google_oauth_token", _r(rb"(?:1//0[A-Za-z0-9_\-]{30,}|ya29\.[A-Za-z0-9_\-]{30,})"),
         (b"1//0", b"ya29.")),
    Rule("stripe_key", _r(rb"(?:sk|rk)_(?:live|test)_[A-Za-z0-9]{16,}"),
         (b"sk_live_", b"sk_test_", b"rk_live_", b"rk_test_")),
    Rule("huggingface_token", _r(rb"hf_[A-Za-z0-9]{30,}"), (b"hf_",), need_digit=True),
    Rule("npm_token", _r(rb"npm_[A-Za-z0-9]{36}(?![A-Za-z0-9])"), (b"npm_",)),
    Rule("pypi_token", _r(rb"pypi-AgE[A-Za-z0-9_\-]{50,}"), (b"pypi-AgE",)),
    Rule("telegram_bot_token", _r(rb"\d{8,10}:AA[0-9A-Za-z_\-]{33}(?![0-9A-Za-z_\-])"),
         (b":AA",), back=10),
    Rule("backblaze_b2_application_key", _r(rb"K0\d{2}[A-Za-z0-9+/]{26,30}(?![A-Za-z0-9+/])"),
         (b"K0",), need_digit=True),
    Rule("azure_storage_account_key", _r(rb"AccountKey=[A-Za-z0-9+/=]{40,}"), (b"AccountKey=",)),
    Rule("jwt", _r(rb"eyJ[A-Za-z0-9_\-]{10,}\.eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}"), (b"eyJ",)),
    Rule("url_with_credentials", _r(
        rb"[a-zA-Z][a-zA-Z0-9+.\-]{1,20}://([^\s/:@\"'<>]{1,64}:[^\s/@\"'<>]{3,128})@[A-Za-z0-9.\-]+"),
        (b"://",), back=21, group=1, generic=True),
    Rule("authorization_bearer", _r(
        rb"(?i)authorization[\"']?\s*[:=]\s*[\"']?bearer\s+([A-Za-z0-9_\-.=+/]{20,})"),
        (b"bearer",), back=24, ci=True, group=1, generic=True),
    Rule("secret_assignment", _r(
        rb"(?i)(?:api[_-]?key|apikey|secret[_-]?key|client[_-]?secret|app[_-]?secret|access[_-]?token|"
        rb"refresh[_-]?token|auth[_-]?token|id[_-]?token|private[_-]?key|application[_-]?key|"
        rb"account[_-]?key|session[_-]?token|api[_-]?secret|webhook[_-]?secret)"
        rb"[\"']?\s*[:=]\s*[\"']([^\"'\s]{16,512})[\"']"),
        (b"key", b"secret", b"token"), back=12, ci=True, group=1, generic=True),
    Rule("password_assignment", _r(
        rb"(?i)(?:password|passwd|passphrase|pwd|store_?password|key_?password)"
        rb"[\"']?\s*[:=]?\s*[\"']([^\"'\s]{8,256})[\"']"),
        (b"passw", b"passphrase", b"pwd"), back=6, ci=True, group=1, generic=True),
]

WINDOW = 1100   # max bytes a single match may span after its anchor
_WORD = re.compile(rb"[A-Za-z0-9_]")

CHUNK = 8 * 1024 * 1024
OVERLAP = 4096
MAX_DEPTH = 4
MAX_DECOMPRESSED_TOTAL = 64 * 1024 ** 3   # zip-bomb guard
MAX_FINDINGS = 50

ZIP_MAGICS = (b"PK\x03\x04", b"PK\x05\x06")
GZIP_MAGIC = b"\x1f\x8b"
BZ2_MAGIC = b"BZh"
XZ_MAGIC = b"\xfd7zXZ\x00"
UNINSPECTABLE_MAGICS = {
    b"7z\xbc\xaf\x27\x1c": "7z archive",
    b"Rar!\x1a\x07": "RAR archive",
    b"\x28\xb5\x2f\xfd": "zstd stream",
}


@dataclass
class Finding:
    path: str
    rule: str
    detail: str

    def as_dict(self) -> dict:
        return {"path": self.path, "rule": self.rule, "detail": self.detail}


@dataclass
class Report:
    findings: List[Finding] = field(default_factory=list)
    files_scanned: int = 0
    bytes_scanned: int = 0
    _seen: set = field(default_factory=set)

    @property
    def blocked(self) -> bool:
        return bool(self.findings)

    def add(self, path: str, rule: str, detail: str) -> None:
        key = (path, rule, detail)
        if key in self._seen:
            return
        self._seen.add(key)
        if len(self.findings) < MAX_FINDINGS:
            self.findings.append(Finding(path, rule, detail))
        elif len(self.findings) == MAX_FINDINGS:
            self.findings.append(Finding("...", "too_many_findings", "further findings omitted"))

    def as_dict(self) -> dict:
        return {
            "ok": not self.blocked,
            "files_scanned": self.files_scanned,
            "bytes_scanned": self.bytes_scanned,
            "findings": [f.as_dict() for f in self.findings],
        }


class _Budget:
    def __init__(self) -> None:
        self.remaining = MAX_DECOMPRESSED_TOTAL


# --------------------------------------------------------------------------
# helpers
# --------------------------------------------------------------------------
def mask(value: bytes, reveal: int = 4) -> str:
    """Never echo a secret: show at most a short vendor prefix and the length."""
    s = value.decode("utf-8", "replace")
    if reveal <= 0 or len(s) <= 8:
        return f"(masked, len={len(s)})"
    return f"{s[:reveal]}…(masked, len={len(s)})"


def _entropy(b: bytes) -> float:
    if not b:
        return 0.0
    counts = {}
    for ch in b:
        counts[ch] = counts.get(ch, 0) + 1
    n = len(b)
    return -sum(c / n * math.log2(c / n) for c in counts.values())


def _looks_real(rule: Rule, value: bytes) -> bool:
    if rule.generic:
        if _GENERIC_PLACEHOLDER_RE.search(value):
            return False
        if rule.name in ("secret_assignment", "authorization_bearer"):
            has_alpha = re.search(rb"[A-Za-z]", value) is not None
            has_digit = re.search(rb"[0-9]", value) is not None
            if not (has_alpha and has_digit) or _entropy(value) < 3.0:
                return False
            # dotted identifiers such as BuildConfig.API_KEY or a.b.c are code, not secrets
            if re.fullmatch(rb"[A-Za-z_][A-Za-z0-9_]*(\.[A-Za-z_][A-Za-z0-9_]*)+", value):
                return False
        if rule.name == "password_assignment" and len(set(value)) < 4:
            return False
        return True
    return _PLACEHOLDER_RE.search(value) is None


def name_violation(name: str) -> Optional[str]:
    base = name.rstrip("/").split("/")[-1]
    low = base.lower()
    if not low:
        return None
    if low.endswith(".pub"):
        return None
    is_template = low.endswith(TEMPLATE_SUFFIXES)
    if low in DENIED_NAMES:
        return f"credential file name '{base}'"
    if SSH_KEY_RE.match(base):
        return f"SSH private key file name '{base}'"
    if not is_template:
        for g in DENIED_GLOBS:
            if fnmatch.fnmatch(low, g):
                return f"credential file name '{base}' (matches {g})"
    return None


def dir_violation(parts: Iterable[str]) -> Optional[str]:
    for p in parts:
        if p in DENIED_DIR_NAMES:
            return f"credential directory '{p}'"
    return None


def _scan_stream(stream: BinaryIO, display: str, report: Report, budget: _Budget,
                 decompressed: bool = False) -> None:
    tail = b""
    while True:
        block = stream.read(CHUNK)
        if not block:
            break
        if decompressed:
            budget.remaining -= len(block)
        if decompressed and budget.remaining < 0:
            report.add(display, "uninspectable", "decompressed size limit exceeded (possible zip bomb)")
            return
        report.bytes_scanned += len(block)
        data = tail + block
        _scan_block(data, len(tail), display, report)
        tail = data[-OVERLAP:]


def _scan_block(data: bytes, skip: int, display: str, report: Report) -> None:
    """Run every rule over `data`; matches ending inside the first `skip` bytes were already seen."""
    lowered = None
    n = len(data)
    for rule in RULES:
        hay = data
        if rule.ci:
            if lowered is None:
                lowered = data.lower()
            hay = lowered
        for anchor in rule.anchors:
            i = hay.find(anchor)
            while i != -1:
                lo = max(0, i - rule.back)
                for m in rule.pattern.finditer(data, lo, min(n, i + WINDOW)):
                    if m.start() > i:
                        break
                    if m.end() <= skip:
                        continue
                    if rule.boundary and m.start() > 0 and _WORD.match(data, m.start() - 1):
                        continue
                    value = m.group(rule.group) if rule.group else m.group(0)
                    if rule.need_digit and not re.search(rb"[0-9]", value):
                        continue
                    if rule.name == "url_with_credentials" and _PLACEHOLDER_URL_RE.search(m.group(0)):
                        continue
                    if _looks_real(rule, value):
                        report.add(display, rule.name, mask(value, 0 if rule.generic else 4))
                i = hay.find(anchor, i + 1)


def _sniff(head: bytes) -> str:
    if head.startswith(ZIP_MAGICS):
        return "zip"
    for magic, label in UNINSPECTABLE_MAGICS.items():
        if head.startswith(magic):
            return "x:" + label
    if head.startswith(GZIP_MAGIC):
        return "gzip"
    if head.startswith(BZ2_MAGIC):
        return "bz2"
    if head.startswith(XZ_MAGIC):
        return "xz"
    if len(head) >= 262 and head[257:262] == b"ustar":
        return "tar"
    return "raw"


def _scan_seekable(f: BinaryIO, display: str, report: Report, budget: _Budget, depth: int) -> None:
    """Scan a seekable binary file object (a real file or a spooled temp file)."""
    head = f.read(512)
    f.seek(0)
    kind = _sniff(head)
    report.files_scanned += 1

    if kind.startswith("x:"):
        report.add(display, "uninspectable", f"{kind[2:]} cannot be inspected; repackage as zip or tar")
        return
    if kind != "raw" and depth >= MAX_DEPTH:
        report.add(display, "uninspectable", "archive nesting too deep")
        return

    if kind == "zip":
        try:
            zf = zipfile.ZipFile(f)
        except zipfile.BadZipFile:
            _scan_stream(f, display, report, budget)  # e.g. a self-extracting stub; scan raw
            return
        with zf:
            for info in zf.infolist():
                mpath = f"{display}!{info.filename}"
                parts = [p for p in info.filename.split("/") if p]
                v = dir_violation(parts[:-1]) or (None if info.is_dir() else name_violation(info.filename))
                if v:
                    report.add(mpath, "forbidden_name", v)
                if info.is_dir():
                    continue
                if info.flag_bits & 0x1:
                    report.add(mpath, "uninspectable", "encrypted zip member")
                    continue
                try:
                    with zf.open(info) as member:
                        _scan_member(member, mpath, report, budget, depth + 1)
                except (NotImplementedError, RuntimeError, zipfile.BadZipFile, EOFError, OSError, lzma.LZMAError) as e:
                    report.add(mpath, "uninspectable", f"cannot read zip member ({type(e).__name__})")
        return

    if kind in ("tar", "gzip", "bz2", "xz"):
        # tar (optionally compressed)?
        try:
            with tarfile.open(fileobj=f, mode="r:*") as tf:
                for ti in tf:
                    mpath = f"{display}!{ti.name}"
                    parts = [p for p in ti.name.split("/") if p]
                    v = dir_violation(parts[:-1]) or (None if ti.isdir() else name_violation(ti.name))
                    if v:
                        report.add(mpath, "forbidden_name", v)
                    if not ti.isfile():
                        continue
                    member = tf.extractfile(ti)
                    if member is None:
                        continue
                    with member:
                        _scan_member(member, mpath, report, budget, depth + 1)
            return
        except (tarfile.TarError, EOFError, OSError, lzma.LZMAError, zlib.error):
            f.seek(0)
        if kind == "tar":
            _scan_stream(f, display, report, budget)
            return
        # plain single-file compression stream
        opener = {"gzip": gzip.GzipFile, "bz2": bz2.BZ2File, "xz": lzma.LZMAFile}[kind]
        try:
            with opener(fileobj=f) as dec:
                _scan_member(dec, display + "!<decompressed>", report, budget, depth + 1)
        except (EOFError, OSError, lzma.LZMAError, zlib.error) as e:
            report.add(display, "uninspectable", f"corrupt {kind} stream ({type(e).__name__})")
        return

    _scan_stream(f, display, report, budget)


def _scan_member(stream: BinaryIO, display: str, report: Report, budget: _Budget, depth: int) -> None:
    """Scan a non-seekable member stream: spool to a temp file if it is itself an archive."""
    head = stream.read(512)
    kind = _sniff(head)
    if kind == "raw":
        report.files_scanned += 1
        _scan_stream(_Prefixed(head, stream), display, report, budget, decompressed=True)
        return
    with tempfile.SpooledTemporaryFile(max_size=64 * 1024 * 1024) as tmp:
        tmp.write(head)
        shutil.copyfileobj(stream, tmp, CHUNK)
        tmp.seek(0)
        _scan_seekable(tmp, display, report, budget, depth)


class _Prefixed(io.RawIOBase):
    """Stream that yields `prefix` first and then the rest of `stream`."""

    def __init__(self, prefix: bytes, stream: BinaryIO) -> None:
        self._prefix = prefix
        self._stream = stream

    def read(self, n: int = -1) -> bytes:
        if self._prefix:
            out, self._prefix = self._prefix, b""
            if n is None or n < 0:
                return out + self._stream.read()
            if len(out) < n:
                out += self._stream.read(n - len(out))
            return out
        return self._stream.read(n)

    def readable(self) -> bool:
        return True


# --------------------------------------------------------------------------
# public API
# --------------------------------------------------------------------------
def location_violation(path: Path) -> Optional[str]:
    real = os.path.realpath(path)
    if not any(real == r or real.startswith(r + os.sep) for r in ALLOWED_ROOTS):
        return f"outside allowed work areas ({', '.join(ALLOWED_ROOTS)})"
    v = dir_violation(Path(real).parts)
    if v:
        return v
    return None


def iter_files(paths: Iterable[Path]):
    """Yield (file_path, relative_display) for every regular file under `paths`."""
    for p in paths:
        p = Path(p)
        if p.is_dir():
            for root, dirs, files in os.walk(p, followlinks=False):
                dirs.sort()
                for name in sorted(files):
                    fp = Path(root) / name
                    yield fp, str(fp)
        else:
            yield p, str(p)


def scan_paths(paths: Iterable[Path]) -> Report:
    report = Report()
    budget = _Budget()
    for fp, display in iter_files(paths):
        if not fp.exists():
            report.add(display, "missing", "file does not exist")
            continue
        v = location_violation(fp)
        if v:
            report.add(display, "forbidden_location", v)
            continue
        if fp.is_symlink() and not fp.resolve().is_file():
            report.add(display, "uninspectable", "dangling or special symlink")
            continue
        v = name_violation(fp.name)
        if v:
            report.add(display, "forbidden_name", v)
            # still scan contents so the user sees everything at once
        if not fp.is_file():
            report.add(display, "uninspectable", "not a regular file")
            continue
        try:
            with open(fp, "rb") as f:
                _scan_seekable(f, display, report, budget, depth=0)
        except OSError as e:
            report.add(display, "uninspectable", f"cannot read file ({e.__class__.__name__})")
    return report


if __name__ == "__main__":  # manual use: python3 secret_guard.py <paths...>
    import json
    import sys

    rep = scan_paths([Path(a) for a in sys.argv[1:]])
    print(json.dumps(rep.as_dict(), ensure_ascii=False, indent=2))
    sys.exit(0 if not rep.blocked else 2)
