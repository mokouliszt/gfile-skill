#!/usr/bin/env python3
"""
pii_scan - find personally identifiable information (PII) before sharing files.

Detectors
  * OpenAI Privacy Filter (openai/privacy-filter, Apache-2.0), run locally with
    onnxruntime (q4 ONNX weights, ~0.9 GB, downloaded once per sandbox session)
  * regular expressions for high-precision formats (emails, JP/intl phone numbers,
    〒 postal codes, JP street addresses, My Number, card numbers, bank accounts)
  * image metadata (GPS position, author/owner fields, embedded text chunks)
  * OCR (Tesseract, jpn+eng) of screenshots and other images, fed to the detectors

This script never modifies, masks or redacts anything. It only reports what it found
(with locations and context) so that Claude can show every finding to the user and
let the user decide.

Exit codes: 0 = nothing found, 2 = findings to review, 1 = error.
"""
from __future__ import annotations

import argparse
import bisect
import hashlib
import html
import io
import json
import os
import re
import shutil
import subprocess
import sys
import tarfile
import tempfile
import time
import zipfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Tuple

sys.path.insert(0, str(Path(__file__).resolve().parent))
import secret_guard  # noqa: E402  (file walking + allowed locations)

# --------------------------------------------------------------------------
# configuration
# --------------------------------------------------------------------------
CACHE = Path(os.environ.get("GFILE_CACHE", "/tmp/gfile_models"))
WORK = Path(tempfile.gettempdir()) / "gfile_pii_work"

MODEL_REPO = "openai/privacy-filter"
MODEL_REV = "7ffa9a043d54d1be65afb281eddf0ffbe629385b"   # pinned revision (2026-04-22)
MODEL_FILES = {  # path: (size, sha256)
    "config.json": (3039, "b2b26a4a4a000639ad30b0c264adbefe365bdb567fbd7bb27303b8c438375bd1"),
    "tokenizer.json": (27868174, "0614fe83cadab421296e664e1f48f4261fa8fef6e03e63bb75c20f38e37d07d3"),
    "onnx/model_q4.onnx": (160219, "8f7dee8b46d096f052b359375dfba5d983cc4d18c44a783bf548615c472f8dea"),
    "onnx/model_q4.onnx_data": (917120144, "f30998e28c71c5374cc7e8b7de8f0f83e981592c0c2d652d2ad4928454dbb496"),
}
TESSDATA_URL = "https://github.com/tesseract-ocr/tessdata_fast/raw/main/{lang}.traineddata"

WINDOW = 1536          # tokens per forward pass (~2.7 GB RSS; safe on a 4 GB sandbox)
CONTEXT = 128          # the model's attention band; windows overlap by this on each side
MIN_SPAN_SCORE = 0.6
DEFAULT_TOKEN_BUDGET = 40000   # ~4-5 min on one CPU core
MAX_TEXT_BYTES = 50 * 1024 * 1024
MAX_LINE_CHARS = 2000
OCR_MIN_SIDE, OCR_MIN_AREA = 120, 60000
DEFAULT_MAX_OCR = 40
MAX_VISUAL = 20
MAX_DEPTH = 4
MAX_LOCS_PER_FINDING = 20

CATEGORY_JA = {
    "private_person": "人名",
    "private_address": "住所",
    "private_phone": "電話番号",
    "private_email": "メールアドレス",
    "private_date": "個人に関する日付(生年月日等)",
    "account_number": "口座番号・カード番号等",
    "private_url": "個人に紐づくURL",
    "secret": "秘密情報の疑い",
    "my_number": "マイナンバー",
    "location_gps": "位置情報(GPS)",
    "metadata_person": "ファイルの作成者情報",
}

PROSE_EXT = {".txt", ".md", ".markdown", ".rst", ".csv", ".tsv", ".log", ".rtf", ".html", ".htm",
             ".tex", ".org", ".adoc", ".eml", ".vcf", ".ics", ".srt", ".vtt", ".text"}
PROSE_NAMES = {"license", "licence", "copying", "authors", "contributors", "notice", "maintainers",
               "credits", "changelog", "changes", "readme", "history", "thanks", "owners", "codeowners"}
IMAGE_EXT = {".png", ".jpg", ".jpeg", ".gif", ".webp", ".bmp", ".tif", ".tiff"}
OFFICE_PARTS = {
    "docx": re.compile(r"^word/(document|header\d*|footer\d*|footnotes|endnotes|comments)\.xml$"),
    "xlsx": re.compile(r"^xl/(sharedStrings|worksheets/sheet\d+|comments\d*)\.xml$"),
    "pptx": re.compile(r"^ppt/(slides/slide\d+|notesSlides/notesSlide\d+|comments/.*)\.xml$"),
    "odf": re.compile(r"^(content|meta)\.xml$"),
}
META_PARTS = re.compile(r"^docProps/(core|app)\.xml$")


def log(msg: str) -> None:
    print(f"[gfile-pii] {msg}", file=sys.stderr, flush=True)


# --------------------------------------------------------------------------
# data structures
# --------------------------------------------------------------------------
@dataclass(frozen=True)
class Loc:
    path: str
    line: Optional[int] = None
    page: Optional[int] = None
    kind: str = "text"     # text | ocr | pdf | office | filename | metadata

    def as_dict(self) -> dict:
        d = {"path": self.path, "kind": self.kind}
        if self.page is not None:
            d["page"] = self.page
        if self.line is not None:
            d["line"] = self.line
        return d


@dataclass
class Doc:
    """A sequence of lines fed to the model in order (context preserved)."""
    name: str
    priority: int
    lines: List[Tuple[str, List[Loc]]] = field(default_factory=list)


@dataclass
class Finding:
    category: str
    value: str
    detectors: set = field(default_factory=set)
    score: float = 0.0
    locs: List[dict] = field(default_factory=list)
    where: set = field(default_factory=set)

    @property
    def count(self) -> int:
        return len(self.where)

    def add(self, detector: str, loc: Loc, context: str, score: float = 1.0) -> None:
        self.detectors.add(detector)
        self.score = max(self.score, score)
        key = (loc.path, loc.line, loc.page)
        if key in self.where:
            return
        self.where.add(key)
        if len(self.locs) < MAX_LOCS_PER_FINDING:
            d = loc.as_dict()
            d["context"] = context
            self.locs.append(d)

    def absorb(self, other: "Finding") -> None:
        self.detectors |= other.detectors
        self.score = max(self.score, other.score)
        for d in other.locs:
            key = (d["path"], d.get("line"), d.get("page"))
            if key not in self.where:
                self.where.add(key)
                if len(self.locs) < MAX_LOCS_PER_FINDING:
                    self.locs.append(d)
        self.where |= other.where

    def as_dict(self) -> dict:
        return {
            "category": self.category,
            "category_ja": CATEGORY_JA.get(self.category, self.category),
            "value": self.value,
            "detectors": sorted(self.detectors),
            "score": round(self.score, 3),
            "occurrences": self.count,
            "locations": self.locs,
        }


class Collector:
    def __init__(self) -> None:
        self.docs: List[Doc] = []
        self.code_lines: Dict[str, List[Loc]] = {}
        self.filenames: Dict[str, List[Loc]] = {}
        self.images: List[dict] = []
        self.findings: Dict[Tuple[str, str], Finding] = {}
        self.not_scanned: Dict[str, List[str]] = {}
        self.files_seen = 0

    def skip(self, reason: str, path: str) -> None:
        self.not_scanned.setdefault(reason, []).append(path)

    def finding(self, category: str, value: str, detector: str, loc: Loc, context: str,
                score: float = 1.0) -> None:
        value = re.sub(r"\s+", " ", value).strip().strip(",;:()<>[]{}\"'`「」『』、。，．・")
        if not value:
            return
        key_val = value.lower() if category == "private_email" else value
        key = (category, key_val)
        f = self.findings.get(key)
        if f is None:
            f = self.findings[key] = Finding(category, value)
        f.add(detector, loc, context, score)


def merge_overlapping(findings: Dict[Tuple[str, str], Finding]) -> List[Finding]:
    """Fold a finding into a longer one of the same category that contains it at the same place
    (e.g. regex '〒150-0001' inside the model's full address span)."""
    by_cat: Dict[str, List[Finding]] = {}
    for f in findings.values():
        by_cat.setdefault(f.category, []).append(f)
    out: List[Finding] = []
    for cat, items in by_cat.items():
        items.sort(key=lambda f: -len(f.value))
        kept: List[Finding] = []
        for f in items:
            norm = re.sub(r"\s", "", f.value).lower()
            host = next((k for k in kept if norm and norm in re.sub(r"\s", "", k.value).lower()
                         and f.where & k.where), None)
            if host is not None and f.where <= host.where | f.where:
                host.absorb(f)
            else:
                kept.append(f)
        out.extend(kept)
    return out


def _context(line: str, start: int, end: int, width: int = 40) -> str:
    a, b = max(0, start - width), min(len(line), end + width)
    return ("…" if a > 0 else "") + line[a:b].replace("\t", " ") + ("…" if b < len(line) else "")


# --------------------------------------------------------------------------
# regex detectors
# --------------------------------------------------------------------------
PREFS = ("北海道|青森県|岩手県|宮城県|秋田県|山形県|福島県|茨城県|栃木県|群馬県|埼玉県|千葉県|東京都|神奈川県|"
         "新潟県|富山県|石川県|福井県|山梨県|長野県|岐阜県|静岡県|愛知県|三重県|滋賀県|京都府|大阪府|兵庫県|"
         "奈良県|和歌山県|鳥取県|島根県|岡山県|広島県|山口県|徳島県|香川県|愛媛県|高知県|福岡県|佐賀県|長崎県|"
         "熊本県|大分県|宮崎県|鹿児島県|沖縄県")
NUM = r"[0-9０-９一二三四五六七八九十〇]"
RE_EMAIL = re.compile(r"(?<![\w.%+-])[A-Za-z0-9._%+\-]{1,64}@[A-Za-z0-9\-]+(?:\.[A-Za-z0-9\-]+)*\.[A-Za-z]{2,24}(?![\w-])")
RE_JP_PHONE = re.compile(r"(?<![\d\-])(?:0\d{1,4}-\d{1,4}-\d{3,4}|0[5789]0\d{8}|\(0\d{1,4}\)\s?\d{1,4}-\d{4})(?![\d\-])")
RE_INTL_PHONE = re.compile(r"(?<![\w+])\+\d{1,3}[\s\-]?\(?\d{1,4}\)?(?:[\s\-]?\d{2,4}){2,4}(?![\d])")
RE_POSTAL = re.compile(r"〒\s?[0-9０-９]{3}[-－ー]?[0-9０-９]{4}")
RE_ADDRESS = re.compile(
    rf"(?:{PREFS})[^\s、。,，「」()（）]{{1,12}}?[市区町村郡][^\s、。,，「」()（）]{{0,24}}?"
    rf"(?:{NUM}+丁目|{NUM}+番地?|{NUM}+[-－ー]{NUM}+)(?:[-－ー]?{NUM}+){{0,2}}(?:号)?")
RE_MYNUMBER = re.compile(r"(?<!\d)\d{4}[\s\-]?\d{4}[\s\-]?\d{4}(?!\d)")
RE_MYNUMBER_CTX = re.compile(r"マイナンバー|個人番号|my\s?number", re.I)
RE_CARD = re.compile(r"(?<!\d)(?:\d{4}[ \-]){3}\d{1,7}(?!\d)|(?<!\d)\d{14,16}(?!\d)")
RE_CARD_CTX = re.compile(r"card|カード|クレジット|credit|visa|master|amex|jcb", re.I)
RE_BANK = re.compile(r"(?:口座番号|普通預金|当座預金|普通|当座)\s*[:：]?\s*(?:No\.?\s*)?([0-9０-９]{7})(?![0-9０-９])")
EMAIL_IGNORE = re.compile(r"@(?:[\w\-]+\.)*(?:example\.(?:com|org|net)|example|test|invalid|localhost)$", re.I)


def _mynumber_ok(digits: str) -> bool:
    if len(digits) != 12:
        return False
    p = [int(c) for c in digits[:11]][::-1]
    s = sum(p[n] * ((n + 1) + 1 if n <= 5 else (n + 1) - 5) for n in range(11))
    r = s % 11
    check = 0 if r <= 1 else 11 - r
    return check == int(digits[11])


def _luhn_ok(digits: str) -> bool:
    total, alt = 0, False
    for ch in reversed(digits):
        d = int(ch)
        if alt:
            d = d * 2 - 9 if d > 4 else d * 2
        total += d
        alt = not alt
    return total % 10 == 0


def _card_ok(digits: str) -> bool:
    if len(digits) not in (14, 15, 16, 19) or not _luhn_ok(digits):
        return False
    return bool(re.match(r"^(4|5[1-5]|2[2-7]|3[47]|35|36|38|6)", digits))


def regex_scan_line(col: Collector, line: str, loc: Loc) -> None:
    if len(line) > 20000:
        line = line[:20000]
    for m in RE_EMAIL.finditer(line):
        if not EMAIL_IGNORE.search(m.group(0)):
            col.finding("private_email", m.group(0), "regex", loc, _context(line, m.start(), m.end()))
    for rx in (RE_JP_PHONE, RE_INTL_PHONE):
        for m in rx.finditer(line):
            digits = re.sub(r"\D", "", m.group(0))
            if 10 <= len(digits) <= 15:
                col.finding("private_phone", m.group(0), "regex", loc, _context(line, m.start(), m.end()))
    for m in RE_POSTAL.finditer(line):
        col.finding("private_address", m.group(0), "regex", loc, _context(line, m.start(), m.end()))
    for m in RE_ADDRESS.finditer(line):
        col.finding("private_address", m.group(0), "regex", loc, _context(line, m.start(), m.end()))
    if RE_MYNUMBER_CTX.search(line):
        for m in RE_MYNUMBER.finditer(line):
            if _mynumber_ok(re.sub(r"\D", "", m.group(0))):
                col.finding("my_number", m.group(0), "regex", loc, _context(line, m.start(), m.end()))
    for m in RE_CARD.finditer(line):
        digits = re.sub(r"\D", "", m.group(0))
        separated = not m.group(0).isdigit()
        if _card_ok(digits) and (separated or RE_CARD_CTX.search(line)):
            col.finding("account_number", m.group(0), "regex", loc, _context(line, m.start(), m.end()))
    for m in RE_BANK.finditer(line):
        col.finding("account_number", m.group(0), "regex", loc, _context(line, m.start(), m.end()))


# lines from source code / config are sent to the model only if they could carry PII
RE_MODEL_WORTHY = re.compile(
    r"[\u3040-\u30ff\u3400-\u9fff\uff66-\uff9f]|@|\d{2,4}[-\s]\d{2,4}[-\s]\d{3,4}|"
    r"\b[A-Z][a-z]+ [A-Z][a-z]+\b|"
    r"(?i:name|address|addr|phone|tel|mobile|e-?mail|birth|dob|author|copyright|contact|owner|street|city|"
    r"zip|postal|customer)")


# --------------------------------------------------------------------------
# text extraction
# --------------------------------------------------------------------------
def decode_text(data: bytes) -> Optional[str]:
    if data.startswith((b"\xff\xfe", b"\xfe\xff")):
        try:
            return data.decode("utf-16")
        except UnicodeDecodeError:
            return None
    if b"\x00" in data[:8192]:
        return None
    for enc in ("utf-8", "cp932"):
        try:
            return data.decode(enc)
        except UnicodeDecodeError:
            continue
    return None


def xml_to_text(xml: str) -> str:
    xml = re.sub(r"</(?:w:p|a:p|text:p|text:h)>|<(?:w:br|w:tab|a:br|text:line-break)[^>]*/?>|</si>|</row>",
                 "\n", xml)
    xml = re.sub(r"</c>|</w:tc>", "\t", xml)
    text = re.sub(r"<[^>]+>", "", xml)
    return html.unescape(text)


def add_text(col: Collector, display: str, text: str, kind: str, prose: bool,
             page: Optional[int] = None, priority: int = 3) -> None:
    lines = text.splitlines()
    doc = Doc(f"{display}" + (f" p{page}" if page else ""), priority) if prose else None
    for i, ln in enumerate(lines, 1):
        if not ln.strip():
            continue
        loc = Loc(display, line=i, page=page, kind=kind)
        regex_scan_line(col, ln, loc)
        if len(ln) > MAX_LINE_CHARS:
            continue
        if prose:
            doc.lines.append((ln, [loc]))
        elif RE_MODEL_WORTHY.search(ln):
            col.code_lines.setdefault(ln.strip(), []).append(loc)
    if doc and doc.lines:
        col.docs.append(doc)


def sniff(head: bytes) -> str:
    k = secret_guard._sniff(head)
    if k == "raw":
        if head.startswith(b"%PDF"):
            return "pdf"
        if head[:8] == b"\x89PNG\r\n\x1a\n" or head[:3] == b"\xff\xd8\xff" or head[:6] in (b"GIF87a", b"GIF89a") \
                or (head[:4] == b"RIFF" and head[8:12] == b"WEBP") or head[:2] == b"BM" \
                or head[:4] in (b"II*\x00", b"MM\x00*"):
            return "image"
    return k


def process_file(col: Collector, disk: Path, display: str, depth: int, ocr: "OCR") -> None:
    col.files_seen += 1
    with open(disk, "rb") as f:
        head = f.read(4096)
    kind = sniff(head)
    ext = Path(display.split("!")[-1]).suffix.lower()

    if kind == "zip":
        try:
            with zipfile.ZipFile(disk) as zf:
                names = zf.namelist()
                office = office_kind(names, ext)
                if office:
                    process_office(col, zf, display, office)
                    return
                if depth >= MAX_DEPTH:
                    col.skip("archive nesting too deep", display)
                    return
                for info in zf.infolist():
                    mdisp = f"{display}!{info.filename}"
                    add_filename(col, info.filename, mdisp)
                    if info.is_dir() or info.flag_bits & 0x1:
                        continue
                    with zf.open(info) as src:
                        extract_and_process(col, src, mdisp, depth + 1, ocr)
        except (zipfile.BadZipFile, OSError, NotImplementedError, RuntimeError) as e:
            col.skip(f"unreadable zip ({type(e).__name__})", display)
        return

    if kind in ("tar", "gzip", "bz2", "xz"):
        if depth >= MAX_DEPTH:
            col.skip("archive nesting too deep", display)
            return
        try:
            with tarfile.open(disk, "r:*") as tf:
                for ti in tf:
                    mdisp = f"{display}!{ti.name}"
                    add_filename(col, ti.name, mdisp)
                    if ti.isfile():
                        src = tf.extractfile(ti)
                        if src:
                            with src:
                                extract_and_process(col, src, mdisp, depth + 1, ocr)
            return
        except (tarfile.TarError, OSError, EOFError):
            pass
        if kind != "tar":
            import bz2
            import gzip
            import lzma
            opener = {"gzip": gzip.open, "bz2": bz2.open, "xz": lzma.open}[kind]
            try:
                with opener(disk, "rb") as src:
                    extract_and_process(col, src, display + "!<decompressed>", depth + 1, ocr)
            except (OSError, EOFError, lzma.LZMAError) as e:
                col.skip(f"corrupt {kind} stream ({type(e).__name__})", display)
        return

    if kind == "pdf":
        process_pdf(col, disk, display, ocr)
        return
    if kind == "image" or ext in IMAGE_EXT:
        process_image(col, disk, display, ocr)
        return
    if kind.startswith("x:"):
        col.skip("uninspectable archive", display)
        return

    size = disk.stat().st_size
    if size > MAX_TEXT_BYTES:
        col.skip("text too large for PII scan (>50MB)", display)
        return
    data = disk.read_bytes()
    text = decode_text(data)
    if text is None:
        col.skip("binary (not PII-scanned)", display)
        return
    if ext == ".svg":
        text = xml_to_text(text)
    stem = Path(display.split("!")[-1]).stem.lower()
    add_text(col, display, text, "text", prose=ext in PROSE_EXT or stem in PROSE_NAMES, priority=3)


def extract_and_process(col, src, display, depth, ocr) -> None:
    WORK.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=WORK, suffix=Path(display).suffix[:10])
    with os.fdopen(fd, "wb") as out:
        shutil.copyfileobj(src, out, 8 * 1024 * 1024)
    try:
        process_file(col, Path(tmp), display, depth, ocr)
    finally:
        # extracted images are kept so that OCR / Claude's visual review can use them
        if not any(img["disk_path"] == tmp for img in col.images):
            os.unlink(tmp)


def office_kind(names: List[str], ext: str) -> Optional[str]:
    s = set(names)
    if "word/document.xml" in s:
        return "docx"
    if "xl/workbook.xml" in s:
        return "xlsx"
    if "ppt/presentation.xml" in s:
        return "pptx"
    if "content.xml" in s and "mimetype" in s:
        return "odf"
    return None


def process_office(col: Collector, zf: zipfile.ZipFile, display: str, kind: str) -> None:
    rx = OFFICE_PARTS[kind]
    for name in sorted(zf.namelist()):
        if META_PARTS.match(name) or (kind == "odf" and name == "meta.xml"):
            meta = zf.read(name).decode("utf-8", "replace")
            for tag in ("dc:creator", "cp:lastModifiedBy", "meta:initial-creator", "Company", "Manager"):
                for m in re.finditer(rf"<{tag}[^>]*>([^<]+)</{tag}>", meta):
                    val = html.unescape(m.group(1)).strip()
                    if val:
                        col.finding("metadata_person", val, "metadata", Loc(f"{display}!{name}", kind="metadata"),
                                    f"{tag} = {val}")
            continue
        if rx.match(name):
            text = xml_to_text(zf.read(name).decode("utf-8", "replace"))
            add_text(col, f"{display}!{name}", text, "office", prose=True, priority=2)
        elif name.startswith(("word/media/", "ppt/media/", "xl/media/", "Pictures/")) and \
                Path(name).suffix.lower() in IMAGE_EXT:
            with zf.open(name) as src:
                extract_and_process(col, src, f"{display}!{name}", MAX_DEPTH, OCR_SENTINEL)


def process_pdf(col: Collector, disk: Path, display: str, ocr: "OCR") -> None:
    if shutil.which("pdfinfo"):
        try:
            info = subprocess.run(["pdfinfo", str(disk)], capture_output=True, text=True, timeout=60).stdout
            for key in ("Author", "Creator"):
                m = re.search(rf"^{key}:\s+(.+)$", info, re.M)
                if m and key == "Author":
                    col.finding("metadata_person", m.group(1).strip(), "metadata",
                                Loc(display, kind="metadata"), f"PDF {key} = {m.group(1).strip()}")
        except (subprocess.SubprocessError, OSError):
            pass
    text = ""
    if shutil.which("pdftotext"):
        try:
            text = subprocess.run(["pdftotext", "-layout", str(disk), "-"], capture_output=True,
                                  timeout=300).stdout.decode("utf-8", "replace")
        except (subprocess.SubprocessError, OSError):
            text = ""
    if len(text.strip()) >= 20:
        for p, page_text in enumerate(text.split("\f"), 1):
            if page_text.strip():
                add_text(col, display, page_text, "pdf", prose=True, page=p, priority=2)
        return
    # scanned PDF: render pages and OCR them
    if ocr.available and shutil.which("pdftoppm"):
        out = Path(tempfile.mkdtemp(dir=WORK if WORK.exists() else None))
        try:
            subprocess.run(["pdftoppm", "-r", "150", "-l", "10", "-png", str(disk), str(out / "p")],
                           capture_output=True, timeout=600)
            for img in sorted(out.glob("p*.png")):
                page = int(re.sub(r"\D", "", img.stem) or 0)
                t = ocr.run(img)
                if t.strip():
                    add_text(col, display, t, "ocr", prose=True, page=page, priority=1)
        finally:
            shutil.rmtree(out, ignore_errors=True)
        col.skip("scanned PDF: only first 10 pages OCR'd", display)
    else:
        col.skip("PDF without text layer (no OCR available)", display)


GPS_TAGS = {1: "lat_ref", 2: "lat", 3: "lon_ref", 4: "lon"}


def _dms(v) -> Optional[float]:
    try:
        d, m, s = (float(x) for x in v)
        return d + m / 60 + s / 3600
    except Exception:
        return None


def process_image(col: Collector, disk: Path, display: str, ocr: "OCR") -> None:
    try:
        from PIL import Image
        with Image.open(disk) as im:
            w, h = im.size
            fmt = (im.format or "").upper()
            exif = im.getexif()
            # GPS
            try:
                gps = exif.get_ifd(0x8825)
            except Exception:
                gps = {}
            if gps and 2 in gps and 4 in gps:
                lat, lon = _dms(gps[2]), _dms(gps[4])
                if lat is not None and lon is not None:
                    if gps.get(1) == "S":
                        lat = -lat
                    if gps.get(3) == "W":
                        lon = -lon
                    val = f"{lat:.6f}, {lon:.6f}"
                    col.finding("location_gps", val, "metadata", Loc(display, kind="metadata"),
                                f"EXIF GPS {val}")
            for tag, label in ((315, "Artist"), (33432, "Copyright"), (42032, "CameraOwnerName"),
                               (40093, "XPAuthor"), (270, "ImageDescription")):
                v = exif.get(tag)
                if isinstance(v, bytes):
                    v = v.decode("utf-16-le" if tag == 40093 else "utf-8", "replace").strip("\x00 ")
                if v and str(v).strip():
                    val = str(v).strip()
                    if tag in (270,):
                        add_text(col, display, val, "metadata", prose=True, priority=0)
                    else:
                        col.finding("metadata_person", val, "metadata", Loc(display, kind="metadata"),
                                    f"EXIF {label} = {val}")
            for k, v in (im.info or {}).items():
                if isinstance(v, str) and k.lower() in ("author", "comment", "description", "title",
                                                        "copyright", "software", "source", "xml:com.adobe.xmp"):
                    if k.lower() == "author":
                        col.finding("metadata_person", v.strip(), "metadata", Loc(display, kind="metadata"),
                                    f"PNG {k} = {v.strip()}")
                    elif k.lower() != "software":
                        add_text(col, display, v[:5000], "metadata", prose=True, priority=0)
            photo_like = bool(exif.get(0x010F) or exif.get(0x0110)) or (fmt == "JPEG" and min(w, h) >= 300)
    except Exception as e:  # unreadable / unsupported image
        col.skip(f"unreadable image ({type(e).__name__})", display)
        return
    col.images.append({"display": display, "disk_path": str(disk), "width": w, "height": h,
                       "format": fmt, "photo_like": photo_like, "ocr_chars": 0, "ocr_done": False})


RE_HUMANISH_NAME = re.compile(r"[\u3040-\u30ff\u3400-\u9fff]| |[A-Z][a-z]+[_\-.][A-Z][a-z]+")


def add_filename(col: Collector, name: str, display: str) -> None:
    base = name.rstrip("/").split("/")[-1]
    if base:
        loc = Loc(display, kind="filename")
        regex_scan_line(col, base, loc)
        if RE_HUMANISH_NAME.search(base):   # only human-looking names go to the model
            col.filenames.setdefault(base, []).append(loc)


# --------------------------------------------------------------------------
# OCR
# --------------------------------------------------------------------------
class OCR:
    def __init__(self, enabled: bool = True) -> None:
        self.available = False
        self.reason = ""
        self.tessdata = CACHE / "tessdata"
        if not enabled:
            self.reason = "disabled"
            return
        if not shutil.which("tesseract"):
            self.reason = "tesseract not installed"
            return
        try:
            self.tessdata.mkdir(parents=True, exist_ok=True)
            for lang in ("jpn", "eng"):
                p = self.tessdata / f"{lang}.traineddata"
                if not p.exists() or p.stat().st_size < 100000:
                    sys_p = Path(f"/usr/share/tesseract-ocr/5/tessdata/{lang}.traineddata")
                    if sys_p.exists():
                        shutil.copy(sys_p, p)
                    else:
                        _download(TESSDATA_URL.format(lang=lang), p)
            self.available = True
        except Exception as e:
            self.reason = f"could not prepare OCR data ({e.__class__.__name__}: {e})"

    def run(self, image: Path) -> str:
        env = dict(os.environ, TESSDATA_PREFIX=str(self.tessdata), OMP_THREAD_LIMIT="1")
        src = image
        tmp = None
        try:
            from PIL import Image
            with Image.open(image) as im:
                im.seek(0)
                w, h = im.size
                if max(w, h) < 1000:   # small images OCR better when upscaled
                    tmp = Path(tempfile.mkstemp(suffix=".png")[1])
                    im.convert("RGB").resize((w * 2, h * 2)).save(tmp)
                    src = tmp
                elif (im.format or "").upper() not in ("PNG", "JPEG", "TIFF", "BMP"):
                    tmp = Path(tempfile.mkstemp(suffix=".png")[1])
                    im.convert("RGB").save(tmp)
                    src = tmp
            r = subprocess.run(["tesseract", str(src), "-", "-l", "jpn+eng"], capture_output=True,
                               env=env, timeout=180)
            text = r.stdout.decode("utf-8", "replace")
            # tesseract puts spaces between CJK characters; remove them
            text = re.sub(r"(?<=[\u3040-\u30ff\u3400-\u9fff])\s(?=[\u3040-\u30ff\u3400-\u9fff])", "", text)
            return text
        except Exception:
            return ""
        finally:
            if tmp:
                tmp.unlink(missing_ok=True)


class _NoOCR:
    available = False


OCR_SENTINEL = _NoOCR()   # images inside office files are OCR'd later with the rest


# --------------------------------------------------------------------------
# model
# --------------------------------------------------------------------------
def _sha256(p: Path) -> str:
    h = hashlib.sha256()
    with open(p, "rb") as f:
        for b in iter(lambda: f.read(8 * 1024 * 1024), b""):
            h.update(b)
    return h.hexdigest()


def _download(url: str, dest: Path, expected_size: Optional[int] = None) -> None:
    import requests
    part = dest.with_suffix(dest.suffix + ".part")
    have = part.stat().st_size if part.exists() else 0
    headers = {"User-Agent": "gfile-skill"}
    if have and expected_size and have < expected_size:
        headers["Range"] = f"bytes={have}-"
    with requests.get(url, headers=headers, stream=True, timeout=(30, 600), allow_redirects=True) as r:
        if r.status_code == 200:
            have = 0
            mode = "wb"
        elif r.status_code == 206:
            mode = "ab"
        else:
            deny = r.headers.get("x-deny-reason")
            raise RuntimeError(f"HTTP {r.status_code} for {url}" + (f" (proxy: {deny})" if deny else ""))
        with open(part, mode) as out:
            for chunk in r.iter_content(4 * 1024 * 1024):
                out.write(chunk)
    part.rename(dest)


def ensure_python_deps() -> Optional[str]:
    missing = []
    for mod, pkg in (("onnxruntime", "onnxruntime"), ("tokenizers", "tokenizers"), ("numpy", "numpy")):
        try:
            __import__(mod)
        except ImportError:
            missing.append(pkg)
    if missing:
        log(f"installing {', '.join(missing)} ...")
        r = subprocess.run([sys.executable, "-m", "pip", "install", "-q", "--break-system-packages", *missing],
                           capture_output=True, text=True)
        if r.returncode != 0:
            return f"pip install failed: {r.stderr.strip()[-300:]}"
    return None


def ensure_model() -> Path:
    root = CACHE / "privacy-filter" / MODEL_REV
    for rel, (size, sha) in MODEL_FILES.items():
        dest = root / rel
        marker = dest.with_suffix(dest.suffix + ".verified")
        if dest.exists() and marker.exists() and marker.read_text().strip() == sha:
            continue
        dest.parent.mkdir(parents=True, exist_ok=True)
        if not (dest.exists() and dest.stat().st_size == size):
            log(f"downloading {rel} ({size / 1e6:.0f} MB) ...")
            url = f"https://huggingface.co/{MODEL_REPO}/resolve/{MODEL_REV}/{rel}"
            _download(url, dest, size)
        if dest.stat().st_size != size or _sha256(dest) != sha:
            dest.unlink(missing_ok=True)
            raise RuntimeError(f"integrity check failed for {rel}")
        marker.write_text(sha)
    return root


class PrivacyFilter:
    def __init__(self, root: Path) -> None:
        import numpy as np
        import onnxruntime as ort
        from tokenizers import Tokenizer
        self.np = np
        cfg = json.loads((root / "config.json").read_text())
        self.labels = [cfg["id2label"][str(i)] for i in range(len(cfg["id2label"]))]
        self.tok = Tokenizer.from_file(str(root / "tokenizer.json"))
        so = ort.SessionOptions()
        so.intra_op_num_threads = max(1, os.cpu_count() or 1)
        t = time.time()
        self.sess = ort.InferenceSession(str(root / "onnx/model_q4.onnx"), so, providers=["CPUExecutionProvider"])
        log(f"model loaded in {time.time() - t:.0f}s")
        self._build_transitions()

    def _build_transitions(self) -> None:
        np = self.np
        K = len(self.labels)
        allowed = np.zeros((K, K), dtype=bool)
        tag = [l.split("-", 1)[0] if l != "O" else "O" for l in self.labels]
        cat = [l.split("-", 1)[1] if l != "O" else "" for l in self.labels]
        for i in range(K):
            for j in range(K):
                if tag[i] in ("O", "E", "S"):
                    allowed[i, j] = tag[j] in ("O", "B", "S")
                else:  # B or I
                    allowed[i, j] = tag[j] in ("I", "E") and cat[j] == cat[i]
        self.trans = np.where(allowed, 0.0, -1e9).astype(np.float32)
        self.start = np.array([0.0 if t in ("O", "B", "S") else -1e9 for t in tag], dtype=np.float32)
        self.end = np.array([0.0 if t in ("O", "E", "S") else -1e9 for t in tag], dtype=np.float32)
        self.tag, self.cat = tag, cat

    def count_tokens(self, text: str) -> int:
        return len(self.tok.encode(text, add_special_tokens=False).ids)

    def _logits(self, ids: List[int], progress: bool = False):
        np = self.np
        n = len(ids)
        t0 = time.time()
        out = np.zeros((n, len(self.labels)), dtype=np.float32)
        step = WINDOW - 2 * CONTEXT
        s = 0
        while True:
            e = min(n, s + WINDOW)
            arr = np.array([ids[s:e]], dtype=np.int64)
            lg = self.sess.run(None, {"input_ids": arr, "attention_mask": np.ones_like(arr)})[0][0]
            keep_from = s + (CONTEXT if s > 0 else 0)
            keep_to = e if e == n else e - CONTEXT
            out[keep_from:keep_to] = lg[keep_from - s:keep_to - s]
            if progress:
                log(f"model: {e}/{n} tokens ({time.time() - t0:.0f}s)")
            if e == n:
                break
            s += step
        return out

    def detect(self, text: str, progress: bool = False):
        np = self.np
        enc = self.tok.encode(text, add_special_tokens=False)
        if not enc.ids:
            return []
        logits = self._logits(enc.ids, progress)
        m = logits.max(axis=1, keepdims=True)
        logp = logits - m - np.log(np.exp(logits - m).sum(axis=1, keepdims=True))
        n, K = logp.shape
        score = logp[0] + self.start
        back = np.zeros((n, K), dtype=np.int32)
        for t in range(1, n):
            cand = score[:, None] + self.trans
            back[t] = cand.argmax(axis=0)
            score = cand.max(axis=0) + logp[t]
        score = score + self.end
        path = [int(score.argmax())]
        for t in range(n - 1, 0, -1):
            path.append(int(back[t, path[-1]]))
        path.reverse()
        probs = np.exp(logp)
        spans, i = [], 0
        while i < n:
            tg = self.tag[path[i]]
            if tg in ("B", "S"):
                j = i
                if tg == "B":
                    while j + 1 < n and self.tag[path[j + 1]] in ("I", "E"):
                        j += 1
                        if self.tag[path[j]] == "E":
                            break
                sc = float(np.mean([probs[k, path[k]] for k in range(i, j + 1)]))
                a, b = enc.offsets[i][0], enc.offsets[j][1]
                spans.append((self.cat[path[i]], a, b, sc))
                i = j + 1
            else:
                i += 1
        return spans


def run_model(col: Collector, budget: int) -> dict:
    info = {"used": False, "reason": "", "tokens_processed": 0, "token_budget": budget, "not_model_scanned": []}
    # model inputs in priority order: file names, metadata/OCR, office/PDF, prose, code lines
    docs: List[Doc] = []
    if col.filenames:
        docs.append(Doc("<file names>", 0, [(n, locs) for n, locs in col.filenames.items()]))
    docs.extend(sorted(col.docs, key=lambda d: d.priority))
    if col.code_lines:
        docs.append(Doc("<source/config lines>", 4, [(ln, locs) for ln, locs in col.code_lines.items()]))
    if not any(d.lines for d in docs):
        info["reason"] = "no text needed model inspection"
        return info
    err = ensure_python_deps()
    if err:
        info["reason"] = err
        return info
    try:
        pf = PrivacyFilter(ensure_model())
    except Exception as e:
        info["reason"] = f"model unavailable: {e.__class__.__name__}: {e}"
        return info
    info["used"] = True

    # all documents go into one text (separated by blank lines) so that short files do not
    # each pay the per-call overhead; the model's 128-token attention band keeps them apart
    lines: List[Tuple[str, List[Loc]]] = []
    used, skipped, over = 0, set(), 0
    for d in docs:
        if lines:
            lines.append(("", []))
        for ln, locs in d.lines:
            c = pf.count_tokens(ln) + 1
            if used + c > budget:
                over += c
                skipped.update(loc.path for loc in locs)
                continue
            used += c
            lines.append((ln, locs))
    text = "\n".join(l for l, _ in lines)
    starts, pos = [], 0
    for l, _ in lines:
        starts.append(pos)
        pos += len(l) + 1
    log(f"model input: {used} tokens (budget {budget}{', ' + str(over) + ' tokens over budget' if over else ''})")
    t0 = time.time()
    for cat, a, b, sc in pf.detect(text, progress=True):
        if sc < MIN_SPAN_SCORE:
            continue
        value = text[a:b].strip()
        if len(value) < 2 or not re.search(r"[\w\u3040-\u30ff\u3400-\u9fff]", value):
            continue
        li = bisect.bisect_right(starts, a) - 1
        line, locs = lines[li]
        ca, cb = a - starts[li], min(len(line), b - starts[li])
        for loc in locs:
            col.finding(cat, value, "privacy-filter", loc, _context(line, ca, cb), sc)
    log(f"model done in {time.time() - t0:.0f}s")
    info["tokens_processed"] = used
    if over:
        info["reason"] = f"token budget exceeded: about {over} tokens were checked by regex only"
        info["not_model_scanned"] = sorted(skipped)[:50]
    return info


# --------------------------------------------------------------------------
# main
# --------------------------------------------------------------------------
def fingerprint(paths) -> str:
    h = hashlib.sha256()
    entries = []
    for fp, _ in secret_guard.iter_files([Path(p) for p in paths]):
        if fp.is_file():
            st = fp.stat()
            entries.append(f"{os.path.realpath(fp)}\0{st.st_size}\0{st.st_mtime_ns}")
    for e in sorted(entries):
        h.update(e.encode("utf-8", "surrogateescape") + b"\n")
    return h.hexdigest()


def scan(paths: List[str], budget: int = DEFAULT_TOKEN_BUDGET, max_ocr: int = DEFAULT_MAX_OCR,
         use_model: bool = True) -> dict:
    t0 = time.time()
    shutil.rmtree(WORK, ignore_errors=True)
    WORK.mkdir(parents=True, exist_ok=True)
    col = Collector()
    ocr = OCR(enabled=max_ocr > 0)
    for fp, display in secret_guard.iter_files([Path(p) for p in paths]):
        if not fp.is_file():
            continue
        v = secret_guard.location_violation(fp)
        if v:
            col.skip(f"refused location: {v}", display)
            continue
        add_filename(col, fp.name, display)
        try:
            process_file(col, fp, display, 0, ocr)
        except Exception as e:
            col.skip(f"error ({type(e).__name__}: {e})", display)

    # OCR, biggest images first
    ocr_info = {"available": ocr.available, "reason": ocr.reason, "images_total": len(col.images),
                "images_ocr": 0, "images_skipped_small": 0, "images_skipped_cap": 0}
    if ocr.available:
        cands = [im for im in col.images if min(im["width"], im["height"]) >= OCR_MIN_SIDE
                 and im["width"] * im["height"] >= OCR_MIN_AREA]
        ocr_info["images_skipped_small"] = len(col.images) - len(cands)
        cands.sort(key=lambda im: -im["width"] * im["height"])
        for k, im in enumerate(cands):
            if k >= max_ocr:
                ocr_info["images_skipped_cap"] += 1
                continue
            log(f"OCR {k + 1}/{min(len(cands), max_ocr)}: {im['display']}")
            text = ocr.run(Path(im["disk_path"]))
            im["ocr_done"] = True
            im["ocr_chars"] = len(re.sub(r"\s", "", text))
            if im["ocr_chars"] >= 4:
                add_text(col, im["display"], text, "ocr", prose=True, priority=1)
                ocr_info["images_ocr"] += 1

    model_info = run_model(col, budget) if use_model else {"used": False, "reason": "disabled"}

    # images Claude should look at itself (faces, names on screen, etc.)
    vis = sorted(
        [im for im in col.images if im["photo_like"] or im["ocr_chars"] >= 10 or
         (not ocr.available and min(im["width"], im["height"]) >= OCR_MIN_SIDE)],
        key=lambda im: (-(im["photo_like"]), -im["ocr_chars"], -im["width"] * im["height"]))
    findings = sorted((f.as_dict() for f in merge_overlapping(col.findings)),
                      key=lambda f: (f["category"], -f["occurrences"], f["value"]))
    return {
        "ok": not findings,
        "elapsed_sec": round(time.time() - t0, 1),
        "fingerprint": fingerprint(paths),
        "inputs": [str(p) for p in paths],
        "files_seen": col.files_seen,
        "model": model_info,
        "ocr": ocr_info,
        "findings_count": len(findings),
        "findings": findings,
        "images_for_visual_review": [{"path": im["disk_path"], "display": im["display"],
                                      "size": f"{im['width']}x{im['height']}", "photo_like": im["photo_like"],
                                      "ocr_chars": im["ocr_chars"]} for im in vis[:MAX_VISUAL]],
        "images_not_visually_listed": max(0, len(vis) - MAX_VISUAL),
        "not_scanned": {k: {"count": len(v), "examples": v[:10]} for k, v in col.not_scanned.items()},
    }


def to_markdown(rep: dict) -> str:
    out = ["# gfile PII report", ""]
    out.append(f"- findings: {rep['findings_count']}")
    out.append(f"- model: {'used' if rep['model'].get('used') else 'NOT used'} {rep['model'].get('reason', '')}")
    out.append(f"- OCR: {'available' if rep['ocr']['available'] else 'unavailable'} "
               f"({rep['ocr']['images_ocr']} image(s) with text)")
    out.append("")
    for i, f in enumerate(rep["findings"], 1):
        out.append(f"## {i}. {f['category_ja']}: {f['value']}")
        out.append(f"detectors: {', '.join(f['detectors'])} / score {f['score']} / {f['occurrences']} occurrence(s)")
        for loc in f["locations"]:
            where = loc["path"]
            if "page" in loc:
                where += f" p.{loc['page']}"
            if "line" in loc:
                where += f" L{loc['line']}"
            out.append(f"- `{where}` ({loc['kind']}): {loc['context']}")
        out.append("")
    if rep["not_scanned"]:
        out.append("## Not PII-scanned")
        for reason, d in rep["not_scanned"].items():
            out.append(f"- {reason}: {d['count']} (e.g. {', '.join(d['examples'][:3])})")
    return "\n".join(out) + "\n"


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="pii_scan", description="report PII in files (never modifies them)")
    ap.add_argument("paths", nargs="+")
    ap.add_argument("--json-out")
    ap.add_argument("--md-out", help="also write a human-readable Markdown report")
    ap.add_argument("--token-budget", type=int, default=DEFAULT_TOKEN_BUDGET)
    ap.add_argument("--max-ocr", type=int, default=DEFAULT_MAX_OCR)
    ap.add_argument("--no-model", action="store_true", help="regex/OCR/metadata only (for testing)")
    a = ap.parse_args(argv)
    for p in a.paths:
        if not Path(p).exists():
            log(f"no such file: {p}")
            return 1
    rep = scan(a.paths, a.token_budget, a.max_ocr, use_model=not a.no_model)
    text = json.dumps(rep, ensure_ascii=False, indent=2)
    if a.json_out:
        Path(a.json_out).write_text(text + "\n", encoding="utf-8")
    if a.md_out:
        Path(a.md_out).write_text(to_markdown(rep), encoding="utf-8")
    print(text)
    return 0 if rep["ok"] else 2


if __name__ == "__main__":
    sys.exit(main())
