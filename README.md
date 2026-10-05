# gfile

**English** | [日本語](README.ja.md)

An Agent Skill that lets Claude (claude.ai web / mobile) share files through
[GigaFile便 (gigafile.nu)](https://gigafile.nu/) straight from its sandbox.

claude.ai can only hand over files up to **30 MB** per file. Larger outputs — an APK,
a video, a dataset — may show a file card in the chat but cannot actually be downloaded.
With this skill Claude uploads such files to GigaFile便 instead and gives you the share
URL, retention period, download key and delete key.

## Features

- **Two triggers**: you explicitly ask Claude to share via GigaFile便, or one of
  Claude's own outputs exceeds the 30 MB download limit.
- **Download key is mandatory.** Claude asks you for the retention period and the
  download key with its question UI. The default key suggestion is today's date as
  `MMdd` (e.g. `1005` for October 5); you can type any other key (1–4 alphanumerics).
  If the key cannot be set *and verified*, the upload is deleted automatically.
- **Secrets are never uploaded.** A built-in scanner (`secret_guard.py`) inspects every
  file before upload — including the contents of zip / apk / jar / tar / gz archives,
  recursively — and refuses API keys, tokens, private keys, passwords, `.env`,
  `auth.json`, keystores and similar. There is intentionally **no override**.
  Encrypted or uninspectable archives (password-protected zip, 7z, rar) are refused too.
- **Personal information is checked before anything is shared.** Names, home addresses,
  phone numbers, emails, birth dates, account / card numbers, My Number, GPS positions
  and author metadata are detected with
  [OpenAI Privacy Filter](https://huggingface.co/openai/privacy-filter) (run locally via
  onnxruntime), regular expressions tuned for Japanese and English, image metadata, and
  OCR (Tesseract jpn+eng) of screenshots and other images. Claude also looks at the
  images itself (faces, names on screen, ID cards, ...). Nothing is masked or removed
  automatically: Claude lists **every** finding with its location and asks you what to
  do. Obvious false positives (code identifiers, company names, sample data, ...) are
  skipped.
- **Full report**: share URL, retention (days and expiry date), download key and
  delete key are always reported back to you.
- Chunked upload (100 MB chunks, sequential, like the official web uploader),
  automatic bundling of multiple files / folders into one zip, SHA-256 of the upload,
  and deletion by delete key.

## Requirements

- Claude on the web or mobile apps with **Code execution and file creation** enabled
- **Network egress** that allows `gigafile.nu`, `*.gigafile.nu` (upload),
  `huggingface.co`, `*.hf.co` (Privacy Filter model) and `github.com`,
  `raw.githubusercontent.com` (OCR language data) — e.g. "All domains"
- Python 3 with `requests`, `numpy`, `Pillow`, `onnxruntime` and Tesseract
  (preinstalled in the claude.ai sandbox; `tokenizers` is installed automatically)
- About 1 GB of free disk and 3 GB of RAM for the model (the q4 ONNX weights, ~0.9 GB,
  are downloaded once per sandbox session and verified by SHA-256)

## Installation

1. Zip the skill folder (the `gfile` folder itself must be at the top of the archive):
   ```bash
   cd skills && zip -r ../gfile.zip gfile
   ```
2. Upload `gfile.zip` from the Skills section of Claude's settings and enable it.

## Usage

Just talk to Claude:

- "Share `build/app-release.apk` via GigaFile便."
- "Build the APK and send it to me." — if the APK is over 30 MB, Claude switches to
  GigaFile便 by itself.
- "Delete the GigaFile upload from earlier."

Claude checks for secrets and personal information first, shows you anything it
found, asks for the retention period (3 / 5 / 7 / 14 / 30 / 60 / 100 days) and the
download key, uploads, and replies with:

```
- Share URL:     https://NN.gigafile.nu/MMDD-xxxxxxxx
- Retention:     7 days (until 2026-10-12)
- Download key:  1005
- Delete key:    ab12
```

Share only the URL and the download key with recipients — anyone holding the delete
key can delete the file.

### CLI (used by Claude inside the sandbox)

```bash
python3 skills/gfile/scripts/gfile.py check  <paths...>                  # size + secret scan, no network
python3 skills/gfile/scripts/gfile.py pii    <paths...> --json-out pii.json [--md-out pii.md]
python3 skills/gfile/scripts/gfile.py upload <paths...> --lifetime 7 --dlkey 1005 --pii-report pii.json \
                                      [--pii-reviewed] [--name NAME] [--json-out FILE]
python3 skills/gfile/scripts/gfile.py delete <url> --delkey ab12
```

`upload` refuses to run without a PII report for exactly the same files. If the report
lists findings, images to review, or could not use the model, `--pii-reviewed` is
required — Claude passes it only after you have seen the findings and decided.

Exit codes: `0` success, `2` invalid input (for `pii`: findings to review), `3` refused
by the secret scanner, `4` network error, `5` unexpected GigaFile response, `6` download
key could not be set or verified (upload deleted), `7` delete failed, `8` PII report
missing, stale or not reviewed.

## Repository layout

```
.
├── LICENSE
├── README.md / README.ja.md
└── skills/
    └── gfile/                  # the skill itself (only this folder is installed)
        ├── SKILL.md
        ├── scripts/
        │   ├── gfile.py        # check / pii / upload / delete
        │   ├── secret_guard.py # credential scanner (fail-closed, no override)
        │   └── pii_scan.py     # personal-information scanner (report only)
        └── references/
            └── protocol.md     # GigaFile web endpoints, for maintenance
```

## Limitations and notes

- **Unofficial.** GigaFile便 has no public API; this skill uses the same endpoints as
  the official web uploader. It is not affiliated with or endorsed by GigaFile, and it
  may break if the site changes. Follow GigaFile's terms of service.
- The download key can only be set after the upload completes, so a just-uploaded file
  is reachable without a key for a few seconds (its URL is random and not yet shared).
- The 30 MB threshold comes from the claude.ai help center ("The maximum file size is
  30MB per file for both uploads and downloads", checked October 2026). It is a
  constant in `gfile.py` if this changes.
- PII detection is best effort. Privacy Filter is trained primarily on English; it works
  on Japanese but less reliably. OCR can misread text, only the 20 most relevant images
  are reviewed visually, the model reads at most 40,000 tokens per run (about 4–5
  minutes on one CPU core; the rest is checked by regular expressions), and compiled
  binaries (dex, .so, ...) are not PII-scanned.
- The secret scanner is pattern-based. It errs on the side of refusing (for example, an
  APK that embeds a Google API key is refused) and cannot guarantee that every possible
  secret is detected — don't ask Claude to share files you know contain secrets.

## License

[MIT](LICENSE)

Third-party components are downloaded at run time and are not part of this repository:
[OpenAI Privacy Filter](https://huggingface.co/openai/privacy-filter) (Apache-2.0) and
[Tesseract tessdata_fast](https://github.com/tesseract-ocr/tessdata_fast) (Apache-2.0).
