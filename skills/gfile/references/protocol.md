# GigaFile便 web endpoints used by gfile

GigaFile便 has no public API. `scripts/gfile.py` talks to the same endpoints as the
official web uploader (`https://gigafile.nu/js/upload.js`, `gfupload-1.0.2.min.js`,
`js/download.js`). Verified working on 2026-10-05. Read this only when the script
fails with exit code 5 or other signs that the site changed.

## 1. Upload server

`GET https://gigafile.nu/` → the HTML contains `server = "NN.gigafile.nu"`.
The page also defines `max_size = "300gb"` and `chunk_size = "100mb"`.
gfile only accepts hosts matching `^[0-9]{1,3}\.gigafile\.nu$`.

## 2. Chunked upload

`POST https://NN.gigafile.nu/upload_chunk.php` (multipart/form-data), chunks sent
sequentially in order:

| field      | value                                                        |
|------------|--------------------------------------------------------------|
| `id`       | random token, same for all chunks (web uses 4×uint32 as hex) |
| `name`     | file name shown to downloaders                               |
| `chunk`    | 0-based chunk index                                          |
| `chunks`   | total chunk count (1 for an empty file)                      |
| `lifetime` | retention days; UI offers 3, 5, 7, 14, 30, 60, 100           |
| `file`     | chunk bytes (`blob`, application/octet-stream)               |

Every chunk returns `{"status":0}`; the last one returns
`{"status":0,"url":"https://NN.gigafile.nu/MMDD-xxxx","delkey":"abcd","filename":"MMDD-xxxx","jwt":"..."}`.
The JWT payload (not verified by gfile) contains `d_expiry` (YYYY-MM-DD), used as the
reported expiry date. `MMDD` in the file id is the expiry date. `status != 0` carries
a `message`.

The server accepts arbitrary `lifetime` values, but gfile restricts them to the UI values.

## 3. Download key (ダウンロードキー)

`GET https://NN.gigafile.nu/set_dlkey.php?file=<filename>&delkey=<delkey>&dlkey=<key>`
→ `{"status":0}` on success, `{"status":1}` on a wrong delkey.
The UI requires `^[0-9a-zA-Z]{1,4}$`.

Verification used by gfile (no wrong-key probes, because repeated wrong attempts can
lock a file — `check_dlkey.php` returns `status 3` when locked):

* `GET https://NN.gigafile.nu/<filename>` contains `download('<filename>', true, ...)`
  when a key is set (`false` when not).
* `GET https://NN.gigafile.nu/check_dlkey.php?file=<filename>&dlkey=<key>&is_zip=0`
  → `{"status":0}` when the key is correct.

## 4. Download (for reference)

Visit the download page first (sets the session cookie), then
`GET https://NN.gigafile.nu/download.php?file=<filename>&dlkey=<key>`.
Without the cookie the server answers with an HTML alert instead of the file; with a
wrong or missing key it answers with an alert saying the key differs.

## 5. Delete

`GET https://NN.gigafile.nu/remove.php?file=<filename>&delkey=<delkey>` → `{"status":0}`.
Afterwards the download page no longer contains the `download('<filename>'` call.
The UI requires `^[0-9a-zA-Z]{4}$` for delete keys.

## 6. Terms of service notes

The GigaFile terms prohibit loading servers or lines beyond normal use. gfile therefore
uploads one file at a time, one chunk at a time (like the official uploader), and
retries a failed chunk at most 4 times with increasing waits.
