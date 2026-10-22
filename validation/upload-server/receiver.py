#!/usr/bin/env python3
"""Reference receiver for upload protocol v1 (docs/UPLOAD_PROTOCOL.md). Stdlib only.

    python3 receiver.py --port 8443 --cert certs/server.pem --key certs/server.key \
        --data data --token-file token.txt [--max-bytes N]

GET  /api/v1/health    -> 200 {"status":"ok","protocol_version":1}
POST /api/v1/captures  -> 201 receipt (new) | 200 receipt (identical replay) | 4xx/5xx error

Transaction: the multipart body is streamed with bounded memory into a private
staging directory while SHA-256 is computed; only after manifest, digests, sizes
and sidecar identity validate is the staging directory renamed (atomically) into
the visible dataset directory, and only then is the receipt returned.
Test-only fault injection: --drop-response-once (commit, then close without a reply).
"""
import argparse
import hashlib
import hmac
import json
import os
import re
import shutil
import ssl
import sys
import tempfile
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

PROTOCOL_VERSION = 1
UUID_RE = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")
HEX64_RE = re.compile(r"^[0-9a-f]{64}$")
MAX_SMALL_PART = 64 * 1024        # manifest
MAX_METADATA = 32 * 1024 * 1024   # sidecar JSON
CHUNK = 64 * 1024


class HttpError(Exception):
    def __init__(self, status, msg):
        super().__init__(msg)
        self.status, self.msg = status, msg


class BodyReader:
    """Reads exactly Content-Length bytes from the socket, tracking consumption."""

    def __init__(self, rfile, length):
        self.rfile, self.remaining = rfile, length

    def read(self, n):
        n = min(n, self.remaining)
        if n <= 0:
            return b""
        data = self.rfile.read(n)
        if not data:
            raise HttpError(400, "body ended early")
        self.remaining -= len(data)
        return data


def iter_parts(body, boundary):
    """Streaming multipart parser. Yields (headers, chunk_iterator) per part; each
    chunk_iterator must be fully consumed before the next part is requested."""
    delim = b"\r\n--" + boundary
    buf = bytearray()

    def fill(min_len):
        while len(buf) < min_len:
            d = body.read(CHUNK)
            if not d:
                return False
            buf.extend(d)
        return True

    # Preamble up to the first boundary line.
    first = b"--" + boundary
    if not fill(len(first) + 2) or not buf.startswith(first):
        raise HttpError(400, "malformed multipart preamble")
    del buf[:len(first)]
    while True:
        if not fill(2):
            raise HttpError(400, "truncated multipart")
        if buf[:2] == b"--":
            return  # closing boundary
        if buf[:2] != b"\r\n":
            raise HttpError(400, "malformed boundary line")
        del buf[:2]
        # Headers
        while b"\r\n\r\n" not in buf:
            if len(buf) > 8192 or not fill(len(buf) + 1):
                raise HttpError(400, "malformed part headers")
        raw, _, rest = bytes(buf).partition(b"\r\n\r\n")
        buf[:] = rest
        headers = {}
        for line in raw.decode("utf-8", "replace").split("\r\n"):
            k, sep, v = line.partition(":")
            if not sep:
                raise HttpError(400, "malformed part header")
            headers[k.strip().lower()] = v.strip()
        done = [False]

        def chunks():
            while True:
                idx = buf.find(delim)
                if idx >= 0:
                    if idx:
                        yield bytes(buf[:idx])
                    del buf[:idx + len(delim)]
                    done[0] = True
                    return
                keep = len(delim) - 1
                if len(buf) > keep:
                    out = bytes(buf[:-keep])
                    del buf[:-keep]
                    yield out
                d = body.read(CHUNK)
                if not d:
                    raise HttpError(400, "truncated part")
                buf.extend(d)

        it = chunks()
        yield headers, it
        for _ in it:  # drain if the consumer stopped early
            pass
        if not done[0]:
            raise HttpError(400, "unterminated part")


def disposition(headers):
    cd = headers.get("content-disposition", "")
    if not cd.startswith("form-data"):
        raise HttpError(400, "part without form-data disposition")
    name = re.search(r'\bname="([^"]*)"', cd)
    fname = re.search(r'\bfilename="([^"]*)"', cd)
    return (name.group(1) if name else None), (fname.group(1) if fname else None)


class Store:
    def __init__(self, root):
        self.root = root
        self.captures = os.path.join(root, "captures")
        self.staging = os.path.join(root, "staging")
        os.makedirs(self.captures, exist_ok=True)
        os.makedirs(self.staging, exist_ok=True)
        # Orphaned staging dirs from interrupted requests are never visible; clean at start.
        for d in os.listdir(self.staging):
            shutil.rmtree(os.path.join(self.staging, d), ignore_errors=True)
        self.lock = threading.Lock()
        self.id_locks = {}

    def id_lock(self, cid):
        with self.lock:
            return self.id_locks.setdefault(cid, threading.Lock())

    def next_receipt(self):
        with self.lock:
            p = os.path.join(self.root, "receipt.counter")
            n = int(open(p).read().strip()) + 1 if os.path.exists(p) else 1
            tmp = p + ".tmp"
            with open(tmp, "w") as f:
                f.write(str(n))
                f.flush()
                os.fsync(f.fileno())
            os.replace(tmp, p)
            return "srv-%06d" % n

    def existing_receipt(self, cid):
        p = os.path.join(self.captures, cid, "receipt.json")
        if not os.path.exists(p):
            return None
        with open(p) as f:
            return json.load(f)


class Handler(BaseHTTPRequestHandler):
    server_version = "mpc-receiver/1"
    protocol_version = "HTTP/1.1"
    timeout = 120  # bound stalled clients; staging is discarded on timeout

    def log_message(self, fmt, *args):  # never log headers (tokens) or bodies
        sys.stderr.write("%s %s\n" % (self.address_string(), fmt % args))

    def reply(self, status, obj):
        data = json.dumps(obj).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def authorized(self):
        token = self.server.token
        if not token:
            return True
        got = self.headers.get("Authorization", "")
        return got.startswith("Bearer ") and hmac.compare_digest(got[7:].encode(), token.encode())

    def do_GET(self):
        if self.path != "/api/v1/health":
            return self.reply(404, {"error": "not found"})
        if not self.authorized():
            return self.reply(401, {"error": "unauthorized"})
        self.reply(200, {"status": "ok", "protocol_version": PROTOCOL_VERSION})

    def do_POST(self):
        if self.path != "/api/v1/captures":
            self.close_connection = True
            return self.reply(404, {"error": "not found"})
        if not self.authorized():
            self.close_connection = True
            return self.reply(401, {"error": "unauthorized"})
        staging = None
        try:
            length = self.headers.get("Content-Length")
            if length is None or not length.isdigit():
                raise HttpError(411, "Content-Length required")
            length = int(length)
            if length > self.server.max_bytes:
                raise HttpError(413, "body exceeds receiver limit of %d bytes" % self.server.max_bytes)
            cid = self.headers.get("Idempotency-Key", "")
            if not UUID_RE.match(cid):
                raise HttpError(400, "Idempotency-Key must be a lowercase UUID capture_id")
            ctype = self.headers.get("Content-Type", "")
            m = re.match(r'^multipart/form-data;\s*boundary="?([A-Za-z0-9\'()+_,./:=?-]{1,70})"?$', ctype)
            if not m:
                raise HttpError(400, "multipart/form-data with boundary required")
            body = BodyReader(self.rfile, length)
            staging = tempfile.mkdtemp(prefix=cid + ".", dir=self.server.store.staging)
            status, receipt = self.ingest(cid, body, m.group(1).encode(), staging)
            staging = None  # promoted or discarded inside ingest
            if self.server.drop_response_once.is_set() and status == 201:
                self.server.drop_response_once.clear()
                self.close_connection = True
                self.connection.shutdown(2)  # simulate a lost response after commit
                return
            self.reply(status, receipt)
        except HttpError as e:
            self.close_connection = True
            try:
                self.reply(e.status, {"error": e.msg})
            except (OSError, ssl.SSLError):
                pass  # client already gone (interrupted upload)
        except (OSError, ssl.SSLError):
            self.close_connection = True
        finally:
            if staging:
                shutil.rmtree(staging, ignore_errors=True)

    def ingest(self, cid, body, boundary, staging):
        manifest = None
        hashes, sizes = {}, {}
        seen = set()
        files = {"capture": os.path.join(staging, "capture.pcapng"),
                 "metadata": os.path.join(staging, "metadata.json")}
        for headers, chunks in iter_parts(body, boundary):
            name, fname = disposition(headers)
            if name in seen:
                raise HttpError(400, "duplicate part %r" % name)
            seen.add(name)
            if name == "manifest":
                data = bytearray()
                for c in chunks:
                    data += c
                    if len(data) > MAX_SMALL_PART:
                        raise HttpError(400, "manifest too large")
                try:
                    manifest = json.loads(bytes(data))
                except ValueError:
                    raise HttpError(400, "manifest is not JSON")
            elif name in files:
                if manifest is None:
                    raise HttpError(400, "manifest must precede file parts")
                expected = "%s.pcapng" % cid if name == "capture" else "%s.meta.json" % cid
                if fname != expected:  # never used as a path; must equal the canonical name
                    raise HttpError(400, "unexpected filename for %s" % name)
                limit = MAX_METADATA if name == "metadata" else self.server.max_bytes
                h, n = hashlib.sha256(), 0
                with open(files[name], "wb") as f:
                    for c in chunks:
                        n += len(c)
                        if n > limit:
                            raise HttpError(413, "%s part too large" % name)
                        h.update(c)
                        f.write(c)
                    f.flush()
                    os.fsync(f.fileno())
                hashes[name], sizes[name] = h.hexdigest(), n
            else:
                raise HttpError(400, "unexpected part %r" % name)
        if body.remaining:
            raise HttpError(400, "trailing data after multipart body")
        if seen != {"manifest", "capture", "metadata"}:
            raise HttpError(400, "missing part(s): %s" % sorted({"manifest", "capture", "metadata"} - seen))
        self.validate(cid, manifest, hashes, sizes, files)

        with self.server.store.id_lock(cid):
            prior = self.server.store.existing_receipt(cid)
            if prior is not None:
                shutil.rmtree(staging, ignore_errors=True)
                if prior["sha256"] == {"capture": hashes["capture"], "metadata": hashes["metadata"]}:
                    return 200, prior
                raise HttpError(409, "capture_id already stored with different content")
            receipt = {"protocol_version": PROTOCOL_VERSION, "capture_id": cid,
                       "receipt_id": self.server.store.next_receipt(), "stored": True,
                       "sha256": {"capture": hashes["capture"], "metadata": hashes["metadata"]},
                       "size_bytes": {"capture": sizes["capture"], "metadata": sizes["metadata"]}}
            os.rename(files["capture"], os.path.join(staging, "%s.pcapng" % cid))
            os.rename(files["metadata"], os.path.join(staging, "%s.meta.json" % cid))
            with open(os.path.join(staging, "receipt.json"), "w") as f:
                json.dump(receipt, f)
                f.flush()
                os.fsync(f.fileno())
            # Atomic promotion: the dataset becomes visible all at once.
            os.rename(staging, os.path.join(self.server.store.captures, cid))
            return 201, receipt

    @staticmethod
    def validate(cid, manifest, hashes, sizes, files):
        if not isinstance(manifest, dict) or manifest.get("protocol_version") != PROTOCOL_VERSION:
            raise HttpError(422, "manifest protocol_version must be 1")
        if manifest.get("capture_id") != cid:
            raise HttpError(422, "manifest capture_id does not match Idempotency-Key")
        mf = manifest.get("files") or {}
        for part, fname in (("capture", "%s.pcapng" % cid), ("metadata", "%s.meta.json" % cid)):
            e = mf.get(part) or {}
            if e.get("filename") != fname:
                raise HttpError(422, "manifest filename mismatch for %s" % part)
            if not isinstance(e.get("sha256"), str) or not HEX64_RE.match(e["sha256"]):
                raise HttpError(422, "manifest sha256 for %s is not 64 lowercase hex" % part)
            if e.get("size_bytes") != sizes[part]:
                raise HttpError(422, "size mismatch for %s" % part)
            if e["sha256"] != hashes[part]:
                raise HttpError(422, "sha256 mismatch for %s" % part)
        try:
            with open(files["metadata"]) as f:
                meta = json.load(f)
        except ValueError:
            raise HttpError(422, "metadata is not JSON")
        if meta.get("capture_id") != cid or meta.get("capture_file") != "%s.pcapng" % cid:
            raise HttpError(422, "metadata capture identity mismatch")
        if meta.get("status") != "complete":
            raise HttpError(422, "metadata status must be complete")
        with open(files["capture"], "rb") as f:
            head = f.read(12)
        if len(head) < 12 or head[:4] != b"\x0a\x0d\x0d\x0a" or head[8:12] not in (b"\x4d\x3c\x2b\x1a", b"\x1a\x2b\x3c\x4d"):
            raise HttpError(422, "capture is not a PCAPNG section")


def make_server(host, port, cert, key, data, token, max_bytes):
    srv = ThreadingHTTPServer((host, port), Handler)
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.load_cert_chain(cert, key)
    srv.socket = ctx.wrap_socket(srv.socket, server_side=True)
    srv.store = Store(data)
    srv.token = token
    srv.max_bytes = max_bytes
    srv.drop_response_once = threading.Event()
    srv.daemon_threads = True
    return srv


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--host", default="0.0.0.0")
    ap.add_argument("--port", type=int, default=8443)
    ap.add_argument("--cert", required=True)
    ap.add_argument("--key", required=True)
    ap.add_argument("--data", default="data")
    ap.add_argument("--token-file", help="file containing the bearer token (omit = no auth)")
    ap.add_argument("--max-bytes", type=int, default=4 * 1024 ** 3)
    ap.add_argument("--drop-response-once", action="store_true")
    a = ap.parse_args()
    token = open(a.token_file).read().strip() if a.token_file else None
    srv = make_server(a.host, a.port, a.cert, a.key, a.data, token, a.max_bytes)
    if a.drop_response_once:
        srv.drop_response_once.set()
    sys.stderr.write("receiver on https://%s:%d (auth %s)\n" % (a.host, a.port, "on" if token else "off"))
    srv.serve_forever()


if __name__ == "__main__":
    main()
