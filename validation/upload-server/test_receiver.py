#!/usr/bin/env python3
"""Receiver protocol tests (UPLOAD_PROTOCOL.md 'Minimum receiver tests').
Run: python3 -I validation/upload-server/test_receiver.py  (needs certs from make_certs.sh)"""
import hashlib
import http.client
import json
import os
import resource
import shutil
import socket
import ssl
import sys
import tempfile
import threading
import unittest
import uuid

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import receiver  # noqa: E402

CERTS = os.path.join(HERE, "certs")
TOKEN = "test-token-" + uuid.uuid4().hex


def pcapng_bytes(n_extra=0):
    # Minimal SHB (28 bytes, no options) + filler EPB-like padding as an opaque body.
    shb = (b"\x0a\x0d\x0d\x0a" + (28).to_bytes(4, "little") + b"\x4d\x3c\x2b\x1a" + b"\x01\x00\x00\x00"
           + b"\xff" * 8 + (28).to_bytes(4, "little"))
    return shb + os.urandom(n_extra)


def sidecar(cid, status="complete", capture_file=None):
    return json.dumps({"schema_version": 1, "capture_id": cid, "status": status,
                       "capture_file": capture_file or "%s.pcapng" % cid}).encode()


class Server:
    def __init__(self, cert="server", max_bytes=64 * 1024 * 1024):
        self.data = tempfile.mkdtemp(prefix="recv-")
        self.srv = receiver.make_server("127.0.0.1", 0, os.path.join(CERTS, cert + ".pem"),
                                        os.path.join(CERTS, cert + ".key"), self.data, TOKEN, max_bytes)
        self.port = self.srv.server_address[1]
        self.t = threading.Thread(target=self.srv.serve_forever, daemon=True)
        self.t.start()

    def close(self):
        self.srv.shutdown()
        self.srv.server_close()
        shutil.rmtree(self.data, ignore_errors=True)

    def datasets(self):
        return sorted(os.listdir(os.path.join(self.data, "captures")))

    def staging(self):
        return os.listdir(os.path.join(self.data, "staging"))


def client_ctx():
    ctx = ssl.create_default_context(cafile=os.path.join(CERTS, "ca.pem"))
    return ctx


def multipart(cid, cap, meta, manifest=None, boundary="mpcBOUNDARY123", parts=None, fnames=None):
    if manifest is None:
        manifest = {"protocol_version": 1, "capture_id": cid, "files": {
            "capture": {"filename": "%s.pcapng" % cid, "size_bytes": len(cap), "sha256": hashlib.sha256(cap).hexdigest()},
            "metadata": {"filename": "%s.meta.json" % cid, "size_bytes": len(meta), "sha256": hashlib.sha256(meta).hexdigest()}}}
    fnames = fnames or {"capture": "%s.pcapng" % cid, "metadata": "%s.meta.json" % cid}
    order = parts or [("manifest", None, json.dumps(manifest).encode()),
                      ("capture", fnames["capture"], cap), ("metadata", fnames["metadata"], meta)]
    out = b""
    for name, fname, data in order:
        disp = 'form-data; name="%s"' % name + ('; filename="%s"' % fname if fname else "")
        out += b"--" + boundary.encode() + b"\r\nContent-Disposition: " + disp.encode() + b"\r\nContent-Type: application/octet-stream\r\n\r\n" + data + b"\r\n"
    return out + b"--" + boundary.encode() + b"--\r\n", boundary


def post(port, cid, body, boundary, token=TOKEN):
    c = http.client.HTTPSConnection("127.0.0.1", port, context=client_ctx(), timeout=30)
    h = {"Content-Type": "multipart/form-data; boundary=" + boundary, "Idempotency-Key": cid,
         "Content-Length": str(len(body))}
    if token:
        h["Authorization"] = "Bearer " + token
    try:
        c.request("POST", "/api/v1/captures", body=body, headers=h)
        r = c.getresponse()
        return r.status, json.loads(r.read() or b"{}")
    finally:
        c.close()


class ReceiverTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if not os.path.exists(os.path.join(CERTS, "server.key")):
            raise unittest.SkipTest("run make_certs.sh first")

    def setUp(self):
        self.s = Server()

    def tearDown(self):
        self.s.close()

    def upload_ok(self, cid=None, cap=None):
        cid = cid or str(uuid.uuid4())
        cap = cap or pcapng_bytes(5000)
        meta = sidecar(cid)
        body, b = multipart(cid, cap, meta)
        return cid, cap, meta, post(self.s.port, cid, body, b)

    def test_health_auth(self):
        c = http.client.HTTPSConnection("127.0.0.1", self.s.port, context=client_ctx())
        c.request("GET", "/api/v1/health", headers={"Authorization": "Bearer " + TOKEN})
        r = c.getresponse()
        self.assertEqual(r.status, 200)
        self.assertEqual(json.loads(r.read()), {"status": "ok", "protocol_version": 1})
        for hdr in ({}, {"Authorization": "Bearer wrong"}, {"Authorization": TOKEN}):
            c.request("GET", "/api/v1/health", headers=hdr)
            r = c.getresponse()
            r.read()
            self.assertEqual(r.status, 401)

    def test_valid_upload_byte_exact_and_receipt(self):
        cid, cap, meta, (st, rc) = self.upload_ok()
        self.assertEqual(st, 201)
        self.assertEqual(rc["capture_id"], cid)
        self.assertTrue(rc["stored"])
        self.assertEqual(rc["sha256"]["capture"], hashlib.sha256(cap).hexdigest())
        self.assertEqual(rc["sha256"]["metadata"], hashlib.sha256(meta).hexdigest())
        d = os.path.join(self.s.data, "captures", cid)
        self.assertEqual(open(os.path.join(d, cid + ".pcapng"), "rb").read(), cap)
        self.assertEqual(open(os.path.join(d, cid + ".meta.json"), "rb").read(), meta)
        self.assertEqual(self.s.staging(), [])

    def test_identical_retry_is_idempotent(self):
        cid, cap, meta, (st, rc) = self.upload_ok()
        body, b = multipart(cid, cap, meta)
        st2, rc2 = post(self.s.port, cid, body, b)
        self.assertEqual((st, st2), (201, 200))
        self.assertEqual(rc, rc2)
        self.assertEqual(self.s.datasets(), [cid])

    def test_conflicting_same_id_409(self):
        cid, cap, meta, (st, _) = self.upload_ok()
        cap2 = pcapng_bytes(10)
        body, b = multipart(cid, cap2, meta)
        st2, rc2 = post(self.s.port, cid, body, b)
        self.assertEqual(st2, 409)
        d = os.path.join(self.s.data, "captures", cid)
        self.assertEqual(open(os.path.join(d, cid + ".pcapng"), "rb").read(), cap)  # not overwritten

    def test_bad_hash_and_identity_422(self):
        cid = str(uuid.uuid4())
        cap, meta = pcapng_bytes(100), sidecar(cid)
        man = {"protocol_version": 1, "capture_id": cid, "files": {
            "capture": {"filename": cid + ".pcapng", "size_bytes": len(cap), "sha256": "0" * 64},
            "metadata": {"filename": cid + ".meta.json", "size_bytes": len(meta), "sha256": hashlib.sha256(meta).hexdigest()}}}
        body, b = multipart(cid, cap, meta, manifest=man)
        self.assertEqual(post(self.s.port, cid, body, b)[0], 422)
        for bad_meta in (sidecar(str(uuid.uuid4())), sidecar(cid, status="recording"),
                         sidecar(cid, capture_file="other.pcapng"), b"not json"):
            body, b = multipart(cid, cap, bad_meta)
            self.assertEqual(post(self.s.port, cid, body, b)[0], 422, bad_meta)
        body, b = multipart(cid, b"not a pcapng file at all", meta)
        self.assertEqual(post(self.s.port, cid, body, b)[0], 422)
        self.assertEqual(self.s.datasets(), [])
        self.assertEqual(self.s.staging(), [])

    def test_missing_duplicate_unexpected_parts_400(self):
        cid = str(uuid.uuid4())
        cap, meta = pcapng_bytes(10), sidecar(cid)
        man = json.dumps({"protocol_version": 1, "capture_id": cid}).encode()
        for parts in ([("manifest", None, man), ("capture", cid + ".pcapng", cap)],
                      [("manifest", None, man), ("capture", cid + ".pcapng", cap), ("capture", cid + ".pcapng", cap)],
                      [("manifest", None, man), ("evil", None, b"x")],
                      [("capture", cid + ".pcapng", cap), ("manifest", None, man)]):
            body, b = multipart(cid, cap, meta, parts=parts)
            self.assertEqual(post(self.s.port, cid, body, b)[0], 400, [p[0] for p in parts])
        self.assertEqual(self.s.datasets(), [])

    def test_path_traversal_and_bad_ids(self):
        cid = str(uuid.uuid4())
        cap, meta = pcapng_bytes(10), sidecar(cid)
        body, b = multipart(cid, cap, meta, fnames={"capture": "../../etc/passwd", "metadata": cid + ".meta.json"})
        self.assertEqual(post(self.s.port, cid, body, b)[0], 400)
        body, b = multipart("../x", cap, meta)
        self.assertEqual(post(self.s.port, "../x", body, b)[0], 400)
        self.assertEqual(self.s.datasets(), [])

    def test_unauthorized_upload(self):
        cid = str(uuid.uuid4())
        body, b = multipart(cid, pcapng_bytes(10), sidecar(cid))
        self.assertEqual(post(self.s.port, cid, body, b, token=None)[0], 401)
        self.assertEqual(post(self.s.port, cid, body, b, token="wrong")[0], 401)

    def test_oversize_413(self):
        self.s.close()
        self.s = Server(max_bytes=2000)
        cid = str(uuid.uuid4())
        body, b = multipart(cid, pcapng_bytes(5000), sidecar(cid))
        try:
            st = post(self.s.port, cid, body, b)[0]
        except (BrokenPipeError, ConnectionResetError):
            st = "reset"  # server may close before the body is fully sent
        self.assertIn(st, (413, "reset"))
        self.assertEqual(self.s.datasets(), [])

    def test_interrupted_body_no_orphan_then_retry(self):
        cid = str(uuid.uuid4())
        cap, meta = pcapng_bytes(200000), sidecar(cid)
        body, b = multipart(cid, cap, meta)
        raw = socket.create_connection(("127.0.0.1", self.s.port))
        tls = client_ctx().wrap_socket(raw, server_hostname="127.0.0.1")
        hdr = ("POST /api/v1/captures HTTP/1.1\r\nHost: x\r\nAuthorization: Bearer %s\r\n"
               "Content-Type: multipart/form-data; boundary=%s\r\nIdempotency-Key: %s\r\nContent-Length: %d\r\n\r\n"
               % (TOKEN, b, cid, len(body))).encode()
        tls.sendall(hdr + body[: len(body) // 2])
        tls.close()
        import time
        time.sleep(0.5)  # let the handler observe the disconnect
        for _ in range(100):
            if not self.s.staging():
                break
            time.sleep(0.05)
        self.assertEqual(self.s.datasets(), [])
        self.assertEqual(self.s.staging(), [])
        self.assertEqual(post(self.s.port, cid, body, b)[0], 201)

    def test_lost_response_then_replay(self):
        self.s.srv.drop_response_once.set()
        cid = str(uuid.uuid4())
        cap, meta = pcapng_bytes(1000), sidecar(cid)
        body, b = multipart(cid, cap, meta)
        with self.assertRaises((http.client.RemoteDisconnected, ConnectionResetError, ssl.SSLError)):
            post(self.s.port, cid, body, b)
        st, rc = post(self.s.port, cid, body, b)  # client retry with the same capture ID
        self.assertEqual(st, 200)
        self.assertEqual(rc["receipt_id"], "srv-000001")
        self.assertEqual(self.s.datasets(), [cid])

    def test_streaming_large_bounded_memory(self):
        cid = str(uuid.uuid4())
        size = 48 * 1024 * 1024
        cap = pcapng_bytes(size)
        meta = sidecar(cid)
        body, b = multipart(cid, cap, meta)
        before = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
        st, rc = post(self.s.port, cid, body, b)
        self.assertEqual(st, 201)
        self.assertEqual(rc["size_bytes"]["capture"], len(cap))
        # The test process itself holds `body` (~96 MB with cap); the server must not add a full copy.
        grown_kb = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss - before
        self.assertLess(grown_kb, 40 * 1024, "server buffered the upload in memory (%d KB)" % grown_kb)


class TlsTests(unittest.TestCase):
    def check_rejected(self, cert, hostname="127.0.0.1"):
        s = Server(cert=cert)
        try:
            c = http.client.HTTPSConnection(hostname, s.port, context=client_ctx(), timeout=5)
            with self.assertRaises(ssl.SSLError):
                c.request("GET", "/api/v1/health")
                c.getresponse()
        finally:
            s.close()

    def test_untrusted_certificate_rejected(self):
        self.check_rejected("untrusted")

    def test_hostname_mismatch_rejected(self):
        self.check_rejected("wronghost")


if __name__ == "__main__":
    unittest.main(verbosity=2)
