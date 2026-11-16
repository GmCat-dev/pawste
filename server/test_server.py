#!/usr/bin/env python3
"""API tests for the Pawste service: starts a throwaway server on a free port. Run: python3 test_server.py"""
import json
import os
import socket
import subprocess
import sys
import tempfile
import time
import unittest
import urllib.error
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
ADMIN = "test-admin-key"


def free_port():
    s = socket.socket(); s.bind(("127.0.0.1", 0)); p = s.getsockname()[1]; s.close(); return p


class PawsteTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.mkdtemp()
        cls.port = free_port()
        import hashlib
        env = dict(os.environ, PAWSTE_DATA=cls.tmp, PAWSTE_PORT=str(cls.port), PAWSTE_ADMIN_KEY_SHA256=hashlib.sha256(ADMIN.encode()).hexdigest())
        cls.proc = subprocess.Popen([sys.executable, os.path.join(HERE, "server.py")], env=env, stdout=subprocess.DEVNULL)
        for _ in range(50):
            try:
                urllib.request.urlopen("http://127.0.0.1:%d/api/pawste/health" % cls.port); break
            except OSError:
                time.sleep(0.1)

    @classmethod
    def tearDownClass(cls):
        cls.proc.terminate(); cls.proc.wait()

    def call(self, method, path, body=None, headers=None, ip="10.0.0.1", raw=None):
        data = raw if raw is not None else (json.dumps(body).encode() if body is not None else None)
        h = {"Content-Type": "application/json", "X-Real-IP": ip}
        h.update(headers or {})
        req = urllib.request.Request("http://127.0.0.1:%d/api/pawste%s" % (self.port, path), data=data, method=method, headers=h)
        try:
            with urllib.request.urlopen(req) as r:
                return r.status, json.loads(r.read())
        except urllib.error.HTTPError as e:
            return e.code, json.loads(e.read() or b"{}")

    def make(self, **kw):
        body = {"hdr": json.dumps({"v": 1, "iv": "AAAAAAAAAAAAAAAA"}), "ct": "QUJD", "ttl": 3600, "burn": False, "pw": False}
        body.update(kw)
        return self.call("POST", "", body, ip=kw.pop("_ip", "10.0.0.1") if "_ip" in kw else "10.0.0.1")

    def test_create_open_edit_delete(self):
        s, d = self.make()
        self.assertEqual(s, 201)
        pid, tok = d["id"], d["edit_token"]
        s, f = self.call("GET", "/" + pid)
        self.assertEqual((s, f["versions"], f["burn"]), (200, 1, False))
        s, o = self.call("POST", "/" + pid + "/open")
        self.assertEqual((s, o["ct"], o["n"]), (200, "QUJD", 1))
        s, _ = self.call("PUT", "/" + pid, {"hdr": json.dumps({"v": 1, "iv": "B"}), "ct": "WFla"}, {"X-Edit-Token": "wrong-token-here"})
        self.assertEqual(s, 403)
        s, e = self.call("PUT", "/" + pid, {"hdr": json.dumps({"v": 1, "iv": "B"}), "ct": "WFla"}, {"X-Edit-Token": tok})
        self.assertEqual((s, e["version"], e["versions"]), (200, 2, 2))
        s, o = self.call("POST", "/" + pid + "/open?v=1")
        self.assertEqual((o["ct"], [x["n"] for x in o["list"]]), ("QUJD", [1, 2]))
        s, o = self.call("POST", "/" + pid + "/open")
        self.assertEqual(o["ct"], "WFla")
        self.assertEqual(self.call("DELETE", "/" + pid, headers={"X-Edit-Token": "nope-nope-nope"})[0], 403)
        self.assertEqual(self.call("DELETE", "/" + pid, headers={"X-Edit-Token": tok})[0], 200)
        self.assertEqual(self.call("GET", "/" + pid)[0], 404)

    def test_burn(self):
        s, d = self.make(burn=True)
        pid = d["id"]
        self.assertEqual(self.call("GET", "/" + pid)[1]["burn"], True)
        self.assertEqual(self.call("GET", "/" + pid)[0], 200)   # facts never consume
        s, o = self.call("POST", "/" + pid + "/open")
        self.assertTrue(o["burned"])
        self.assertEqual(self.call("POST", "/" + pid + "/open")[0], 404)
        s, d = self.make(burn=True)
        s, _ = self.call("PUT", "/" + d["id"], {"hdr": json.dumps({"v": 1, "iv": "B"}), "ct": "WFla"}, {"X-Edit-Token": d["edit_token"]})
        self.assertEqual(s, 400)

    def test_validation(self):
        self.assertEqual(self.make(ttl=999)[0], 400)
        self.assertEqual(self.make(ct="not base64 !!")[0], 400)
        self.assertEqual(self.make(hdr="{}")[0], 400)
        self.assertEqual(self.make(ct="A" * 720_001)[0], 400)
        self.assertEqual(self.call("POST", "", raw=b"x" * 800_000)[0], 413)
        self.assertEqual(self.call("GET", "/../../etc")[0], 404)
        self.assertEqual(self.call("GET", "/ABCDEFGHJK")[0], 404)
        s, _ = self.call("POST", "", {"hdr": "{}", "ct": "QQ"}, {"Origin": "https://evil.example"})
        self.assertEqual(s, 403)

    def test_reports_hide_and_admin(self):
        s, d = self.make()
        pid = d["id"]
        for i, ip in enumerate(["1.1.1.1", "1.1.1.1", "2.2.2.2"]):
            self.assertEqual(self.call("POST", "/%s/report" % pid, {"reason": "spam", "link": "https://evil.example/x"}, ip=ip)[0], 200)
        self.assertEqual(self.call("GET", "/" + pid)[0], 200)   # only 2 different people so far
        self.call("POST", "/%s/report" % pid, {"reason": "abuse", "details": "mean"}, ip="3.3.3.3")
        self.assertEqual(self.call("GET", "/" + pid)[0], 451)
        self.assertEqual(self.call("POST", "/%s/open" % pid)[0], 451)
        self.assertEqual(self.call("GET", "/admin/overview")[0], 403)
        s, ov = self.call("GET", "/admin/overview", headers={"X-Admin-Key": ADMIN})
        self.assertEqual(s, 200)
        mine = [r for r in ov["reports"] if r["paste_id"] == pid]
        self.assertEqual((len(mine), mine[0]["reporters"], mine[0]["link"]), (3, 3, ""))
        self.assertEqual(self.call("POST", "/admin/restore", {"id": pid}, {"X-Admin-Key": ADMIN})[0], 200)
        self.assertEqual(self.call("GET", "/" + pid)[0], 200)
        self.assertEqual(self.call("POST", "/admin/delete", {"id": pid}, {"X-Admin-Key": ADMIN})[0], 200)
        self.assertEqual(self.call("GET", "/" + pid)[0], 404)
        self.assertEqual(self.call("POST", "/%s/report" % pid, {"reason": "spam"})[0], 404)

    def test_rate_limit(self):
        codes = [self.call("POST", "", {"hdr": json.dumps({"v": 1, "iv": "A"}), "ct": "QQ", "ttl": 600}, ip="9.9.9.9")[0] for _ in range(31)]
        self.assertEqual(codes.count(201), 30)
        self.assertEqual(codes[-1], 429)

    def test_kinds(self):
        s, d = self.make(hdr=json.dumps({"v": 1, "k": "none", "z": 1}))
        self.assertEqual((s, d["kind"], len(d["id"])), (201, "none", 8))
        s, f = self.call("GET", "/" + d["id"])
        self.assertEqual(f["kind"], "none")
        s, d2 = self.make(hdr=json.dumps({"v": 1, "k": "pw", "iv": "AAAA", "salt": "BBBB", "it": 600000}))
        self.assertEqual((s, d2["kind"], len(d2["id"])), (201, "pw", 8))
        self.assertTrue(self.call("GET", "/" + d2["id"])[1]["pw"])
        s, d3 = self.make()
        self.assertEqual((d3["kind"], len(d3["id"])), ("e2e", 10))
        self.assertEqual(self.make(hdr=json.dumps({"v": 1, "k": "pw", "iv": "AAAA"}))[0], 400)    # pw needs a salt
        self.assertEqual(self.make(hdr=json.dumps({"v": 1, "k": "weird"}))[0], 400)
        self.assertEqual(self.make(hdr=json.dumps({"v": 1}))[0], 400)                              # e2e needs an iv
        # a new version must keep the same kind
        s, _ = self.call("PUT", "/" + d["id"], {"hdr": json.dumps({"v": 1, "iv": "B"}), "ct": "WFla"}, {"X-Edit-Token": d["edit_token"]})
        self.assertEqual(s, 400)
        s, e = self.call("PUT", "/" + d["id"], {"hdr": json.dumps({"v": 1, "k": "none"}), "ct": "WFla"}, {"X-Edit-Token": d["edit_token"]})
        self.assertEqual((s, e["version"]), (200, 2))
        # short-link report keeps a paw.gmcat.io link without a key
        self.call("POST", "/%s/report" % d["id"], {"reason": "spam", "link": "https://paw.gmcat.io/" + d["id"]}, ip="7.7.7.7")
        ov = self.call("GET", "/admin/overview", headers={"X-Admin-Key": ADMIN})[1]
        r = [x for x in ov["reports"] if x["paste_id"] == d["id"]][0]
        self.assertEqual((r["link"], r["kind"]), ("https://paw.gmcat.io/" + d["id"], "none"))

    def text_call(self, method, path, body=b"", headers=None, ip="20.0.0.1"):
        h = {"X-Real-IP": ip, "Content-Type": "text/plain; charset=utf-8"}
        h.update(headers or {})
        req = urllib.request.Request("http://127.0.0.1:%d/api/pawste%s" % (self.port, path), data=body if method == "POST" else None, method=method, headers=h)
        try:
            with urllib.request.urlopen(req) as r:
                return r.status, r.read().decode(), dict(r.headers)
        except urllib.error.HTTPError as e:
            return e.code, e.read().decode(), dict(e.headers)

    def test_command_line_and_raw(self):
        text = "GM, Cat Crew! ☕\nline two"
        s, body, h = self.text_call("POST", "/plain?ttl=1d&title=Notes&lang=python", text.encode())
        self.assertEqual(s, 201)
        link = body.strip()
        self.assertRegex(link, r"^https://paw\.gmcat\.io/[a-z0-9]{8}$")
        self.assertIn("#e=", h["X-Pawste-Edit"])
        pid = link.rsplit("/", 1)[1]
        s, f = self.call("GET", "/" + pid)
        self.assertEqual((f["kind"], f["burn"]), ("none", False))
        s, raw, rh = self.text_call("GET", "/%s/raw" % pid)
        self.assertEqual((s, raw), (200, text))
        self.assertIn("sandbox", rh["Content-Security-Policy"])
        self.assertTrue(rh["Content-Type"].startswith("text/plain"))
        # the browser can read the same paste (kind none: base64 JSON)
        s, o = self.call("POST", "/" + pid + "/open")
        import base64 as b64
        self.assertEqual(json.loads(b64.b64decode(o["ct"]))["t"], "Notes")
        # edit token from the header deletes it
        tok = h["X-Pawste-Edit"].split("#e=")[1]
        self.assertEqual(self.call("DELETE", "/" + pid, headers={"X-Edit-Token": tok})[0], 200)
        self.assertEqual(self.text_call("GET", "/%s/raw" % pid)[0], 404)

    def test_command_line_guards(self):
        s, body, _ = self.text_call("POST", "/plain", b"password = hunter2secret", ip="21.0.0.1")
        self.assertEqual(s, 422)
        self.assertIn("Leak Guard", body)
        fake_aws = ("AK" + "IA" + "ABCDEFGHIJKLMNOP").encode()   # built at runtime so key scanners stay quiet
        self.assertEqual(self.text_call("POST", "/plain", b"key " + fake_aws, ip="21.0.0.1")[0], 422)
        self.assertEqual(self.text_call("POST", "/plain", b"card 4111 1111 1111 1111", ip="21.0.0.1")[0], 422)
        self.assertEqual(self.text_call("POST", "/plain?force=1", b"password = hunter2secret", ip="21.0.0.1")[0], 201)
        self.assertEqual(self.text_call("POST", "/plain?ttl=5y", b"hi", ip="21.0.0.1")[0], 400)
        self.assertEqual(self.text_call("POST", "/plain", b"   ", ip="21.0.0.1")[0], 400)
        self.assertEqual(self.text_call("POST", "/plain", b"\xff\xfe\x00binary", ip="21.0.0.1")[0], 400)
        s, body, _ = self.text_call("POST", "/plain?burn=1", b"one time", headers={"Accept": "application/json"}, ip="21.0.0.1")
        d = json.loads(body)
        self.assertEqual((s, d["burn"], d["raw"]), (201, True, None))
        self.assertEqual(self.text_call("GET", "/%s/raw" % d["id"])[0], 403)          # burn: browser only
        s, e2 = self.make()
        self.assertEqual(self.text_call("GET", "/%s/raw" % e2["id"])[0], 403)   # private: locked

    def test_old_database_gets_kind(self):
        import sqlite3
        with sqlite3.connect(os.path.join(self.tmp, "pawste.db")) as con:
            cols = [r[1] for r in con.execute("PRAGMA table_info(pastes)")]
        self.assertIn("kind", cols)


if __name__ == "__main__":
    unittest.main(verbosity=1)
