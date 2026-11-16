#!/usr/bin/env python3
"""GmCat Pawste: the private paste bin at tools.gmcat.io/pawste/ (links look like tools.gmcat.io/p/<id>#<key>).

Private pastes (kind "e2e", the default) are locked (AES-256-GCM) in the sender's browser before they are sent. The key
travels only in the part of the link after "#", which browsers never send to a server, so this service stores
scrambled bytes it cannot read. Short-link pastes are either locked with a password only (kind "pw": still unreadable
here) or not encrypted at all (kind "none": the sender chose a short link and was told GmCat can read it).
Private pastes get 10-character ids, short-link pastes 8 (paw.gmcat.io/<id>).
A small standard-library service behind Nginx on 127.0.0.1:4198 (same pattern as GmCat Drop).

  POST   /api/pawste                         new paste {hdr, ct, ttl, burn, pw} -> {id, edit_token, expires}
  GET    /api/pawste/<id>                    public facts: burn, pw, expires, versions, created, updated (never consumes)
  POST   /api/pawste/<id>/open?v=N           the locked text of version N (default: latest). "Burn after reading"
                                             pastes are deleted right here, so link previews (which only fetch the
                                             static page) can never use one up.
  PUT    /api/pawste/<id>                    save a new version {hdr, ct}                         [X-Edit-Token]
  DELETE /api/pawste/<id>                    delete now                                           [X-Edit-Token]
  POST   /api/pawste/<id>/report             {reason, details, link}; 3 reports from different visitors hide it
  POST   /api/pawste/plain?ttl=1d&burn=1&title=&lang=&force=1   command line (paw.gmcat.io POST / lands here): the body is
                                             plain text; makes a short-link paste (not encrypted) and answers with the link
                                             (+ X-Pawste-Edit header; JSON with Accept: application/json). Leak Guard runs here
                                             and refuses likely secrets unless force=1.
  GET    /api/pawste/<id>/raw                a short-link paste as plain text (paw.gmcat.io/raw/<id>); not for burn,
                                             password or private pastes
Admin (the owner's dashboard forwards these with the admin key; only its SHA-256 lives here, PAWSTE_ADMIN_KEY_SHA256):
  GET    /api/pawste/admin/overview          counts, storage, open reports
  POST   /api/pawste/admin/hold {id}  /restore {id}  /delete {id}  /dismiss {report}

hdr is the browser's small public header (cipher version, IV, password salt), ct the base64 ciphertext.
Data: PAWSTE_DATA/pawste.db (SQLite). Edit tokens are stored only as SHA-256 hashes. No IP addresses are stored,
only short-lived salted hashes in memory for rate limits. Expired pastes are deleted every minute.
Dev mode (PAWSTE_DEV_STATIC=<dist/tools>): also serves the static Toolbox and /p/<id>, for local testing.
"""
import base64
import hashlib
import hmac
import json
import os
import re
import secrets
import sqlite3
import threading
import time
import urllib.parse
import zlib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

DATA = Path(os.environ.get("PAWSTE_DATA", "/var/lib/gmcat-pawste"))
PORT = int(os.environ.get("PAWSTE_PORT", "4198"))
CAP_BYTES = int(float(os.environ.get("PAWSTE_CAP_MB", "2048")) * 1024 * 1024)
ADMIN_SHA = os.environ.get("PAWSTE_ADMIN_KEY_SHA256", "").strip().lower()
DEV_STATIC = os.environ.get("PAWSTE_DEV_STATIC", "")

MAX_CT = 720_000            # base64 characters: about 512 KB of text once unlocked
MAX_HDR = 400
MAX_VERSIONS = 50
TTLS = {600, 3600, 86400, 604800, 2592000, 15552000, 31536000}   # 10 min, 1 h, 1 day, 1 week, 1 month, 6 months, 1 year
REPORTS_TO_HIDE = 3
LIMITS = {"create": (30, 3600), "edit": (120, 3600), "report": (10, 3600), "miss": (120, 3600)}
ALPHABET = "23456789abcdefghjkmnpqrstuvwxyz"   # no look-alikes (0/o, 1/l/i)
ID_LEN = 10          # private (e2e) pastes
SHORT_LEN = 8        # short-link pastes
ID_RE = re.compile(r"^[%s]{%d}(?:[%s]{%d})?$" % (ALPHABET, SHORT_LEN, ALPHABET, ID_LEN - SHORT_LEN))
KINDS = ("e2e", "pw", "none")
B64_RE = re.compile(r"^[A-Za-z0-9+/=_-]+$")
REASONS = {"illegal", "abuse", "personal", "malware", "spam", "copyright", "other"}
LINK_BASE = os.environ.get("PAWSTE_LINK_BASE", "https://paw.gmcat.io/")
TTL_WORDS = {"10m": 600, "1h": 3600, "1d": 86400, "1w": 604800, "1m": 2592000, "6m": 15552000, "1y": 31536000}
LANG_RE = re.compile(r"^[a-z0-9+#-]{1,20}$")
# Leak Guard for command-line pastes (the web editor runs its own copy in the browser)
LEAK_RULES = [
    ("a private key", re.compile(r"-----BEGIN (?:[A-Z]+ )?PRIVATE KEY-----")),
    ("an AWS access key", re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b")),
    ("a GitHub token", re.compile(r"\b(?:gh[pousr]_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{60,})\b")),
    ("a Slack token", re.compile(r"\bxox[abposr]-[A-Za-z0-9-]{10,}\b")),
    ("a Stripe secret key", re.compile(r"\b[rs]k_live_[A-Za-z0-9]{16,}\b")),
    ("a Google API key", re.compile(r"\bAIza[0-9A-Za-z_-]{35}\b")),
    ("an AI service key", re.compile(r"\bsk-(?:ant-|proj-)?[A-Za-z0-9_-]{24,}\b")),
    ("a login token (JWT)", re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b")),
    ("a password in a link", re.compile(r"\b[a-z][a-z0-9+.-]*://[^\s:@/]+:[^\s@/]{3,}@\S+", re.I)),
    ("a password or secret", re.compile(r"\b(?:password|passwd|pwd|secret|api[_-]?key|access[_-]?token|auth[_-]?token|client[_-]?secret)\b[\"']?\s*[:=]\s*[\"']?(?!\[hidden)[^\s\"',;]{4,}", re.I)),
]


def luhn_card(text):
    for m in re.finditer(r"\b(?:\d[ -]?){13,19}\b", text):
        d = re.sub(r"\D", "", m.group(0))
        if 13 <= len(d) <= 19 and len(set(d)) > 1:
            total, alt = 0, False
            for ch in reversed(d):
                n = int(ch) * (2 if alt else 1)
                total += n - 9 if n > 9 else n
                alt = not alt
            if total % 10 == 0:
                return True
    return False


def leak_check(text):
    found = [name for name, rx in LEAK_RULES if rx.search(text)]
    if luhn_card(text):
        found.append("a card number")
    return found


def none_text(row_ct, hdr):
    """The text of a short-link (kind "none") paste."""
    raw = base64.b64decode(row_ct)
    if json.loads(hdr).get("z"):
        raw = zlib.decompress(raw, -15)
    return json.loads(raw.decode("utf-8"))

SALT = secrets.token_bytes(32)          # new every start: visitor hashes can't be linked across restarts
HITS = {}
HITS_LOCK = threading.Lock()
DB_LOCK = threading.Lock()


def now():
    return int(time.time())


def sha(s):
    return hashlib.sha256(s.encode()).hexdigest()


def db():
    con = sqlite3.connect(DATA / "pawste.db", timeout=10)
    con.row_factory = sqlite3.Row
    con.execute("PRAGMA foreign_keys = ON")
    return con


def init():
    DATA.mkdir(parents=True, exist_ok=True)
    with db() as con:
        con.execute("PRAGMA journal_mode = WAL")
        con.executescript("""
        CREATE TABLE IF NOT EXISTS pastes (
            id TEXT PRIMARY KEY, created INTEGER NOT NULL, updated INTEGER NOT NULL, expires INTEGER NOT NULL,
            burn INTEGER NOT NULL DEFAULT 0, pw INTEGER NOT NULL DEFAULT 0, edit_hash TEXT NOT NULL,
            held INTEGER NOT NULL DEFAULT 0, opens INTEGER NOT NULL DEFAULT 0, size INTEGER NOT NULL DEFAULT 0);
        CREATE TABLE IF NOT EXISTS versions (
            paste_id TEXT NOT NULL REFERENCES pastes(id) ON DELETE CASCADE, n INTEGER NOT NULL,
            created INTEGER NOT NULL, hdr TEXT NOT NULL, ct TEXT NOT NULL, PRIMARY KEY (paste_id, n));
        CREATE TABLE IF NOT EXISTS reports (
            id INTEGER PRIMARY KEY AUTOINCREMENT, paste_id TEXT NOT NULL, created INTEGER NOT NULL,
            reason TEXT NOT NULL, details TEXT NOT NULL DEFAULT '', link TEXT NOT NULL DEFAULT '',
            visitor TEXT NOT NULL, open INTEGER NOT NULL DEFAULT 1);
        CREATE TABLE IF NOT EXISTS stats (k TEXT PRIMARY KEY, v INTEGER NOT NULL DEFAULT 0);
        CREATE INDEX IF NOT EXISTS pastes_expires ON pastes(expires);
        """)
        cols = [r[1] for r in con.execute("PRAGMA table_info(pastes)")]
        if "kind" not in cols:   # added with short links (2026-11-15); older pastes are all private
            con.execute("ALTER TABLE pastes ADD COLUMN kind TEXT NOT NULL DEFAULT 'e2e'")


def bump(con, key, n=1):
    con.execute("INSERT INTO stats (k, v) VALUES (?, ?) ON CONFLICT(k) DO UPDATE SET v = v + ?", (key, n, n))


def used_bytes(con):
    return con.execute("SELECT COALESCE(SUM(LENGTH(ct)), 0) FROM versions").fetchone()[0]


def remove(con, pid):
    con.execute("DELETE FROM versions WHERE paste_id = ?", (pid,))
    con.execute("DELETE FROM reports WHERE paste_id = ?", (pid,))
    con.execute("DELETE FROM pastes WHERE id = ?", (pid,))


def cleanup_once():
    with DB_LOCK, db() as con:
        for (pid,) in con.execute("SELECT id FROM pastes WHERE expires <= ?", (now(),)).fetchall():
            remove(con, pid)
    t = now()
    with HITS_LOCK:
        for k in list(HITS):
            HITS[k] = [x for x in HITS[k] if x > t - 3600]
            if not HITS[k]:
                del HITS[k]


def cleanup_loop():
    while True:
        try:
            cleanup_once()
        except Exception as ex:  # keep the loop alive; the next minute tries again
            print("cleanup failed:", ex, flush=True)
        time.sleep(60)


def cipher_kind(d):
    """-> (kind, None) for good paste data, or (None, error message)."""
    hdr, ct = d.get("hdr"), d.get("ct")
    if not isinstance(hdr, str) or not isinstance(ct, str) or not hdr or not ct:
        return None, "Missing paste data."
    if len(hdr) > MAX_HDR or len(ct) > MAX_CT:
        return None, "That paste is too big. Pawste holds up to 512 KB of text."
    if not B64_RE.match(ct):
        return None, "The paste data is damaged."
    try:
        h = json.loads(hdr)
        if not isinstance(h, dict) or h.get("v") != 1:
            raise ValueError
        kind = h.get("k", "e2e")
        if kind not in KINDS or (kind != "none" and not isinstance(h.get("iv"), str)) or (kind == "pw" and not h.get("salt")):
            raise ValueError
    except ValueError:
        return None, "The paste data is damaged."
    return kind, None


class Handler(BaseHTTPRequestHandler):
    server_version = "GmCatPawste/1"
    protocol_version = "HTTP/1.1"

    def log_message(self, fmt, *args):
        pass

    def visitor(self):
        ip = self.headers.get("X-Real-IP") or self.client_address[0]
        return hmac.new(SALT, ip.encode(), "sha256").hexdigest()[:16]

    def limited(self, kind, record=True):
        n, window = LIMITS[kind]
        key, t = "%s:%s" % (kind, self.visitor()), now()
        with HITS_LOCK:
            recent = [x for x in HITS.get(key, []) if x > t - window]
            if len(recent) >= n:
                HITS[key] = recent
                return True
            if record:
                recent.append(t)
            HITS[key] = recent
        return False

    def send_json(self, code, data):
        body = json.dumps(data).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Robots-Tag", "noindex, nofollow")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def error(self, code, msg):
        self.send_json(code, {"error": msg})

    def read_json(self, limit=4096):
        n = int(self.headers.get("Content-Length") or 0)
        if n > limit:
            self.close_connection = True
            raise ValueError("too large")
        try:
            d = json.loads(self.rfile.read(n) or b"{}")
        except (ValueError, UnicodeDecodeError):
            raise ValueError("bad json")
        if not isinstance(d, dict):
            raise ValueError("bad json")
        return d

    def parts(self):
        u = urllib.parse.urlsplit(self.path)
        return [p for p in u.path.split("/") if p], urllib.parse.parse_qs(u.query)

    def same_origin(self):
        """Writes must come from our own pages (blocks other sites from posting on a visitor's behalf)."""
        origin = self.headers.get("Origin", "")
        if not origin:
            return True
        host = self.headers.get("Host", "")
        return origin in ("https://" + host, "http://" + host)

    def admin_ok(self):
        key = self.headers.get("X-Admin-Key", "")
        return bool(ADMIN_SHA) and bool(key) and hmac.compare_digest(sha(key), ADMIN_SHA)

    def live(self, con, pid):
        if not ID_RE.match(pid):
            return None
        row = con.execute("SELECT * FROM pastes WHERE id = ?", (pid,)).fetchone()
        if not row or row["expires"] <= now():
            return None
        return row

    def facts(self, con, row):
        n = con.execute("SELECT COUNT(*) FROM versions WHERE paste_id = ?", (row["id"],)).fetchone()[0]
        return {"id": row["id"], "kind": row["kind"], "burn": bool(row["burn"]), "pw": bool(row["pw"]), "created": row["created"],
                "updated": row["updated"], "expires": row["expires"], "versions": n}

    def not_found(self):
        self.limited("miss")
        self.error(404, "This paste doesn't exist. It may have expired, been deleted, or been read already.")

    # ---------------------------------------------------------------- routes
    def do_GET(self):
        parts, q = self.parts()
        if parts[:2] == ["api", "pawste"]:
            if len(parts) == 3 and parts[2] == "health":
                return self.send_json(200, {"ok": True})
            if len(parts) == 4 and parts[2] == "admin" and parts[3] == "overview":
                return self.admin_overview()
            if len(parts) == 4 and parts[3] == "raw":
                return self.raw(parts[2])
            if len(parts) == 3:
                if self.limited("miss", record=False):
                    return self.error(429, "Too many wrong links. Please wait a while and try again.")
                with db() as con:
                    row = self.live(con, parts[2])
                    if not row:
                        return self.not_found()
                    if row["held"]:
                        return self.error(451, "This paste was hidden after reports and is waiting for review.")
                    return self.send_json(200, self.facts(con, row))
            return self.error(404, "Not found.")
        if DEV_STATIC:
            return self.dev_static(parts)
        self.error(404, "Not found.")

    def do_POST(self):
        parts, q = self.parts()
        if parts[:2] != ["api", "pawste"]:
            return self.error(404, "Not found.")
        if not self.same_origin():
            return self.error(403, "Not allowed.")
        try:
            if len(parts) == 2:
                return self.create()
            if len(parts) == 3 and parts[2] == "plain":
                return self.create_plain(q)
            if len(parts) == 4 and parts[2] == "admin":
                return self.admin_action(parts[3])
            if len(parts) == 4 and parts[3] == "open":
                return self.open(parts[2], q)
            if len(parts) == 4 and parts[3] == "report":
                return self.report(parts[2])
        except ValueError:
            return self.error(400, "That request didn't look right.")
        self.error(404, "Not found.")

    def do_PUT(self):
        parts, _ = self.parts()
        if len(parts) != 3 or parts[:2] != ["api", "pawste"] or not self.same_origin():
            return self.error(404, "Not found.")
        if self.limited("edit"):
            return self.error(429, "That's a lot of saves. Please wait a little and try again.")
        try:
            d = self.read_json(MAX_CT + MAX_HDR + 1000)
        except ValueError:
            return self.error(413, "That paste is too big. Pawste holds up to 512 KB of text.")
        kind, bad = cipher_kind(d)
        if bad:
            return self.error(400, bad)
        with DB_LOCK, db() as con:
            row = self.live(con, parts[2])
            if not row or not hmac.compare_digest(row["edit_hash"], sha(self.headers.get("X-Edit-Token", ""))):
                return self.error(403, "This link can't edit that paste.")
            if row["burn"]:
                return self.error(400, "Burn-after-reading pastes can't be edited.")
            if row["held"]:
                return self.error(451, "This paste is hidden while it's reviewed.")
            if kind != row["kind"]:
                return self.error(400, "A new version must be locked the same way as the paste.")
            if used_bytes(con) + len(d["ct"]) > CAP_BYTES:
                return self.error(507, "Pawste is full right now. Please try again later.")
            n = con.execute("SELECT COALESCE(MAX(n), 0) FROM versions WHERE paste_id = ?", (row["id"],)).fetchone()[0] + 1
            count = con.execute("SELECT COUNT(*) FROM versions WHERE paste_id = ?", (row["id"],)).fetchone()[0]
            if count >= MAX_VERSIONS:   # keep the first version and the newest ones
                oldest = con.execute("SELECT MIN(n) FROM versions WHERE paste_id = ? AND n > 1", (row["id"],)).fetchone()[0]
                con.execute("DELETE FROM versions WHERE paste_id = ? AND n = ?", (row["id"], oldest))
            t = now()
            con.execute("INSERT INTO versions (paste_id, n, created, hdr, ct) VALUES (?, ?, ?, ?, ?)", (row["id"], n, t, d["hdr"], d["ct"]))
            con.execute("UPDATE pastes SET updated = ?, size = ? WHERE id = ?", (t, len(d["ct"]), row["id"]))
            bump(con, "edits")
            self.send_json(200, {"ok": True, "version": n, **self.facts(con, self.live(con, row["id"]))})

    def do_DELETE(self):
        parts, _ = self.parts()
        if len(parts) != 3 or parts[:2] != ["api", "pawste"] or not self.same_origin():
            return self.error(404, "Not found.")
        with DB_LOCK, db() as con:
            row = self.live(con, parts[2])
            if not row or not hmac.compare_digest(row["edit_hash"], sha(self.headers.get("X-Edit-Token", ""))):
                return self.error(403, "This link can't delete that paste.")
            remove(con, row["id"])
            bump(con, "deleted")
        self.send_json(200, {"ok": True})

    # ---------------------------------------------------------------- actions
    def create(self):
        if self.limited("create"):
            return self.error(429, "You've made a lot of pastes this hour. Please wait a little and try again.")
        try:
            d = self.read_json(MAX_CT + MAX_HDR + 1000)
        except ValueError:
            return self.error(413, "That paste is too big. Pawste holds up to 512 KB of text.")
        kind, bad = cipher_kind(d)
        if bad:
            return self.error(400, bad)
        ttl = d.get("ttl")
        if ttl not in TTLS:
            return self.error(400, "Choose how long to keep it.")
        token = secrets.token_urlsafe(18)
        t = now()
        with DB_LOCK, db() as con:
            if used_bytes(con) + len(d["ct"]) > CAP_BYTES:
                return self.error(507, "Pawste is full right now. Please try again later.")
            while True:
                pid = "".join(secrets.choice(ALPHABET) for _ in range(ID_LEN if kind == "e2e" else SHORT_LEN))
                if not con.execute("SELECT 1 FROM pastes WHERE id = ?", (pid,)).fetchone():
                    break
            con.execute("INSERT INTO pastes (id, created, updated, expires, burn, pw, edit_hash, size, kind) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                        (pid, t, t, t + ttl, 1 if d.get("burn") else 0, 1 if (d.get("pw") or kind == "pw") else 0, sha(token), len(d["ct"]), kind))
            con.execute("INSERT INTO versions (paste_id, n, created, hdr, ct) VALUES (?, 1, ?, ?, ?)", (pid, t, d["hdr"], d["ct"]))
            bump(con, "created")
        self.send_json(201, {"id": pid, "kind": kind, "edit_token": token, "expires": t + ttl, "burn": bool(d.get("burn"))})

    def send_text(self, code, text, extra=None):
        body = text.encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Robots-Tag", "noindex, nofollow")
        self.send_header("Content-Security-Policy", "default-src 'none'; sandbox")
        for k, v in (extra or {}).items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(body)

    def wants_json(self):
        return "application/json" in (self.headers.get("Accept") or "")

    def create_plain(self, q):
        """Command-line paste: plain text in, short link out."""
        say = (lambda code, msg: self.send_json(code, {"error": msg})) if self.wants_json() else (lambda code, msg: self.send_text(code, msg + "\n"))
        if self.limited("create"):
            return say(429, "You've made a lot of pastes this hour. Please wait a little and try again.")
        n = int(self.headers.get("Content-Length") or 0)
        if n > 512 * 1024:
            self.close_connection = True
            return say(413, "That's too big. Pawste holds up to 512 KB of text.")
        try:
            text = self.rfile.read(n).decode("utf-8")
        except UnicodeDecodeError:
            return say(400, "Pawste takes text (UTF-8), not binary files.")
        if not text.strip():
            return say(400, "Nothing to paste: send some text, e.g. echo hi | curl --data-binary @- https://paw.gmcat.io")
        one = lambda k, d="": (q.get(k) or [d])[0]
        ttl_s = one("ttl", "1w")
        ttl = TTL_WORDS.get(ttl_s) or (int(ttl_s) if ttl_s.isdigit() and int(ttl_s) in TTLS else None)
        if not ttl:
            return say(400, "ttl must be one of 10m, 1h, 1d, 1w, 1m, 6m or 1y.")
        if one("force") not in ("1", "true", "yes"):
            found = leak_check(text)
            if found:
                return say(422, "Leak Guard: this looks like it contains %s. Command-line pastes aren't encrypted, so it wasn't shared. "
                                "Remove it, use https://paw.gmcat.io/secure-note/ for secrets, or add force=1 if you're sure." % ", ".join(found))
        lang = one("lang", "auto").lower()
        doc = {"t": one("title")[:120], "f": lang if LANG_RE.match(lang) else "auto", "b": text}
        ct = base64.b64encode(json.dumps(doc, ensure_ascii=False).encode("utf-8")).decode()
        if len(ct) > MAX_CT:
            return say(413, "That's too big. Pawste holds up to 512 KB of text.")
        burn = one("burn") in ("1", "true", "yes")
        token = secrets.token_urlsafe(18)
        t = now()
        with DB_LOCK, db() as con:
            if used_bytes(con) + len(ct) > CAP_BYTES:
                return say(507, "Pawste is full right now. Please try again later.")
            while True:
                pid = "".join(secrets.choice(ALPHABET) for _ in range(SHORT_LEN))
                if not con.execute("SELECT 1 FROM pastes WHERE id = ?", (pid,)).fetchone():
                    break
            con.execute("INSERT INTO pastes (id, created, updated, expires, burn, pw, edit_hash, size, kind) VALUES (?, ?, ?, ?, ?, 0, ?, ?, 'none')",
                        (pid, t, t, t + ttl, 1 if burn else 0, sha(token), len(ct)))
            con.execute("INSERT INTO versions (paste_id, n, created, hdr, ct) VALUES (?, 1, ?, ?, ?)", (pid, t, json.dumps({"v": 1, "k": "none"}), ct))
            bump(con, "created")
            bump(con, "cli")
        link, edit = LINK_BASE + pid, LINK_BASE + pid + "#e=" + token
        if self.wants_json():
            return self.send_json(201, {"id": pid, "link": link, "edit_link": edit, "edit_token": token, "expires": t + ttl, "burn": burn,
                                        "raw": None if burn else LINK_BASE + "raw/" + pid})
        self.send_text(201, link + "\n", {"X-Pawste-Edit": edit, "X-Pawste-Expires": str(t + ttl)})

    def raw(self, pid):
        if self.limited("miss", record=False):
            return self.send_text(429, "Too many wrong links. Please wait a while and try again.\n")
        with db() as con:
            row = self.live(con, pid)
            if not row:
                self.limited("miss")
                return self.send_text(404, "This paste doesn't exist. It may have expired or been deleted.\n")
            if row["held"]:
                return self.send_text(451, "This paste is hidden while it's reviewed.\n")
            if row["kind"] != "none":
                return self.send_text(403, "This paste is locked. Open %s%s in a browser to read it.\n" % (LINK_BASE, pid))
            if row["burn"]:
                return self.send_text(403, "This is a burn-after-reading paste: open %s%s in a browser (it's deleted once read).\n" % (LINK_BASE, pid))
            v = con.execute("SELECT * FROM versions WHERE paste_id = ? ORDER BY n DESC LIMIT 1", (pid,)).fetchone()
            try:
                doc = none_text(v["ct"], v["hdr"])
            except (ValueError, zlib.error):
                return self.send_text(500, "This paste couldn't be read.\n")
        with DB_LOCK, db() as con:
            con.execute("UPDATE pastes SET opens = opens + 1 WHERE id = ?", (pid,))
            bump(con, "raw")
        self.send_text(200, doc.get("b", ""))

    def open(self, pid, q):
        if self.limited("miss", record=False):
            return self.error(429, "Too many wrong links. Please wait a while and try again.")
        with DB_LOCK, db() as con:
            row = self.live(con, pid)
            if not row:
                return self.not_found()
            if row["held"]:
                return self.error(451, "This paste was hidden after reports and is waiting for review.")
            try:
                n = int(q.get("v", ["0"])[0])
            except ValueError:
                n = 0
            if n:
                v = con.execute("SELECT * FROM versions WHERE paste_id = ? AND n = ?", (pid, n)).fetchone()
            else:
                v = con.execute("SELECT * FROM versions WHERE paste_id = ? ORDER BY n DESC LIMIT 1", (pid,)).fetchone()
            if not v:
                return self.error(404, "That version isn't kept any more.")
            facts = self.facts(con, row)
            facts["list"] = [{"n": r["n"], "created": r["created"]} for r in
                             con.execute("SELECT n, created FROM versions WHERE paste_id = ? ORDER BY n", (pid,))]
            if row["burn"]:
                remove(con, pid)
                facts["burned"] = True
            else:
                con.execute("UPDATE pastes SET opens = opens + 1 WHERE id = ?", (pid,))
            bump(con, "opens")
        self.send_json(200, {**facts, "n": v["n"], "hdr": v["hdr"], "ct": v["ct"]})

    def report(self, pid):
        if self.limited("report"):
            return self.error(429, "Thanks, we have your reports. Please wait a while before sending more.")
        d = self.read_json(8192)
        reason = d.get("reason")
        if reason not in REASONS:
            return self.error(400, "Choose a reason.")
        details = str(d.get("details") or "")[:1500]
        link = str(d.get("link") or "")[:300]
        if link and not re.match(r"^https://(?:tools\.gmcat\.io/p/|paw\.gmcat\.io/)[%s]{%d,%d}(?:#[A-Za-z0-9_-]+)?$" % (ALPHABET, SHORT_LEN, ID_LEN), link):
            link = ""
        with DB_LOCK, db() as con:
            row = self.live(con, pid)
            if not row:
                return self.not_found()
            vis = self.visitor()
            if not con.execute("SELECT 1 FROM reports WHERE paste_id = ? AND visitor = ? AND open = 1", (pid, vis)).fetchone():
                con.execute("INSERT INTO reports (paste_id, created, reason, details, link, visitor) VALUES (?, ?, ?, ?, ?, ?)",
                            (pid, now(), reason, details, link, vis))
            people = con.execute("SELECT COUNT(DISTINCT visitor) FROM reports WHERE paste_id = ? AND open = 1", (pid,)).fetchone()[0]
            if people >= REPORTS_TO_HIDE and not row["held"]:
                con.execute("UPDATE pastes SET held = 1 WHERE id = ?", (pid,))
            bump(con, "reports")
        self.send_json(200, {"ok": True})

    def admin_overview(self):
        if not self.admin_ok():
            return self.error(403, "Not allowed.")
        with db() as con:
            stats = {r["k"]: r["v"] for r in con.execute("SELECT k, v FROM stats")}
            reports = [dict(r) for r in con.execute(
                "SELECT r.id, r.paste_id, r.created, r.reason, r.details, r.link, p.held, p.expires, p.kind FROM reports r "
                "JOIN pastes p ON p.id = r.paste_id WHERE r.open = 1 ORDER BY r.created DESC LIMIT 200")]
            for r in reports:
                r["reporters"] = con.execute("SELECT COUNT(DISTINCT visitor) FROM reports WHERE paste_id = ? AND open = 1",
                                             (r["paste_id"],)).fetchone()[0]
            self.send_json(200, {
                "live": con.execute("SELECT COUNT(*) FROM pastes WHERE expires > ?", (now(),)).fetchone()[0],
                "held": con.execute("SELECT COUNT(*) FROM pastes WHERE held = 1").fetchone()[0],
                "used_bytes": used_bytes(con), "cap_bytes": CAP_BYTES, "stats": stats, "reports": reports})

    def admin_action(self, action):
        if not self.admin_ok():
            return self.error(403, "Not allowed.")
        d = self.read_json()
        with DB_LOCK, db() as con:
            if action == "dismiss":
                con.execute("UPDATE reports SET open = 0 WHERE id = ?", (int(d.get("report") or 0),))
                return self.send_json(200, {"ok": True})
            pid = str(d.get("id") or "")
            if not con.execute("SELECT 1 FROM pastes WHERE id = ?", (pid,)).fetchone():
                return self.error(404, "No such paste.")
            if action == "hold":
                con.execute("UPDATE pastes SET held = 1 WHERE id = ?", (pid,))
            elif action == "restore":
                con.execute("UPDATE pastes SET held = 0 WHERE id = ?", (pid,))
                con.execute("UPDATE reports SET open = 0 WHERE paste_id = ?", (pid,))
            elif action == "delete":
                remove(con, pid)
            else:
                return self.error(404, "Not found.")
        self.send_json(200, {"ok": True})

    # ---------------------------------------------------------------- dev only
    def dev_static(self, parts):
        root = Path(DEV_STATIC).resolve()
        rel = "/".join(parts)
        if (len(parts) == 2 and parts[0] == "p" and ID_RE.match(parts[1])) or (len(parts) == 1 and ID_RE.match(parts[0])):
            rel = "pawste/view/index.html"
        f = (root / rel).resolve()
        if f.is_dir():
            f = f / "index.html"
        if root not in f.parents and f != root or not f.is_file():
            return self.error(404, "Not found.")
        body = f.read_bytes()
        types = {".html": "text/html; charset=utf-8", ".css": "text/css", ".js": "text/javascript", ".png": "image/png",
                 ".svg": "image/svg+xml", ".json": "application/json", ".webp": "image/webp", ".xml": "application/xml"}
        self.send_response(200)
        self.send_header("Content-Type", types.get(f.suffix, "application/octet-stream"))
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        if f.suffix == ".html" and rel.startswith("pawste") and os.environ.get("PAWSTE_DEV_CSP"):
            csp = re.findall(r'Content-Security-Policy "([^"]+)"', (Path(__file__).parent / "deploy" / "nginx-tools-pawste.conf").read_text())
            pol = csp[0] if rel == "pawste/view/index.html" else csp[-1]
            self.send_header("Content-Security-Policy", pol.replace("PAWSTE_THEME_HASH", os.environ["PAWSTE_DEV_CSP"]))
        self.end_headers()
        self.wfile.write(body)


def main():
    init()
    threading.Thread(target=cleanup_loop, daemon=True).start()
    srv = ThreadingHTTPServer(("127.0.0.1", PORT), Handler)
    srv.daemon_threads = True
    print("GmCat Pawste on 127.0.0.1:%d, data in %s" % (PORT, DATA), flush=True)
    srv.serve_forever()


if __name__ == "__main__":
    main()
