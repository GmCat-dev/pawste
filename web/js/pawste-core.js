/* Pawste core: shared by the editor (pawste.js) and the viewer (pawste-view.js).
   Three kinds of paste (hdr.k):
   - "e2e" (default, private link): AES-256-GCM in the browser. The 32-byte key lives only in the link after "#", which
     browsers never send to a server. With a password too, the AES key is SHA-256(link key + PBKDF2(password)).
   - "pw" (short link + password): the AES key comes from the password alone (PBKDF2, 600k rounds), so the link is
     short and the server still can't read it, but a weak password could be guessed.
   - "none" (short link): not encrypted. The server can read it. For code and notes, never for secrets.
   The server only ever sees {hdr, ct}: hdr = {v, k?, iv?, salt?, it?, z?}, ct = base64 (ciphertext or packed text).
   Inside: {t: title, f: format (auto|text|md|<language>), b: body}. */
(function () {
  "use strict";
  var P = window.Pawste = {};
  var enc = new TextEncoder(), dec = new TextDecoder();
  var PBKDF2_ITER = 310000, PW_ONLY_ITER = 600000;
  var me = document.currentScript;
  P.API = "/api/pawste";
  P.MAX_BYTES = 512 * 1024;
  /* Where shared links point: the short domain once it's live (data-link-base on this script tag), else this site's /p/ */
  P.LINK_BASE = (me && me.dataset.linkBase && /(^|\.)gmcat\.io$/.test(location.hostname)) ? me.dataset.linkBase : (location.origin + "/p/");

  /* ---------- base64 ---------- */
  function b64(bytes) {
    var s = "", chunk = 0x8000;
    for (var i = 0; i < bytes.length; i += chunk) s += String.fromCharCode.apply(null, bytes.subarray(i, i + chunk));
    return btoa(s);
  }
  function unb64(s) {
    s = s.replace(/-/g, "+").replace(/_/g, "/");
    while (s.length % 4) s += "=";
    var bin = atob(s), out = new Uint8Array(bin.length);
    for (var i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
    return out;
  }
  function b64url(bytes) { return b64(bytes).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, ""); }
  P.b64url = b64url;
  P.unb64 = unb64;
  P.newKey = function () { return b64url(crypto.getRandomValues(new Uint8Array(32))); };

  /* ---------- compression (where the browser has it) ---------- */
  var canZip = typeof CompressionStream === "function" && typeof DecompressionStream === "function";
  function pipe(bytes, stream) {
    return new Response(new Blob([bytes]).stream().pipeThrough(stream)).arrayBuffer().then(function (b) { return new Uint8Array(b); });
  }

  /* ---------- keys ---------- */
  function pbkdf2(password, salt, iter) {
    return crypto.subtle.importKey("raw", enc.encode(password), "PBKDF2", false, ["deriveBits"]).then(function (k) {
      return crypto.subtle.deriveBits({ name: "PBKDF2", hash: "SHA-256", salt: salt, iterations: iter }, k, 256);
    });
  }
  function aesKey(kind, linkKey, password, salt, iter) {
    var step;
    if (kind === "pw") {
      if (!password) return Promise.reject(new Error("locked"));
      step = pbkdf2(password, salt, iter);
    } else {
      var raw = unb64(linkKey || "");
      if (raw.length !== 32) return Promise.reject(new Error("badkey"));
      step = password ? pbkdf2(password, salt, iter).then(function (bits) {
        var both = new Uint8Array(64); both.set(raw); both.set(new Uint8Array(bits), 32);
        return crypto.subtle.digest("SHA-256", both);
      }) : Promise.resolve(raw);
    }
    return step.then(function (material) { return crypto.subtle.importKey("raw", material, "AES-GCM", false, ["encrypt", "decrypt"]); });
  }
  function kindOf(hdr) { return hdr.k === "pw" || hdr.k === "none" ? hdr.k : "e2e"; }
  P.kind = function (hdrStr) { try { return kindOf(JSON.parse(hdrStr)); } catch (e) { return "e2e"; } };

  /* lock({t, f, b}, kind, linkKey, password?) -> {hdr, ct}. kind: "e2e" | "pw" | "none" */
  P.lock = function (doc, kind, linkKey, password) {
    var hdr = { v: 1 };
    if (kind !== "e2e") hdr.k = kind;
    var plain = enc.encode(JSON.stringify(doc));
    var packed = canZip ? pipe(plain, new CompressionStream("deflate-raw")).then(function (z) { hdr.z = 1; return z; }) : Promise.resolve(plain);
    if (kind === "none") return packed.then(function (bytes) { return { hdr: JSON.stringify(hdr), ct: b64(bytes) }; });
    var iv = crypto.getRandomValues(new Uint8Array(12));
    var iter = kind === "pw" ? PW_ONLY_ITER : PBKDF2_ITER;
    var salt = password ? crypto.getRandomValues(new Uint8Array(16)) : null;
    hdr.iv = b64(iv);
    if (salt) { hdr.salt = b64(salt); hdr.it = iter; }
    return Promise.all([packed, aesKey(kind, linkKey, password, salt, iter)]).then(function (r) {
      return crypto.subtle.encrypt({ name: "AES-GCM", iv: iv }, r[1], r[0]);
    }).then(function (ct) { return { hdr: JSON.stringify(hdr), ct: b64(new Uint8Array(ct)) }; });
  };

  /* unlock(hdrString, ct, linkKey, password?) -> {t, f, b}. Rejects with Error("locked") when the key/password is wrong. */
  P.unlock = function (hdrStr, ct, linkKey, password) {
    var hdr = JSON.parse(hdrStr), kind = kindOf(hdr);
    if (hdr.z && !canZip) return Promise.reject(new Error("oldbrowser"));
    var opened = kind === "none" ? Promise.resolve(unb64(ct)) :
      aesKey(kind, linkKey, password, hdr.salt ? unb64(hdr.salt) : null, hdr.it || PBKDF2_ITER).then(function (k) {
        return crypto.subtle.decrypt({ name: "AES-GCM", iv: unb64(hdr.iv) }, k, unb64(ct));
      }).then(function (buf) { return new Uint8Array(buf); }, function (e) { throw new Error(e && e.message === "badkey" ? "badkey" : "locked"); });
    return opened.then(function (bytes) {
      return hdr.z ? pipe(bytes, new DecompressionStream("deflate-raw")) : bytes;
    }).then(function (bytes) {
      var doc = JSON.parse(dec.decode(bytes));
      return { t: String(doc.t || ""), f: String(doc.f || "auto"), b: String(doc.b || "") };
    });
  };
  P.needsPassword = function (hdrStr) { try { return !!JSON.parse(hdrStr).salt; } catch (e) { return false; } };

  /* ---------- link fragments: #<key>&e=<edit token>&L=5-9 (short links: #e=...&L=...) ---------- */
  P.parseHash = function (hash) {
    var parts = (hash || "").replace(/^#/, "").split("&"), out = { key: "", edit: "", lines: null };
    parts.forEach(function (p, i) {
      if (i === 0 && /^[A-Za-z0-9_-]{43}$/.test(p)) out.key = p;
      else if (/^e=[A-Za-z0-9_-]{10,64}$/.test(p)) out.edit = p.slice(2);
      else if (/^L=\d+(-\d+)?$/.test(p)) {
        var m = p.slice(2).split("-").map(Number);
        out.lines = [Math.min(m[0], m[1] || m[0]), Math.max(m[0], m[1] || m[0])];
      }
    });
    return out;
  };
  /* frag("key", "&e=x") -> "#key&e=x" ; frag("", "&L=3") -> "#L=3" ; frag("", "") -> "" */
  P.frag = function (key, extra) {
    var f = (key || "") + (extra || "");
    f = f.replace(/^&/, "");
    return f ? "#" + f : "";
  };
  P.link = function (id, key, extra) { return P.LINK_BASE + id + P.frag(key, extra); };
  P.ID_RE = /^[2-9a-hjkmnp-z]{8}(?:[2-9a-hjkmnp-z]{2})?$/;
  P.HOME = location.hostname === "paw.gmcat.io" ? "/" : "/pawste/";   // the editor
  P.LINK_HOST = P.LINK_BASE.replace(/^https?:\/\//, "").replace(/\/(p\/)?$/, "");   // for labels, e.g. paw.gmcat.io

  /* ---------- this device's pastes (localStorage) ---------- */
  var MINE = "pawste-mine";
  P.mine = function () {
    var t = Date.now() / 1000;
    try { return (JSON.parse(localStorage.getItem(MINE) || "[]") || []).filter(function (x) { return x.expires > t; }); } catch (e) { return []; }
  };
  P.saveMine = function (list) { try { localStorage.setItem(MINE, JSON.stringify(list.slice(0, 50))); } catch (e) { /* private mode */ } };
  P.remember = function (item) { P.saveMine([item].concat(P.mine().filter(function (x) { return x.id !== item.id; }))); };
  P.forget = function (id) { P.saveMine(P.mine().filter(function (x) { return x.id !== id; })); };
  P.findMine = function (id) { return P.mine().filter(function (x) { return x.id === id; })[0] || null; };

  /* ---------- API ---------- */
  P.api = function (method, path, body, headers) {
    return fetch(P.API + path, {
      method: method, headers: Object.assign(body ? { "Content-Type": "application/json" } : {}, headers || {}),
      body: body ? JSON.stringify(body) : undefined
    }).then(function (r) {
      return r.json().catch(function () { return {}; }).then(function (d) {
        if (!r.ok) { var e = new Error(d.error || "Something went wrong (" + r.status + ")."); e.status = r.status; throw e; }
        return d;
      });
    }, function () { throw new Error("Couldn't reach Pawste. Check your connection and try again."); });
  };

  /* ---------- small helpers ---------- */
  P.esc = function (s) { return String(s).replace(/[&<>"']/g, function (c) { return { "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]; }); };
  P.bytes = function (s) { return enc.encode(s).length; };
  P.size = function (n) { return n < 1024 ? n + " B" : n < 1048576 ? (n / 1024).toFixed(n < 10240 ? 1 : 0) + " KB" : (n / 1048576).toFixed(1) + " MB"; };
  P.left = function (expires) {
    var s = Math.max(0, Math.round(expires - Date.now() / 1000));
    if (s < 3600) return Math.max(1, Math.round(s / 60)) + " min";
    if (s < 86400) return Math.round(s / 3600) + " h";
    var d = Math.round(s / 86400);
    return d + (d === 1 ? " day" : " days");
  };
  P.when = function (t) {
    try { return new Date(t * 1000).toLocaleString(undefined, { month: "short", day: "numeric", hour: "numeric", minute: "2-digit" }); }
    catch (e) { return new Date(t * 1000).toISOString().slice(0, 16).replace("T", " "); }
  };
  P.copy = function (text) {
    if (navigator.clipboard && navigator.clipboard.writeText) return navigator.clipboard.writeText(text);
    var ta = document.createElement("textarea"); ta.value = text; ta.style.position = "fixed"; ta.style.opacity = "0";
    document.body.appendChild(ta); ta.select();
    try { document.execCommand("copy"); } finally { ta.remove(); }
    return Promise.resolve();
  };
  P.flash = function (btn, msg) {
    var old = btn.dataset.label || btn.textContent;
    btn.dataset.label = old; btn.textContent = msg || "Copied!";
    clearTimeout(btn._t); btn._t = setTimeout(function () { btn.textContent = old; }, 1600);
  };

  /* ---------- formats ---------- */
  P.LANGS = [["auto", "Detect automatically"], ["text", "Plain text"], ["md", "Markdown (shows formatted)"],
    ["bash", "Bash / shell"], ["c", "C"], ["cpp", "C++"], ["csharp", "C#"], ["css", "CSS"], ["diff", "Diff / patch"],
    ["go", "Go"], ["graphql", "GraphQL"], ["ini", "INI / TOML"], ["java", "Java"], ["javascript", "JavaScript"], ["json", "JSON"],
    ["kotlin", "Kotlin"], ["lua", "Lua"], ["makefile", "Makefile"], ["perl", "Perl"], ["php", "PHP"], ["python", "Python"],
    ["r", "R"], ["ruby", "Ruby"], ["rust", "Rust"], ["scss", "SCSS"], ["sql", "SQL"], ["swift", "Swift"],
    ["typescript", "TypeScript"], ["vbnet", "VB.NET"], ["xml", "HTML / XML"], ["yaml", "YAML"]];
  P.langName = function (f) {
    for (var i = 0; i < P.LANGS.length; i++) if (P.LANGS[i][0] === f) return P.LANGS[i][1].replace(" (shows formatted)", "");
    return f;
  };
  /* Pick a language for "auto": looks like Markdown -> md; otherwise highlight.js guesses; weak guesses -> text. */
  P.detect = function (text) {
    var sample = text.slice(0, 20000);
    var mdHits = (sample.match(/^(#{1,6} |\s*[-*] |\s*\d+\. |> |```)/gm) || []).length + (sample.match(/\[[^\]]+\]\(https?:\/\/[^)]+\)|\*\*[^*\n]+\*\*/g) || []).length;
    var lines = sample.split("\n").length;
    if (mdHits >= 2 && mdHits >= lines / 12 && !/[;{}]\s*$/m.test(sample.slice(0, 400))) return "md";
    if (window.hljs) {
      var r = hljs.highlightAuto(sample, P.LANGS.slice(3).map(function (l) { return l[0]; }));
      if (r.language && r.relevance >= 6) return r.language;
    }
    return "text";
  };

  /* ---------- Leak Guard: spot secrets before they're shared ---------- */
  function luhn(num) {
    var s = 0, alt = false;
    for (var i = num.length - 1; i >= 0; i--) {
      var d = +num[i];
      if (alt) { d *= 2; if (d > 9) d -= 9; }
      s += d; alt = !alt;
    }
    return s % 10 === 0;
  }
  var RULES = [
    ["Private key", /-----BEGIN (?:[A-Z]+ )?PRIVATE KEY-----[\s\S]*?(?:-----END (?:[A-Z]+ )?PRIVATE KEY-----|$)/g],
    ["AWS access key", /\b(?:AKIA|ASIA)[0-9A-Z]{16}\b/g],
    ["GitHub token", /\b(?:gh[pousr]_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{60,})\b/g],
    ["Slack token", /\bxox[abposr]-[A-Za-z0-9-]{10,}\b/g],
    ["Stripe secret key", /\b[rs]k_live_[A-Za-z0-9]{16,}\b/g],
    ["Google API key", /\bAIza[0-9A-Za-z_-]{35}\b/g],
    ["AI service key", /\bsk-(?:ant-|proj-)?[A-Za-z0-9_-]{24,}\b/g],
    ["Email service key", /\b(?:re_[A-Za-z0-9]{8,}_[A-Za-z0-9]{12,}|SG\.[A-Za-z0-9_-]{16,}\.[A-Za-z0-9_-]{16,})\b/g],
    ["Discord token", /\b[MN][A-Za-z0-9_-]{23,25}\.[A-Za-z0-9_-]{6}\.[A-Za-z0-9_-]{27,}\b/g],
    ["Login token (JWT)", /\beyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b/g],
    ["Password in a link", /\b[a-z][a-z0-9+.-]*:\/\/[^\s:@\/]+:[^\s@\/]{3,}@[^\s]+/gi],
    ["Password or secret", /\b(?:password|passwd|pwd|secret|api[_-]?key|access[_-]?token|auth[_-]?token|client[_-]?secret)\b["']?\s*[:=]\s*["']?[^\s"',;]{4,}/gi],
    ["Card number", /\b(?:\d[ -]?){13,19}\b/g, function (m) { var d = m.replace(/\D/g, ""); return d.length >= 13 && d.length <= 19 && luhn(d) && !/^(\d)\1+$/.test(d); }],
    ["Recovery phrase", /\b(?:seed|recovery|mnemonic|secret)\s+(?:phrase|words)\b/gi]
  ];
  /* -> [{type, start, end, text}] (no overlaps, in order) */
  P.scan = function (text) {
    var found = [];
    if (text.length > P.MAX_BYTES) text = text.slice(0, P.MAX_BYTES);
    RULES.forEach(function (r) {
      r[1].lastIndex = 0;
      var m;
      while ((m = r[1].exec(text))) {
        if (!m[0]) { r[1].lastIndex++; continue; }
        if (r[2] && !r[2](m[0])) continue;
        if (m[0].indexOf("[hidden") !== -1) continue;   // already hidden by Leak Guard
        found.push({ type: r[0], start: m.index, end: m.index + m[0].length, text: m[0] });
      }
    });
    found.sort(function (a, b) { return a.start - b.start || b.end - a.end; });
    var out = [], last = -1;
    found.forEach(function (f) { if (f.start >= last) { out.push(f); last = f.end; } });
    return out;
  };
  P.redact = function (text, hits) {
    var s = text;
    hits.slice().reverse().forEach(function (h) {
      var keep = h.type === "Password or secret" ? (h.text.match(/^[^:=]+[:=]\s*["']?/) || [""])[0] : "";
      if (h.type === "Recovery phrase") return;   // a warning only: we can't tell which words are the phrase
      s = s.slice(0, h.start) + keep + "[hidden " + h.type.toLowerCase() + "]" + s.slice(h.end);
    });
    return s;
  };

  /* ---------- Markdown (safe: everything is escaped first, links are http(s)/mailto only) ---------- */
  function inline(s) {
    var codes = [];
    s = s.replace(/`([^`\n]+)`/g, function (_, c) { codes.push(c); return "\u0000" + (codes.length - 1) + "\u0000"; });
    s = P.esc(s);
    s = s.replace(/!\[([^\]]*)\]\(([^)\s]+)\)/g, function (_, alt, url) { return "[image: " + alt + "]"; });
    s = s.replace(/\[([^\]]+)\]\(([^)\s]+)\)/g, function (all, label, url) {
      var u = url.replace(/&amp;/g, "&");
      if (!/^(https?:\/\/|mailto:)/i.test(u)) return all;
      return '<a href="' + P.esc(u) + '" rel="nofollow noopener noreferrer ugc" target="_blank">' + label + "</a>";
    });
    s = s.replace(/(^|[\s(])(https?:\/\/[^\s<)]+)/g, function (_, pre, url) {
      return pre + '<a href="' + url + '" rel="nofollow noopener noreferrer ugc" target="_blank">' + url + "</a>";
    });
    s = s.replace(/\*\*([^*]+)\*\*/g, "<strong>$1</strong>").replace(/__([^_]+)__/g, "<strong>$1</strong>");
    s = s.replace(/(^|[^*])\*([^*\s][^*]*)\*/g, "$1<em>$2</em>").replace(/(^|[^\w])_([^_\s][^_]*)_(?!\w)/g, "$1<em>$2</em>");
    s = s.replace(/~~([^~]+)~~/g, "<del>$1</del>");
    return s.replace(/\u0000(\d+)\u0000/g, function (_, i) { return "<code>" + P.esc(codes[+i]) + "</code>"; });
  }
  P.markdown = function (src) {
    var lines = src.replace(/\r\n?/g, "\n").split("\n"), out = [], i = 0, para = [];
    function flush() { if (para.length) { out.push("<p>" + inline(para.join("\n")).replace(/\n/g, "<br>") + "</p>"); para = []; } }
    while (i < lines.length) {
      var l = lines[i], m;
      if ((m = l.match(/^\s*```\s*([\w+-]*)/))) {
        flush();
        var code = [], lang = m[1].toLowerCase();
        i++;
        while (i < lines.length && !/^\s*```/.test(lines[i])) code.push(lines[i++]);
        i++;
        var html = P.esc(code.join("\n"));
        if (window.hljs && lang && hljs.getLanguage(lang)) { try { html = hljs.highlight(code.join("\n"), { language: lang }).value; } catch (e) { /* plain */ } }
        out.push('<pre class="md-code"><code class="hljs">' + html + "</code></pre>");
        continue;
      }
      if (!l.trim()) { flush(); i++; continue; }
      if ((m = l.match(/^(#{1,6})\s+(.*)$/))) { flush(); var n = Math.min(6, m[1].length + 1); out.push("<h" + n + ">" + inline(m[2]) + "</h" + n + ">"); i++; continue; }
      if (/^\s*([-*_])(\s*\1){2,}\s*$/.test(l)) { flush(); out.push("<hr>"); i++; continue; }
      if (/^>\s?/.test(l)) {
        flush();
        var q = [];
        while (i < lines.length && /^>\s?/.test(lines[i])) q.push(lines[i++].replace(/^>\s?/, ""));
        out.push("<blockquote>" + P.markdown(q.join("\n")) + "</blockquote>");
        continue;
      }
      if (/^\s*([-*+]|\d+[.)])\s+/.test(l)) {
        flush();
        var ordered = /^\s*\d/.test(l), items = [];
        while (i < lines.length && /^\s*([-*+]|\d+[.)])\s+/.test(lines[i])) {
          var item = lines[i++].replace(/^\s*([-*+]|\d+[.)])\s+/, ""), box = item.match(/^\[([ xX])\]\s+(.*)$/);
          items.push(box ? '<li class="task"><input type="checkbox" disabled' + (box[1] !== " " ? " checked" : "") + "> " + inline(box[2]) + "</li>" : "<li>" + inline(item) + "</li>");
        }
        out.push((ordered ? "<ol>" : "<ul>") + items.join("") + (ordered ? "</ol>" : "</ul>"));
        continue;
      }
      if (/\|/.test(l) && i + 1 < lines.length && /^\s*\|?\s*:?-{3,}:?\s*(\|\s*:?-{3,}:?\s*)*\|?\s*$/.test(lines[i + 1])) {
        flush();
        var row = function (r) { return r.trim().replace(/^\||\|$/g, "").split("|").map(function (c) { return c.trim(); }); };
        var head = row(l), body = [];
        i += 2;
        while (i < lines.length && /\|/.test(lines[i]) && lines[i].trim()) body.push(row(lines[i++]));
        out.push('<div class="md-table"><table><thead><tr>' + head.map(function (c) { return "<th>" + inline(c) + "</th>"; }).join("") + "</tr></thead><tbody>" +
          body.map(function (r) { return "<tr>" + r.map(function (c) { return "<td>" + inline(c) + "</td>"; }).join("") + "</tr>"; }).join("") + "</tbody></table></div>");
        continue;
      }
      para.push(l); i++;
    }
    flush();
    return out.join("\n");
  };

  /* ---------- line diff between two versions ---------- */
  /* -> [{op: " "|"+"|"-", text}] ; null when the texts are too big to compare here */
  P.diff = function (a, b) {
    var A = a.split("\n"), B = b.split("\n"), pre = 0, post = 0;
    while (pre < A.length && pre < B.length && A[pre] === B[pre]) pre++;
    while (post < A.length - pre && post < B.length - pre && A[A.length - 1 - post] === B[B.length - 1 - post]) post++;
    var a2 = A.slice(pre, A.length - post), b2 = B.slice(pre, B.length - post), n = a2.length, m = b2.length;
    if (n * m > 4000000) return null;
    var L = [], i, j;
    for (i = 0; i <= n; i++) L.push(new Uint32Array(m + 1));
    for (i = n - 1; i >= 0; i--) for (j = m - 1; j >= 0; j--) L[i][j] = a2[i] === b2[j] ? L[i + 1][j + 1] + 1 : Math.max(L[i + 1][j], L[i][j + 1]);
    var out = A.slice(0, pre).map(function (t) { return { op: " ", text: t }; });
    i = 0; j = 0;
    while (i < n && j < m) {
      if (a2[i] === b2[j]) { out.push({ op: " ", text: a2[i] }); i++; j++; }
      else if (L[i + 1][j] >= L[i][j + 1]) out.push({ op: "-", text: a2[i++] });
      else out.push({ op: "+", text: b2[j++] });
    }
    while (i < n) out.push({ op: "-", text: a2[i++] });
    while (j < m) out.push({ op: "+", text: b2[j++] });
    return out.concat(A.slice(A.length - post).map(function (t) { return { op: " ", text: t }; }));
  };

  /* Split highlighted HTML into lines, closing and reopening <span>s that cross a line break. */
  P.splitLines = function (html) {
    var out = [], open = [], line = "", re = /(<span[^>]*>)|(<\/span>)|(\n)|([^<\n]+|<)/g, m;
    while ((m = re.exec(html))) {
      if (m[1]) { open.push(m[1]); line += m[1]; }
      else if (m[2]) { open.pop(); line += m[2]; }
      else if (m[3]) { out.push(line + new Array(open.length + 1).join("</span>")); line = open.join(""); }
      else line += m[4];
    }
    out.push(line);
    return out;
  };

  /* ---------- in-page dialogs (never the browser's own confirm/alert/prompt boxes) ----------
     P.ask({title, text, ok, cancel, danger, input: "password"|"text", placeholder}) -> Promise:
       confirm style: true / false ; with input: the typed value, or null when cancelled
     P.tell({title, text}) -> Promise (a single OK button) */
  P.ask = function (o) {
    return new Promise(function (resolve) {
      var d = document.createElement("dialog");
      d.className = "pw-dlg card pw-ask";
      d.setAttribute("aria-labelledby", "pw-ask-h");
      d.innerHTML = '<form method="dialog">' +
        '<h2 class="panel-h" id="pw-ask-h">' + P.esc(o.title || "Are you sure?") + "</h2>" +
        (o.text ? '<p class="pw-ask-text">' + P.esc(o.text) + "</p>" : "") +
        (o.input ? '<input class="pw-ask-input" type="' + (o.input === "password" ? "password" : "text") + '" autocomplete="off" aria-label="' + P.esc(o.placeholder || o.title || "") + '" placeholder="' + P.esc(o.placeholder || "") + '">' : "") +
        '<div class="tool-actions">' +
        '<button class="btn ' + (o.danger ? "pw-danger" : "primary") + '" value="ok">' + P.esc(o.ok || "OK") + "</button>" +
        (o.cancel === false ? "" : '<button class="btn" value="cancel" formnovalidate>' + P.esc(o.cancel || "Cancel") + "</button>") +
        "</div></form>";
      document.body.appendChild(d);
      var input = d.querySelector(".pw-ask-input"), done = false;
      function finish(okd) {
        if (done) return; done = true;
        var v = input ? (okd ? input.value : null) : okd;
        if (d.open) d.close();
        d.remove();
        resolve(v);
      }
      d.addEventListener("close", function () { finish(d.returnValue === "ok"); });
      d.addEventListener("cancel", function (ev) { ev.preventDefault(); finish(false); });   // Esc
      d.addEventListener("click", function (ev) { if (ev.target === d) finish(false); });     // tap outside
      d.showModal();
      (input || d.querySelector('button[value="' + (o.danger ? "cancel" : "ok") + '"]') || d.querySelector("button")).focus();
    });
  };
  P.tell = function (o) { return P.ask({ title: o.title || "Heads up", text: o.text, ok: "OK", cancel: false }); };

  /* ---------- QR code (vendored qrcode-generator, MIT) ---------- */
  P.qrSvg = function (text) {
    if (!window.qrcode) return "";
    var q = qrcode(0, "M"); q.addData(text); q.make();
    return q.createSvgTag({ cellSize: 6, margin: 2, scalable: true });
  };
})();
