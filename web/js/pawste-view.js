/* Pawste reader: paw.gmcat.io/<id>[#<key>][&e=<edit token>][&L=5-9] (also tools.gmcat.io/p/<id>…).
   Private pastes need the key after "#"; short-link pastes don't (or ask for their password). Everything is unlocked here. */
(function () {
  "use strict";
  var P = window.Pawste, $ = function (id) { return document.getElementById(id); };
  var id = (location.pathname.match(/^\/(?:p\/)?([a-z0-9]{8}(?:[a-z0-9]{2})?)\/?$/) || [])[1];
  if (id && !P.ID_RE.test(id)) id = "";
  var hash = P.parseHash(location.hash);
  var state = $("pw-state");
  var facts = null, doc = null, password = "", current = 0, wrap = false, showSource = false, selected = hash.lines;
  var cache = {};   // version -> {t, f, b}
  var mine = id ? P.findMine(id) : null;
  var editToken = hash.edit || (mine && mine.key === hash.key ? mine.edit : "");

  function say(html) { state.hidden = false; state.innerHTML = html; $("pw-paper").hidden = true; }
  function plainLink() { return P.link(id, hash.key); }
  function lineFrag() { return selected ? "&L=" + selected[0] + (selected[1] !== selected[0] ? "-" + selected[1] : "") : ""; }

  /* Keep the edit token out of the address bar (people copy addresses); it's remembered on this device instead. */
  if (hash.edit && id) {
    if (!mine) { P.remember({ id: id, key: hash.key, edit: hash.edit, title: "", created: Math.floor(Date.now() / 1000), expires: Date.now() / 1000 + 86400 * 365, burn: false }); mine = P.findMine(id); }
    else if (!mine.edit) { mine.edit = hash.edit; P.remember(mine); }
    history.replaceState(null, "", location.pathname + P.frag(hash.key, lineFrag()));
  }

  /* ---------- start ---------- */
  if (!id) { say("<h1>That's not a Pawste link</h1><p>Check the address and try again.</p>"); return; }
  P.api("GET", "/" + id).then(function (f) {
    facts = f;
    if ((f.kind || "e2e") === "e2e" && !hash.key) {
      say('<h1>This link is missing its key</h1><p>Private Pawste links end with a long code after “#”. That code is the key that unlocks the paste, and only the person who shared it has it. Ask them to send the whole link again.</p><p><a class="btn" href="' + P.HOME + '">Make your own paste</a></p>');
      return;
    }
    if (f.burn) {
      say('<h1>🔥 This paste deletes itself when opened</h1><p>Someone sent you a burn-after-reading paste. Once you open it, it\'s deleted from Pawste for good, so be ready to read or copy it.</p>' +
        (editToken ? '<p class="muted">You made this paste. Opening it deletes it for everyone, including the person you meant it for.</p>' : "") +
        '<div class="btn-row"><button class="btn primary" type="button" id="pw-burn-go">Open it now</button>' + (editToken ? '<button class="btn" type="button" id="pw-burn-del">Delete without opening</button>' : "") + "</div>");
      $("pw-burn-go").addEventListener("click", function () { this.disabled = true; open(0); });
      if (editToken) $("pw-burn-del").addEventListener("click", del);
    } else open(0);
  }).catch(function (e) {
    if (e.status === 404) say('<h1>This paste is gone</h1><p>It may have expired, been deleted by its owner, or been a burn-after-reading paste that someone already opened.</p><p><a class="btn" href="' + P.HOME + '">Make a new paste</a></p>');
    else if (e.status === 451) say("<h1>This paste is hidden for now</h1><p>Readers reported it, so it's hidden until GmCat reviews it.</p>");
    else say("<h1>Couldn't open the paste</h1><p>" + P.esc(e.message) + "</p>");
  });

  function open(v) {
    say("<p>Unlocking…</p>");
    return P.api("POST", "/" + id + "/open" + (v ? "?v=" + v : "")).then(function (d) {
      facts = d;
      return unlockWith(d);
    }).catch(function (e) {
      if (e.status === 404) say("<h1>This paste is gone</h1><p>" + P.esc(e.message) + "</p>");
      else say("<h1>Couldn't open the paste</h1><p>" + P.esc(e.message) + "</p>");
    });
  }

  /* Unlock, asking for a password when needed. The locked text stays in memory, so a wrong password can be retried
     even after a burn-after-reading paste is gone from the server. */
  function unlockWith(d) {
    return P.unlock(d.hdr, d.ct, hash.key, password).then(function (r) {
      cache[d.n] = r; current = d.n; doc = r; show();
    }, function (e) {
      if (e.message === "oldbrowser") return say("<h1>Please update your browser</h1><p>This paste was made with compression your browser doesn't support yet. A current Chrome, Safari, Firefox or Edge opens it.</p>");
      if (e.message === "locked" && P.needsPassword(d.hdr)) return askPassword(d, !!password);
      say("<h1>This key doesn't fit</h1><p>The link may have been cut short or changed. Ask for the whole link again.</p>");
    });
  }
  function askPassword(d, wrong) {
    say('<h1>🔑 This paste has a password</h1><p>' + (wrong ? '<b class="pw-bad">That password didn\'t work.</b> ' : "") + "Enter the password the sender gave you." +
      (d.burned ? " The paste is already deleted from Pawste, but you can keep trying here until you leave this page." : "") + "</p>" +
      '<form class="pw-pwform" id="pw-pwform"><input type="password" id="pw-pw" autocomplete="off" aria-label="Password" required><button class="btn primary" type="submit">Unlock</button></form>');
    $("pw-pw").focus();
    $("pw-pwform").addEventListener("submit", function (ev) {
      ev.preventDefault();
      password = $("pw-pw").value;
      state.innerHTML = "<p>Unlocking…</p>";
      unlockWith(d);
    });
  }

  /* ---------- render ---------- */
  function lang() { return doc.f === "auto" ? P.detect(doc.b) : doc.f; }
  function show() {
    state.hidden = true;
    $("pw-paper").hidden = false;
    var lines = doc.b.split("\n").length, l = lang();
    $("pw-h").textContent = doc.t || "Untitled paste";
    document.title = (doc.t || "Private paste") + " · Pawste";
    var bits = [P.langName(l), lines + (lines === 1 ? " line" : " lines"), P.size(P.bytes(doc.b))];
    bits.push(facts.updated > facts.created ? "updated " + P.when(facts.updated) : "made " + P.when(facts.created));
    var kind = facts.kind || "e2e";
    $("pw-kind-label").textContent = kind === "none" ? "Short-link paste" : kind === "pw" ? "Password-locked paste" : "Private paste";
    bits.push(kind === "none" ? "🔗 short link, not encrypted" : kind === "pw" ? "🔑 locked with a password" : "🔒 private" + (facts.pw ? " + password" : ""));
    $("pw-facts").textContent = bits.join(" · ");
    $("pw-foot-left").textContent = facts.burned ? "Deleted from Pawste" : "Deleted in " + P.left(facts.expires);
    $("pw-burned").hidden = !facts.burned;
    $("pw-src").hidden = l !== "md";
    $("pw-src").textContent = showSource ? "Show formatted" : "Show source";
    $("pw-src").setAttribute("aria-pressed", String(showSource));
    var many = facts.list && facts.list.length > 1;
    $("pw-hist").hidden = !many || facts.burned;
    if (many) {
      var sel = '<label class="pw-ver-pick"><span class="sr">Version</span><select id="pw-ver-sel">' + facts.list.slice().reverse().map(function (x, i) {
        return '<option value="' + x.n + '"' + (x.n === current ? " selected" : "") + ">Version " + x.n + (i === 0 ? " (latest)" : "") + " · " + P.when(x.created) + "</option>";
      }).join("") + "</select></label>";
      $("pw-ver").innerHTML = sel;
      $("pw-ver-sel").addEventListener("change", function () { pickVersion(+this.value); });
    } else $("pw-ver").textContent = "";
    var owner = !!editToken && !facts.burned;
    $("pw-edit").hidden = !owner;
    if (owner) $("pw-edit").href = P.HOME + "?edit=" + id + P.frag(hash.key, "&e=" + editToken);
    $("pw-del").hidden = !owner;
    if (mine && !facts.burned) { mine.title = doc.t; mine.expires = facts.expires; P.remember(mine); }
    renderBody();
  }

  function renderBody() {
    var body = $("pw-body"), l = lang();
    body.className = "pw-body" + (wrap ? " wrap" : "");
    if (l === "md" && !showSource) {
      body.innerHTML = '<div class="pw-md">' + P.markdown(doc.b) + "</div>";
      $("pw-linehint").hidden = true;
      return;
    }
    $("pw-linehint").hidden = false;
    var html = P.esc(doc.b);
    if (window.hljs && l !== "text" && l !== "md" && hljs.getLanguage(l) && doc.b.length < 300000) {
      try { html = hljs.highlight(doc.b, { language: l, ignoreIllegals: true }).value; } catch (e) { /* plain */ }
    } else if (l === "md" && window.hljs) {
      try { html = hljs.highlight(doc.b, { language: "markdown", ignoreIllegals: true }).value; } catch (e) { /* plain */ }
    }
    var rows = P.splitLines(html);
    var out = new Array(rows.length);
    for (var i = 0; i < rows.length; i++) {
      out[i] = '<div class="pw-ln" id="L' + (i + 1) + '"><a class="pw-num" href="#" data-n="' + (i + 1) + '" aria-label="Line ' + (i + 1) + '">' + (i + 1) + '</a><code class="pw-lc">' + (rows[i] || " ") + "</code></div>";
    }
    body.innerHTML = '<div class="pw-code hljs" style="--digits:' + String(rows.length).length + '">' + out.join("") + "</div>";
    markLines(true);
  }

  function markLines(scroll) {
    document.querySelectorAll(".pw-ln.on").forEach(function (el) { el.classList.remove("on"); });
    if (!selected) return;
    for (var n = selected[0]; n <= selected[1]; n++) { var el = $("L" + n); if (el) el.classList.add("on"); }
    var first = $("L" + selected[0]);
    if (scroll && first) setTimeout(function () { first.scrollIntoView({ block: "center" }); }, 50);
  }
  $("pw-body").addEventListener("click", function (ev) {
    var a = ev.target.closest(".pw-num");
    if (!a) return;
    ev.preventDefault();
    var n = +a.dataset.n;
    if (ev.shiftKey && selected) selected = [Math.min(selected[0], n), Math.max(selected[1], n)];
    else if (selected && selected[0] === n && selected[1] === n) selected = null;
    else selected = [n, n];
    history.replaceState(null, "", location.pathname + P.frag(hash.key, lineFrag()));
    markLines(false);
  });

  function pickVersion(n) {
    if (cache[n]) { current = n; doc = cache[n]; show(); return; }
    fetchVersion(n).then(function (r) { current = n; doc = r; show(); }).catch(function (e) { P.tell({ title: "Couldn't open that version", text: e.message }); });
  }
  function fetchVersion(n) {
    if (cache[n]) return Promise.resolve(cache[n]);
    return P.api("POST", "/" + id + "/open?v=" + n).then(function (d) {
      return P.unlock(d.hdr, d.ct, hash.key, password).then(function (r) { cache[n] = r; return r; });
    });
  }

  /* ---------- toolbar ---------- */
  // Phones: only Copy text / Copy link show; "More" opens the rest (Toolbox tidy, 2026-11-17). Desktop shows them all.
  var moreBtn = $("pw-more-btn"), more = $("pw-more");
  function setMore(open) { more.classList.toggle("open", open); moreBtn.setAttribute("aria-expanded", open ? "true" : "false"); }
  moreBtn.addEventListener("click", function () { setMore(!more.classList.contains("open")); });
  more.addEventListener("click", function (ev) { if (ev.target.closest(".btn") && ev.target.id !== "pw-wrap" && ev.target.id !== "pw-src") setMore(false); });
  document.addEventListener("click", function (ev) { if (!ev.target.closest(".pw-toolbar")) setMore(false); });
  document.addEventListener("keydown", function (ev) { if (ev.key === "Escape" && more.classList.contains("open")) { setMore(false); moreBtn.focus(); } });
  function currentLink() { return P.link(id, hash.key, lineFrag()); }
  $("pw-copy").addEventListener("click", function () {
    var b = this, t = doc.b;
    if (selected) t = doc.b.split("\n").slice(selected[0] - 1, selected[1]).join("\n");
    P.copy(t).then(function () { P.flash(b, selected ? "Copied the chosen lines" : "Copied!"); });
  });
  $("pw-copylink").addEventListener("click", function () {
    var b = this;
    if (facts.burned) { P.flash(b, "Deleted: link no longer works"); return; }
    P.copy(currentLink()).then(function () { P.flash(b, selected ? "Copied link to the lines" : "Copied!"); });
  });
  var EXT = { javascript: "js", typescript: "ts", python: "py", ruby: "rb", rust: "rs", bash: "sh", csharp: "cs", cpp: "cpp", c: "c", go: "go", java: "java",
    kotlin: "kt", lua: "lua", perl: "pl", php: "php", json: "json", yaml: "yml", xml: "html", css: "css", scss: "scss", sql: "sql", swift: "swift",
    md: "md", diff: "diff", ini: "ini", makefile: "mk", graphql: "graphql", r: "r", vbnet: "vb" };
  function fileName() {
    var base = (doc.t || "pawste-" + id).replace(/[^\w.-]+/g, "-").replace(/^-+|-+$/g, "").slice(0, 60) || "pawste";
    return /\.\w{1,8}$/.test(base) ? base : base + "." + (EXT[lang()] || "txt");
  }
  function blobUrl() { return URL.createObjectURL(new Blob([doc.b], { type: "text/plain;charset=utf-8" })); }
  $("pw-dl").addEventListener("click", function () {
    var a = document.createElement("a"); a.href = blobUrl(); a.download = fileName();
    document.body.appendChild(a); a.click(); a.remove();
  });
  $("pw-raw").addEventListener("click", function () {
    var real = (facts.kind || "e2e") === "none" && !facts.burn && location.hostname === "paw.gmcat.io";
    window.open(real ? "/raw/" + id : blobUrl(), "_blank", "noopener");
  });
  $("pw-wrap").addEventListener("click", function () { wrap = !wrap; this.setAttribute("aria-pressed", String(wrap)); $("pw-body").classList.toggle("wrap", wrap); });
  $("pw-src").addEventListener("click", function () { showSource = !showSource; show(); });
  $("pw-fork").addEventListener("click", function () {
    try { sessionStorage.setItem("pawste-copy", JSON.stringify({ t: doc.t ? doc.t + " (copy)" : "", f: doc.f, b: doc.b })); } catch (e) { P.tell({ title: "Couldn't make a copy", text: "Your browser blocked it. Copy the text instead." }); return; }
    location.href = P.HOME + "?copy=1";
  });
  $("pw-del").addEventListener("click", del);
  function del() {
    P.ask({ title: "Delete this paste?", text: "It's deleted for everyone, and the link stops working. This can't be undone.", ok: "Delete it", danger: true }).then(function (yes) {
      if (yes) reallyDelete();
    });
  }
  function reallyDelete() {
    P.api("DELETE", "/" + id, null, { "X-Edit-Token": editToken }).then(function () {
      P.forget(id);
      say('<h1>Deleted</h1><p>The paste is gone from Pawste. The link won\'t open any more.</p><p><a class="btn" href="' + P.HOME + '">Make a new paste</a></p>');
    }).catch(function (e) { P.tell({ title: "Couldn't delete it", text: e.message }); });
  }

  /* ---------- dialogs ---------- */
  document.addEventListener("click", function (ev) { var c = ev.target.closest("[data-close]"); if (c) c.closest("dialog").close(); });
  document.querySelectorAll("dialog").forEach(function (d) {
    d.addEventListener("click", function (ev) { if (ev.target === d) d.close(); });   // tap outside to close
  });
  $("pw-qrbtn").addEventListener("click", function () {
    if (facts.burned) { P.flash(this, "Deleted: nothing to share"); return; }
    $("pw-qr-box").innerHTML = P.qrSvg(currentLink());
    $("pw-qr-dlg").showModal();
  });

  /* History + changes */
  $("pw-hist").addEventListener("click", function () {
    var sec = $("pw-history"), list = facts.list || [];
    sec.hidden = false;
    var opts = list.map(function (x) { return '<option value="' + x.n + '">Version ' + x.n + " · " + P.when(x.created) + "</option>"; }).join("");
    $("pw-hist-a").innerHTML = opts; $("pw-hist-b").innerHTML = opts;
    var last = list[list.length - 1].n, prev = list[list.length - 2].n;
    $("pw-hist-b").value = String(current && current !== list[0].n ? current : last);
    $("pw-hist-a").value = String(+$("pw-hist-b").value === prev || +$("pw-hist-b").value === last ? prev : list[0].n);
    compare();
    sec.scrollIntoView({ block: "start", behavior: "smooth" });
  });
  $("pw-hist-a").addEventListener("change", compare);
  $("pw-hist-b").addEventListener("change", compare);
  function compare() {
    var a = +$("pw-hist-a").value, b = +$("pw-hist-b").value;
    $("pw-hist-sum").textContent = "Comparing…";
    Promise.all([fetchVersion(a), fetchVersion(b)]).then(function (r) {
      var d = P.diff(r[0].b, r[1].b);
      if (!d) { $("pw-hist-sum").textContent = "These versions are too big to compare here."; $("pw-diff").textContent = ""; return; }
      var add = 0, rem = 0;
      d.forEach(function (x) { if (x.op === "+") add++; else if (x.op === "-") rem++; });
      var titleNote = r[0].t !== r[1].t ? " Title: “" + (r[0].t || "Untitled") + "” → “" + (r[1].t || "Untitled") + "”." : "";
      $("pw-hist-sum").textContent = (add || rem ? add + " line" + (add === 1 ? "" : "s") + " added, " + rem + " removed." : "No changes to the text.") + titleNote;
      // show changed lines with 3 lines of context; fold long unchanged stretches
      var keep = d.map(function () { return false; });
      d.forEach(function (x, i) { if (x.op !== " ") for (var k = Math.max(0, i - 3); k <= Math.min(d.length - 1, i + 3); k++) keep[k] = true; });
      var html = [], skipped = 0, na = 0, nb = 0;
      d.forEach(function (x, i) {
        if (x.op !== "+") na++;
        if (x.op !== "-") nb++;
        if (!keep[i]) { skipped++; return; }
        if (skipped) { html.push('<div class="pw-fold">⋯ ' + skipped + " unchanged line" + (skipped === 1 ? "" : "s") + "</div>"); skipped = 0; }
        var cls = x.op === "+" ? "add" : x.op === "-" ? "rem" : "";
        html.push('<div class="pw-dl ' + cls + '"><span class="pw-dn">' + (x.op === "+" ? "" : na) + '</span><span class="pw-dn">' + (x.op === "-" ? "" : nb) + '</span><span class="pw-dop">' + (x.op === " " ? "" : x.op) + "</span><code>" + (P.esc(x.text) || " ") + "</code></div>");
      });
      if (skipped) html.push('<div class="pw-fold">⋯ ' + skipped + " unchanged line" + (skipped === 1 ? "" : "s") + "</div>");
      $("pw-diff").innerHTML = add || rem ? html.join("") : "";
    }).catch(function (e) { $("pw-hist-sum").textContent = e.message; });
  }

  /* Report */
  $("pw-report").addEventListener("click", function () {
    $("pw-rep-msg").textContent = "";
    $("pw-rep-key").closest("label").hidden = (facts.kind || "e2e") !== "e2e";   // short links can be read without a key
    $("pw-rep-dlg").showModal();
  });
  $("pw-rep-send").addEventListener("click", function () {
    var reason = $("pw-rep-reason").value, msg = $("pw-rep-msg");
    if (!reason) { msg.textContent = "Choose a reason."; return; }
    if (facts.burned) { msg.textContent = "This paste is already deleted."; return; }
    P.api("POST", "/" + id + "/report", { reason: reason, details: $("pw-rep-details").value, link: ($("pw-rep-key").checked || (facts.kind || "e2e") !== "e2e") ? plainLink() : "" }).then(function () {
      msg.textContent = "Thanks. GmCat will take a look.";
      setTimeout(function () { $("pw-rep-dlg").close(); }, 1600);
    }).catch(function (e) { msg.textContent = e.message; });
  });

  /* ---------- snippet picture (drawing lives in pawste-snippet.js) ---------- */
  function drawPic() {
    var total = doc.b.split("\n").length;
    var from = Math.max(1, Math.min(total, +$("pw-pic-from").value || 1));
    var to = Math.max(from, Math.min(total, +$("pw-pic-to").value || from, from + 59));
    P.snippet.draw($("pw-pic-canvas"), { text: doc.b, lang: lang(), title: $("pw-pic-title").checked ? doc.t : "", from: from, to: to,
      theme: $("pw-pic-theme").value, nums: $("pw-pic-nums").checked, onLogo: function () { if ($("pw-pic-dlg").open) drawPic(); } });
  }
  $("pw-pic").addEventListener("click", function () {
    var total = doc.b.split("\n").length;
    $("pw-pic-from").max = $("pw-pic-to").max = total;
    $("pw-pic-from").value = selected ? selected[0] : 1;
    $("pw-pic-to").value = selected ? selected[1] : Math.min(total, 30);
    $("pw-pic-title").parentElement.hidden = !doc.t;
    $("pw-pic-dlg").showModal();
    drawPic();
  });
  ["pw-pic-from", "pw-pic-to", "pw-pic-theme", "pw-pic-nums", "pw-pic-title"].forEach(function (k) { $(k).addEventListener("input", drawPic); $(k).addEventListener("change", drawPic); });
  $("pw-pic-save").addEventListener("click", function () {
    $("pw-pic-canvas").toBlob(function (b) {
      var a = document.createElement("a"); a.href = URL.createObjectURL(b); a.download = fileName().replace(/\.\w+$/, "") + "-snippet.png";
      document.body.appendChild(a); a.click(); a.remove();
    }, "image/png");
  });
  $("pw-pic-copy").addEventListener("click", function () {
    var btn = this;
    if (!(navigator.clipboard && window.ClipboardItem)) { P.flash(btn, "Not supported here: use Download"); return; }
    var blob = new Promise(function (res) { $("pw-pic-canvas").toBlob(res, "image/png"); });
    navigator.clipboard.write([new ClipboardItem({ "image/png": blob })]).then(function () { P.flash(btn, "Copied picture!"); }, function () { P.flash(btn, "Couldn't copy: use Download"); });
  });
})();
