/* Pawste editor (paw.gmcat.io/, also tools.gmcat.io/pawste/). Modes:
   new paste (default) · copy of another paste (?copy=1, text handed over in sessionStorage) · edit (?edit=<id>#[<key>&]e=<token>)
   Link types: private (kind e2e, key in the link) · short (kind none, not encrypted) · short + password (kind pw). */
(function () {
  "use strict";
  var P = window.Pawste, $ = function (id) { return document.getElementById(id); };
  var text = $("pw-text"), fmt = $("pw-format"), title = $("pw-title"), err = $("pw-err");
  var DRAFT = "pawste-draft", params = new URLSearchParams(location.search);
  var editing = null;   // {id, kind, key, edit, password}
  var hits = [];
  var HOME = location.pathname.indexOf("/pawste/") === 0 ? "/pawste/" : "/";
  var SECRET = $("pw-editor").dataset.preset === "secret";   // Secure Note page: always private, burn on
  if (SECRET) $("pw-kind").hidden = true;
  function isShort() { if (SECRET) return false; var r = document.querySelector('input[name="pw-kind"]:checked'); return !!r && r.value === "short"; }
  function labels() {
    var short = isShort() && !editing, pw = $("pw-usepw").checked;
    $("pw-pw-hint").textContent = short ? "Locks the short link after all: GmCat can't read it without the password. Pick a strong one." : "Readers need the link and the password";
    if (!editing && !SECRET) $("pw-go").textContent = short && !pw ? "Get short link" : "Lock & get link";
    $("pw-guard-short").hidden = !(short && !pw);
    document.querySelectorAll(".pw-kind-opt").forEach(function (l) { l.classList.toggle("on", l.querySelector("input").checked); });
  }
  document.querySelectorAll('input[name="pw-kind"]').forEach(function (r) { r.addEventListener("change", labels); });
  $("pw-to-private").addEventListener("click", function () { document.querySelector('input[name="pw-kind"][value="private"]').checked = true; labels(); });

  P.LANGS.forEach(function (l) { var o = document.createElement("option"); o.value = l[0]; o.textContent = l[1]; fmt.appendChild(o); });

  function showErr(msg) { err.textContent = msg || ""; }
  function note(msg) { $("pw-note").hidden = !msg; $("pw-note").textContent = msg || ""; }

  /* ---------- counting, detection, Leak Guard ---------- */
  var scanTimer;
  function update() {
    var n = P.bytes(text.value);
    $("pw-count").textContent = P.size(n) + " of 512 KB";
    $("pw-count").classList.toggle("over", n > P.MAX_BYTES);
    clearTimeout(scanTimer);
    scanTimer = setTimeout(function () {
      if (fmt.value === "auto" && text.value.trim()) $("pw-detected").textContent = "Looks like: " + P.langName(P.detect(text.value));
      else $("pw-detected").textContent = "";
      hits = P.scan(text.value);
      var list = $("pw-guard-list");
      list.textContent = "";
      var counts = {};
      hits.forEach(function (h) { counts[h.type] = (counts[h.type] || 0) + 1; });
      Object.keys(counts).forEach(function (k) {
        var li = document.createElement("li");
        var sample = hits.filter(function (h) { return h.type === k; })[0].text.replace(/\s+/g, " ");
        li.innerHTML = "<b>" + P.esc(k) + "</b>" + (counts[k] > 1 ? " ×" + counts[k] : "") + ' <code>' + P.esc(sample.slice(0, 6) + (sample.length > 10 ? "…" : "")) + "</code>";
        list.appendChild(li);
      });
      $("pw-guard").hidden = !hits.length || SECRET;   // secure note: sharing a secret is the point
      try { if (!editing && !SECRET) sessionStorage.setItem(DRAFT, JSON.stringify({ t: title.value, f: fmt.value, b: text.value })); } catch (e) { /* full */ }
    }, 250);
  }
  text.addEventListener("input", update);
  title.addEventListener("input", update);
  fmt.addEventListener("change", update);
  $("pw-hide-all").addEventListener("click", function () {
    hits = P.scan(text.value);
    text.value = P.redact(text.value, hits);
    update();
    text.focus();
  });
  /* Tab inserts two spaces (Shift+Tab or Esc then Tab still leaves the box for keyboard users) */
  var escPressed = false;
  text.addEventListener("keydown", function (ev) {
    if (ev.key === "Escape") { escPressed = true; return; }
    if (ev.key === "Tab" && !ev.shiftKey && !escPressed) {
      ev.preventDefault();
      var s = text.selectionStart, e2 = text.selectionEnd;
      text.setRangeText("  ", s, e2, "end");
      update();
    }
    escPressed = false;
  });

  $("pw-usepw").addEventListener("change", function () { $("pw-pass").hidden = !this.checked; if (this.checked) $("pw-pass").focus(); labels(); });
  $("pw-burn").addEventListener("change", function () { if (this.checked) showErr(""); });
  $("pw-clear").addEventListener("click", function () {
    var clear = function () { text.value = ""; title.value = ""; fmt.value = "auto"; update(); text.focus(); };
    if (!text.value) return clear();
    P.ask({ title: "Clear your paste?", text: "The text and title in the box will be removed.", ok: "Clear it", danger: true }).then(function (yes) { if (yes) clear(); });
  });

  /* ---------- share ---------- */
  var warnedLeak = false;
  $("pw-go").addEventListener("click", function () {
    showErr("");
    var body = text.value, n = P.bytes(body);
    if (!body.trim()) { showErr("Paste something first."); text.focus(); return; }
    if (n > P.MAX_BYTES) { showErr("That's " + P.size(n) + ". Pawste holds up to 512 KB."); return; }
    var usePw = $("pw-usepw").checked && !editing, pw = usePw ? $("pw-pass").value : (editing && editing.password) || "";
    var kind = editing ? editing.kind : isShort() ? (usePw ? "pw" : "none") : "e2e";
    var minPw = kind === "pw" ? 8 : 4;
    if (usePw && pw.length < minPw) { showErr("Choose a password of at least " + minPw + " characters" + (kind === "pw" ? " (it's the only lock on a short link)." : ".")); $("pw-pass").focus(); return; }
    if (!SECRET && P.scan(body).length && !warnedLeak) {
      warnedLeak = true;
      showErr("Leak Guard spotted something that looks private (see above). Press the button again to share anyway.");
      $("pw-guard").scrollIntoView({ block: "center", behavior: "smooth" });
      return;
    }
    var f = fmt.value === "auto" ? P.detect(body) : fmt.value;
    var doc = { t: title.value.trim().slice(0, 120), f: f, b: body };
    var key = kind !== "e2e" ? "" : editing ? editing.key : P.newKey();
    var btn = $("pw-go");
    btn.disabled = true; btn.textContent = "Locking…";
    P.lock(doc, kind, key, pw).then(function (locked) {
      if (editing) return P.api("PUT", "/" + editing.id, locked, { "X-Edit-Token": editing.edit });
      return P.api("POST", "", { hdr: locked.hdr, ct: locked.ct, ttl: +$("pw-ttl").value, burn: $("pw-burn").checked, pw: usePw });
    }).then(function (d) {
      try { sessionStorage.removeItem(DRAFT); } catch (e) { /* ignore */ }
      if (editing) {
        var mine = P.findMine(editing.id);
        if (mine) { mine.title = doc.t; P.remember(mine); }
        location.href = P.link(editing.id, key, "&e=" + editing.edit);
        return;
      }
      P.remember({ id: d.id, key: key, kind: kind, edit: d.edit_token, title: doc.t, created: Math.floor(Date.now() / 1000), expires: d.expires, burn: d.burn, pw: usePw });
      done(d, key, doc, usePw, kind);
    }).catch(function (e) {
      showErr(e.message);
    }).then(function () { btn.disabled = false; if (editing) btn.textContent = "Save new version"; else labels(); warnedLeak = false; });
  });

  function done(d, key, doc, usePw, kind) {
    var link = P.link(d.id, key), edit = P.link(d.id, key, "&e=" + d.edit_token);
    $("pw-link").value = link;
    $("pw-open").href = link;
    $("pw-edit-link").value = edit;
    $("pw-qr").innerHTML = P.qrSvg(link);
    var bits = ["Deleted in " + P.left(d.expires) + "."];
    if (kind === "none") bits.push("🔗 Short link: it isn't encrypted, so anyone with the link can read it, and GmCat could too.");
    if (kind === "pw") bits.push("🔑 Locked with your password: GmCat can't read it without it.");
    if (d.burn) bits.push("🔥 It's deleted the first time it's opened, so don't open it yourself (use the edit link to check it).");
    if (usePw) bits.push("🔑 Send the password separately, for example in a different app.");
    $("pw-done-note").textContent = bits.join(" ");
    $("pw-open").hidden = !!d.burn;
    $("pw-editor").hidden = true;
    $("pw-done").hidden = false;
    $("pw-done").focus();
    $("pw-done").scrollIntoView({ block: "start", behavior: "smooth" });
    text.value = ""; title.value = ""; $("pw-burn").checked = SECRET; $("pw-usepw").checked = false; $("pw-pass").value = ""; $("pw-pass").hidden = true;
    update(); labels();
    renderMine();
  }
  $("pw-copy-link").addEventListener("click", function () { var b = this; P.copy($("pw-link").value).then(function () { P.flash(b); }); });
  $("pw-copy-edit").addEventListener("click", function () { var b = this; P.copy($("pw-edit-link").value).then(function () { P.flash(b); }); });
  $("pw-again").addEventListener("click", function () { $("pw-done").hidden = true; $("pw-editor").hidden = false; text.focus(); });

  /* ---------- this device's pastes ---------- */
  function renderMine() {
    var list = P.mine(), ul = $("pw-mine");
    $("pw-mine-sec").hidden = !list.length;
    ul.textContent = "";
    list.forEach(function (x) {
      var li = document.createElement("li"), link = P.link(x.id, x.key);
      li.innerHTML = '<div><a href="' + P.esc(link) + '">' + P.esc(x.title || "Untitled paste") + "</a>" +
        '<small class="muted">' + P.when(x.created) + " · deleted in " + P.left(x.expires) + (x.kind === "none" ? " · 🔗 short link" : x.kind === "pw" ? " · 🔗 short link 🔑" : " · 🔒 private" + (x.pw ? " 🔑" : "")) + (x.burn ? " · 🔥 burn after reading" : "") + "</small></div>" +
        '<span class="pw-mine-btns"><button class="linkbtn" type="button" data-copy>Copy link</button>' +
        (x.burn ? "" : ' <a class="linkbtn" href="' + HOME + "?edit=" + x.id + P.frag(x.key, "&e=" + x.edit) + '">Edit</a>') + "</span>";
      li.querySelector("[data-copy]").addEventListener("click", function () { var b = this; P.copy(link).then(function () { P.flash(b); }); });
      ul.appendChild(li);
    });
  }
  $("pw-mine-clear").addEventListener("click", function () {
    P.ask({ title: "Forget the list on this device?", text: "The pastes stay online until they expire, but you'll lose their edit links.", ok: "Forget the list", danger: true })
      .then(function (yes) { if (yes) { P.saveMine([]); renderMine(); } });
  });

  /* ---------- start: edit, copy, or a saved draft ---------- */
  function startEdit() {
    var id = params.get("edit"), h = P.parseHash(location.hash);
    if (!P.ID_RE.test(id || "") || !h.edit) { note("This edit link is incomplete. Open the full edit link again."); return; }
    history.replaceState(null, "", HOME + "?edit=" + id);   // keep the key out of the address bar while editing
    note("Loading your paste…");
    P.api("POST", "/" + id + "/open").then(function (d) {
      if (d.burn) throw new Error("Burn-after-reading pastes can't be edited.");
      var kind = d.kind || P.kind(d.hdr);
      if (kind === "e2e" && !h.key) throw new Error("This edit link is missing its key. Open the full edit link again.");
      var ask = function (pw) {
        return P.unlock(d.hdr, d.ct, h.key, pw).then(function (doc) { return { doc: doc, pw: pw }; }, function (e) {
          if (e.message !== "locked" || !P.needsPassword(d.hdr)) throw new Error("This link can't unlock that paste.");
          return P.ask({ title: pw ? "That password didn't work" : "This paste has a password", text: pw ? "Try again." : "Enter it to edit the paste.",
            input: "password", placeholder: "Password", ok: "Unlock" }).then(function (again) {
            if (again === null) throw new Error("Editing needs the password.");
            return ask(again);
          });
        });
      };
      return ask("").then(function (r) {
        editing = { id: id, kind: kind, key: kind === "e2e" ? h.key : "", edit: h.edit, password: r.pw };
        title.value = r.doc.t; text.value = r.doc.b; fmt.value = r.doc.f;
        if (fmt.value !== r.doc.f) fmt.value = "auto";
        note("Editing your paste (version " + d.n + "). Saving keeps the same link and adds a new version to its history.");
        $("pw-go").textContent = "Save new version";
        document.querySelector(".pw-ttl").hidden = true;
        document.querySelector(".pw-checks").hidden = true;
        $("pw-kind").hidden = true;
        $("pw-guard-short").hidden = true;
        $("pw-clear").hidden = true;
        update();
      });
    }).catch(function (e) { note(e.message); });
  }
  if (params.has("edit")) startEdit();
  else {
    var src = null;
    try { src = (SECRET && !params.has("copy")) ? null : JSON.parse(sessionStorage.getItem(params.has("copy") ? "pawste-copy" : DRAFT) || "null"); sessionStorage.removeItem("pawste-copy"); } catch (e) { src = null; }
    if (src && typeof src.b === "string") {
      title.value = String(src.t || ""); text.value = src.b; fmt.value = src.f || "auto";
      if (fmt.value !== src.f) fmt.value = "auto";
      if (params.has("copy")) { note("This is your own copy. Change anything, then lock it to get a new link. The original stays as it was."); history.replaceState(null, "", HOME); }
    }
    update();
  }
  labels();
  renderMine();
})();
