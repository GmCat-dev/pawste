/* Code to Image (paw.gmcat.io/code-to-image/): draws the code as a picture on this device with Pawste's snippet renderer.
   Nothing is uploaded unless the visitor chooses "Share the code as a paste". */
(function () {
  "use strict";
  var P = window.Pawste, $ = function (id) { return document.getElementById(id); };
  var text = $("cti-text"), lang = $("cti-lang"), status = $("cti-status");
  var KEY = "pawste-cti";
  P.LANGS.forEach(function (l) {
    if (l[0] === "md") return;
    var o = document.createElement("option"); o.value = l[0]; o.textContent = l[1]; lang.appendChild(o);
  });
  try {   // keep the visitor's last code and settings in this browser
    var saved = JSON.parse(localStorage.getItem(KEY) || "null");
    if (saved && typeof saved.b === "string") {
      text.value = saved.b; $("cti-title").value = saved.t || ""; lang.value = saved.l || "auto"; $("cti-theme").value = saved.s || "night";
      $("cti-nums").checked = saved.n !== false;
      if (!lang.value) lang.value = "auto";
    }
  } catch (e) { /* storage off */ }

  var timer;
  function draw() {
    var l = lang.value === "auto" ? P.detect(text.value) : lang.value, total = Math.max(1, text.value.split("\n").length);
    $("cti-from").max = $("cti-to").max = total;
    P.snippet.draw($("cti-canvas"), { text: text.value || " ", lang: l === "md" ? "markdown" : l, title: $("cti-title").value.trim(),
      from: +$("cti-from").value || 1, to: +$("cti-to").value || 60, theme: $("cti-theme").value, nums: $("cti-nums").checked, onLogo: draw });
    try { localStorage.setItem(KEY, JSON.stringify({ b: text.value.slice(0, 20000), t: $("cti-title").value, l: lang.value, s: $("cti-theme").value, n: $("cti-nums").checked })); } catch (e) { /* full */ }
  }
  function soon() { clearTimeout(timer); timer = setTimeout(draw, 150); }
  ["cti-text", "cti-title", "cti-from", "cti-to"].forEach(function (k) { $(k).addEventListener("input", soon); });
  ["cti-lang", "cti-theme", "cti-nums"].forEach(function (k) { $(k).addEventListener("change", draw); });
  text.addEventListener("keydown", function (ev) {   // Tab inserts spaces (Esc first to leave the box with Tab)
    if (ev.key === "Tab" && !ev.shiftKey && !text.dataset.esc) { ev.preventDefault(); text.setRangeText("    ", text.selectionStart, text.selectionEnd, "end"); soon(); }
    text.dataset.esc = ev.key === "Escape" ? "1" : "";
  });

  function fileName() { return ($("cti-title").value.trim() || "code").replace(/[^\w.-]+/g, "-").replace(/\.\w+$/, "").slice(0, 50) + "-pawste.png"; }
  $("cti-save").addEventListener("click", function () {
    $("cti-canvas").toBlob(function (b) {
      var a = document.createElement("a"); a.href = URL.createObjectURL(b); a.download = fileName();
      document.body.appendChild(a); a.click(); a.remove();
    }, "image/png");
  });
  $("cti-copy").addEventListener("click", function () {
    var btn = this;
    if (!(navigator.clipboard && window.ClipboardItem)) { P.flash(btn, "Not supported here: use Download"); return; }
    var blob = new Promise(function (res) { $("cti-canvas").toBlob(res, "image/png"); });
    navigator.clipboard.write([new ClipboardItem({ "image/png": blob })]).then(function () { P.flash(btn, "Copied picture!"); }, function () { P.flash(btn, "Couldn't copy: use Download"); });
  });
  $("cti-paste").addEventListener("click", function () {
    try { sessionStorage.setItem("pawste-copy", JSON.stringify({ t: $("cti-title").value.trim(), f: lang.value, b: text.value })); }
    catch (e) { P.tell({ title: "Couldn't hand the code over", text: "Your browser blocked it. Copy the code into a new paste instead." }); return; }
    location.href = P.HOME + "?copy=1";
  });
  draw();
  if (document.fonts && document.fonts.ready) document.fonts.ready.then(draw);
  status.textContent = "";
})();
