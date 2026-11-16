/* Pawste snippet pictures: draws highlighted code on a canvas, on the device (used by the reader and Code to Image).
   Needs pawste-core.js (and highlight.js for colours). */
(function () {
  "use strict";
  var P = window.Pawste;
  var THEMES = {
    night: { bg: ["#1d1530", "#3a2a5c"], card: "#120e1c", text: "#ece6f7", dim: "#7d7393", title: "#f2a582",
      tok: { keyword: "#f28fb0", built_in: "#8fb6ef", type: "#8fd6c5", literal: "#f5c967", number: "#f5c967", string: "#9fe0a5", regexp: "#9fe0a5", comment: "#7d7393", meta: "#b8bff0",
        title: "#8fb6ef", "title.function": "#8fb6ef", "title.class": "#8fd6c5", attr: "#f2a582", attribute: "#f2a582", variable: "#ece6f7", params: "#ece6f7", tag: "#f28fb0", name: "#f28fb0",
        section: "#f2a582", bullet: "#f5c967", link: "#8fb6ef", symbol: "#f5c967", addition: "#9fe0a5", deletion: "#f28fb0", strong: "#ffffff", emphasis: "#ece6f7", quote: "#a9a0bb", property: "#8fb6ef" } },
    day: { bg: ["#fde9dc", "#e3e0fb"], card: "#fffdfa", text: "#2f2340", dim: "#9d93ad", title: "#c2552c",
      tok: { keyword: "#b0306a", built_in: "#2f5bb5", type: "#157266", literal: "#94640f", number: "#94640f", string: "#2f7d4f", regexp: "#2f7d4f", comment: "#9d93ad", meta: "#5f56b8",
        title: "#2f5bb5", "title.function": "#2f5bb5", "title.class": "#157266", attr: "#c2552c", attribute: "#c2552c", variable: "#2f2340", params: "#2f2340", tag: "#b0306a", name: "#b0306a",
        section: "#c2552c", bullet: "#94640f", link: "#2f5bb5", symbol: "#94640f", addition: "#2f7d4f", deletion: "#b0306a", strong: "#000000", emphasis: "#2f2340", quote: "#6c6181", property: "#2f5bb5" } },
    mint: { bg: ["#0f1918", "#1f8f80"], card: "#0b1413", text: "#e6f2ef", dim: "#6f8a86", title: "#6fd6c5",
      tok: { keyword: "#6fd6c5", built_in: "#8fb6ef", type: "#c9b6ff", literal: "#ffd27a", number: "#ffd27a", string: "#b6f09c", regexp: "#b6f09c", comment: "#6f8a86", meta: "#8fd6c5",
        title: "#8fd0ff", "title.function": "#8fd0ff", "title.class": "#c9b6ff", attr: "#ffb38a", attribute: "#ffb38a", variable: "#e6f2ef", params: "#e6f2ef", tag: "#6fd6c5", name: "#6fd6c5",
        section: "#6fd6c5", bullet: "#ffd27a", link: "#8fd0ff", symbol: "#ffd27a", addition: "#b6f09c", deletion: "#ff9aa8", strong: "#ffffff", emphasis: "#e6f2ef", quote: "#93aaa6", property: "#8fd0ff" } },
    sunset: { bg: ["#ef9a76", "#8a62c4"], card: "#22182e", text: "#fbefe9", dim: "#9a8aa8", title: "#ffc08f",
      tok: { keyword: "#ff9cc0", built_in: "#ffc08f", type: "#b5e3ff", literal: "#ffe08a", number: "#ffe08a", string: "#c4f0a8", regexp: "#c4f0a8", comment: "#9a8aa8", meta: "#d9c4ff",
        title: "#b5e3ff", "title.function": "#b5e3ff", "title.class": "#ffc08f", attr: "#ffc08f", attribute: "#ffc08f", variable: "#fbefe9", params: "#fbefe9", tag: "#ff9cc0", name: "#ff9cc0",
        section: "#ffc08f", bullet: "#ffe08a", link: "#b5e3ff", symbol: "#ffe08a", addition: "#c4f0a8", deletion: "#ff9cc0", strong: "#ffffff", emphasis: "#fbefe9", quote: "#c9b8d6", property: "#b5e3ff" } }
  };
  var logo = new Image(), logoWaiters = [];
  logo.onload = function () { logoWaiters.splice(0).forEach(function (f) { f(); }); };
  logo.src = "/img/favicon.png";

  function tokenLines(text, l, from, to) {
    /* -> [[{text, cls}]] for lines from..to (1-based), using the same highlighter as the page */
    var src = text.split("\n").slice(from - 1, to).join("\n"), html = P.esc(src);
    if (window.hljs && l !== "text" && hljs.getLanguage(l === "md" ? "markdown" : l)) {
      try { html = hljs.highlight(src, { language: l === "md" ? "markdown" : l, ignoreIllegals: true }).value; } catch (e) { /* plain */ }
    }
    return P.splitLines(html).map(function (h) {
      var box = document.createElement("div"), out = [];
      box.innerHTML = h;
      (function walk(node, cls) {
        node.childNodes.forEach(function (c) {
          if (c.nodeType === 3) out.push({ text: c.nodeValue, cls: cls });
          else {
            var own = (c.className || "").split(/\s+/).filter(function (x) { return x.indexOf("hljs-") === 0; }).map(function (x) { return x.slice(5).replace(/_$/, ""); });
            var sub = c.className && /hljs-title/.test(c.className) && /function_|class_/.test(c.className) ? "title." + (/function_/.test(c.className) ? "function" : "class") : own[0];
            walk(c, sub || cls);
          }
        });
      })(box, "");
      return out;
    });
  }

  /* draw(canvas, {text, lang, title, from, to, theme, nums, onLogo}) — lines from..to (1-based, at most 60) */
  function draw(cv, o) {
    var total = o.text.split("\n").length;
    var from = Math.max(1, Math.min(total, o.from || 1)), to = Math.max(from, Math.min(total, o.to || total, from + 59));
    var th = THEMES[o.theme] || THEMES.night, nums = !!o.nums, showTitle = !!o.title;
    if (!(logo.complete && logo.naturalWidth) && o.onLogo) logoWaiters.push(o.onLogo);
    var lines = tokenLines(o.text, o.lang, from, to).map(function (toks) {   // tabs -> 4 spaces, cut very long lines
      var len = 0, outT = [];
      toks.forEach(function (t) {
        var s = t.text.replace(/\t/g, "    ");
        if (len >= 100) return;
        if (len + s.length > 100) s = s.slice(0, 100 - len - 1) + "…";
        len += s.length; outT.push({ text: s, cls: t.cls });
      });
      return { toks: outT, len: len };
    });
    // trim the shared indent so the picture isn't mostly empty space
    var indent = Math.min.apply(null, lines.filter(function (x) { return x.len && x.toks.map(function (t) { return t.text; }).join("").trim(); }).map(function (x) {
      return x.toks.map(function (t) { return t.text; }).join("").match(/^ */)[0].length;
    }).concat([999]));
    if (indent && indent < 999) lines.forEach(function (x) {
      var cut = indent;
      x.toks.forEach(function (t) { var m = Math.min(cut, t.text.match(/^ */)[0].length); t.text = t.text.slice(m); cut -= m; });
      x.len = Math.max(0, x.len - indent);
    });
    var cols = Math.max(32, Math.max.apply(null, lines.map(function (x) { return x.len; })) + (nums ? String(to).length + 2 : 0));
    var W = 1200, pad = 64, cardPad = 36, inner = W - pad * 2 - cardPad * 2;
    var fs = Math.max(12, Math.min(24, Math.floor(inner / (cols * 0.602))));
    var lh = Math.round(fs * 1.55), head = 64 + (showTitle ? 0 : 0), foot = 70;
    var H = pad + head + lines.length * lh + cardPad * 2 + foot;
    var dpr = 2;
    cv.width = W * dpr; cv.height = H * dpr; cv.style.aspectRatio = W + " / " + H;
    var g = cv.getContext("2d");
    g.setTransform(dpr, 0, 0, dpr, 0, 0);
    var grad = g.createLinearGradient(0, 0, W, H);
    grad.addColorStop(0, th.bg[0]); grad.addColorStop(1, th.bg[1]);
    g.fillStyle = grad; g.fillRect(0, 0, W, H);
    // card
    var cx = pad, cy = pad * 0.75, cw = W - pad * 2, ch = head + lines.length * lh + cardPad * 1.6;
    g.save(); g.shadowColor = "rgba(0,0,0,.28)"; g.shadowBlur = 40; g.shadowOffsetY = 14;
    g.fillStyle = th.card; roundRect(g, cx, cy, cw, ch, 18); g.fill(); g.restore();
    // window dots: pixel squares in GmCat colors
    ["#ef9a76", "#f5c967", "#72d49a"].forEach(function (c, i) { g.fillStyle = c; g.fillRect(cx + 26 + i * 24, cy + 26, 12, 12); });
    g.font = "600 17px 'DM Sans', system-ui, sans-serif"; g.fillStyle = th.dim; g.textBaseline = "middle";
    var label = showTitle ? o.title : P.langName(o.lang);
    if (label.length > 70) label = label.slice(0, 69) + "…";
    g.textAlign = "center"; g.fillStyle = showTitle ? th.title : th.dim; g.fillText(label, cx + cw / 2, cy + 32); g.textAlign = "left";
    // code
    var mono = fs + "px ui-monospace, 'SF Mono', Menlo, Consolas, 'Liberation Mono', monospace";
    g.font = mono; g.textBaseline = "alphabetic";
    var gutter = nums ? g.measureText(String(to) + "  ").width : 0, y = cy + head + fs;
    lines.forEach(function (ln, i) {
      var x = cx + cardPad;
      if (nums) { g.fillStyle = th.dim; g.textAlign = "right"; g.fillText(String(from + i), x + gutter - g.measureText("  ").width, y); g.textAlign = "left"; }
      x += gutter;
      ln.toks.forEach(function (t) {
        g.fillStyle = th.tok[t.cls] || th.tok[(t.cls || "").split(".")[0]] || th.text;
        g.fillText(t.text, x, y);
        x += g.measureText(t.text).width;
      });
      y += lh;
    });
    // footer mark
    var fy = H - foot / 2 - 4;
    if (logo.complete && logo.naturalWidth) { g.imageSmoothingEnabled = false; g.drawImage(logo, W - pad - 34, fy - 17, 34, 34); g.imageSmoothingEnabled = true; }
    g.font = "700 18px 'DM Sans', system-ui, sans-serif"; g.textAlign = "right"; g.textBaseline = "middle";
    g.fillStyle = "rgba(255,255,255,.92)";
    if (o.theme === "day") g.fillStyle = "#2f2340";
    g.fillText("Pawste · " + (P.LINK_HOST.indexOf("gmcat.io") !== -1 ? P.LINK_HOST : "tools.gmcat.io"), W - pad - 46, fy);
    g.textAlign = "left";
    if (total > 1) { g.font = "500 15px 'DM Sans', system-ui, sans-serif"; g.globalAlpha = .8; g.fillText(to - from + 1 < total ? "Lines " + from + "–" + to + " of " + total : total + " lines", pad, fy); g.globalAlpha = 1; }
  }
  function roundRect(g, x, y, w, h, r) {
    g.beginPath(); g.moveTo(x + r, y); g.arcTo(x + w, y, x + w, y + h, r); g.arcTo(x + w, y + h, x, y + h, r); g.arcTo(x, y + h, x, y, r); g.arcTo(x, y, x + w, y, r); g.closePath();
  }
  P.snippet = { draw: draw, THEMES: THEMES };
})();
