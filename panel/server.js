// Minimal static server for the Playwright suite. Node stdlib only — no dependency.
//
// It exists so tests run against a real http:// origin. That matters: localStorage is
// origin-scoped and `file://` has no usable origin, so the HR-4.7 storage assertions
// would pass vacuously without it. It also sets the real CSP, so a future inline script
// or CDN reference fails the tests rather than only failing review.
//
// Test-only. The panel is served by the Go control plane from Phase 4 (spec §3).

const http = require('http');
const fs = require('fs');
const path = require('path');

const ROOT = path.join(__dirname, 'static');
const PORT = Number(process.env.PORT || 4173);

const TYPES = {
  '.html': 'text/html; charset=utf-8',
  '.js': 'text/javascript; charset=utf-8',
  '.css': 'text/css; charset=utf-8',
};

// HR-9.7, verbatim. Enforced here so the tests exercise the real policy: an inline
// script or a CDN reference is blocked by the browser and the test fails.
const CSP = [
  "default-src 'self'",
  "script-src 'self'",
  "object-src 'none'",
  "base-uri 'none'",
  "frame-ancestors 'none'",
].join('; ');

http
  .createServer((req, res) => {
    const rel = decodeURIComponent(new URL(req.url, 'http://localhost').pathname);

    // Path traversal: resolve, then confirm the result is still inside ROOT.
    // HR-8.3's reasoning applied to our own test server — a confined destination
    // directory is only confined if you check after resolution, not before.
    const file = path.normalize(path.join(ROOT, rel === '/' ? 'audit-keygen.html' : rel));
    if (!file.startsWith(ROOT)) {
      res.writeHead(403).end('forbidden');
      return;
    }

    fs.readFile(file, (err, body) => {
      if (err) {
        res.writeHead(404).end('not found');
        return;
      }
      res.writeHead(200, {
        'Content-Type': TYPES[path.extname(file)] || 'application/octet-stream',
        'Content-Security-Policy': CSP,
        'X-Content-Type-Options': 'nosniff',
        'Cache-Control': 'no-store',
      });
      res.end(body);
    });
  })
  .listen(PORT, '127.0.0.1', () => {
    console.log(`static server on http://127.0.0.1:${PORT}`);
  });
