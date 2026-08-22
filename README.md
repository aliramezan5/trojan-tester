# ⚡ V2Ray & Trojan Tester v1.1

A privacy-hardened proxy tester with two distinct modes:

- **Quick Scan (browser):** conservative endpoint reachability only. It does **not** claim a proxy is working.
- **Real Verify (optional backend):** actual proxy traffic through `sing-box`, with repeated attempts and a score.

Live frontend: `https://aliramezan5.github.io/trojan-tester/`

## v1.1 changes
- Removed fast-error false positives and the old SNI-as-endpoint assumption.
- Quick Scan reports **Reachable / Uncertain / Failed**; only backend verification can report **Verified**.
- Structured parsing for VLESS, Trojan, VMess, Hysteria2, Shadowsocks and TUIC.
- Structural SHA-256 fingerprints for dedup/cache; secrets are excluded from the cache key.
- Source persistence is opt-in; backend token is session-only.
- No public CORS proxy fallback. The optional backend has an SSRF-hardened subscription proxy.
- QR is generated locally. Deployment fetches QRCode.js from an immutable pinned revision, verifies its Git blob SHA, and serves it from the app's own origin; there is no runtime third-party QR request.
- IndexedDB cache/history, corrected Select Visible behavior, PWA support, iPhone-focused responsive UI.
- Optional `sing-box` Real Verify backend with rate limits, private/reserved network blocking, fixed test destinations, repeated attempts, exit IP and a small throughput probe.

## Development
Requires Node.js 20+ for tests/checks; the frontend itself is static.
```bash
npm test
npm run check
```

## Local Windows usage
- `start-server.bat` prepares and verifies the pinned local QR vendor and starts the frontend.
- `start-all.bat` starts the frontend plus the pinned/verified Cloudflare Quick Tunnel.
- `start-backend.bat` runs the optional Real Verify backend if Node.js and `sing-box` are installed.

## Real Verify backend
See [`backend/README.md`](backend/README.md). GitHub Pages cannot run `sing-box`, so public Real Verify requires a container host.

### One-click Render deployment
The repository includes [`render.yaml`](render.yaml) for a Docker web service in Frankfurt with `/health`, CORS restricted to the GitHub Pages origin, rate limits, private/reserved network blocking from the backend, and an automatically generated bearer token.

Deploy from: `https://render.com/deploy?repo=https://github.com/aliramezan5/trojan-tester`

After Render finishes:
1. Copy the service HTTPS URL into **Backend URL** in the app.
2. Copy the generated `TT_API_TOKEN` from Render into **Backend Token**.
3. Press **بررسی Backend**, then **Real Verify**.

The free Render instance is suitable for testing but can spin down after inactivity. For always-on verification, switch the same service to a paid instance without changing the code.

## Deployment
`.github/workflows/pages.yml` runs tests, builds a static GitHub Pages artifact, fetches the pinned QR dependency, verifies its Git blob SHA, and deploys. This avoids a runtime dependency while keeping the build reproducible and checksum-gated.

## Third-party software
See [`THIRD_PARTY_NOTICES.md`](THIRD_PARTY_NOTICES.md).
