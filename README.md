# ⚡ V2Ray & Trojan Tester v1.1

A privacy-hardened proxy tester with two distinct modes:

- **Quick Scan (browser):** conservative endpoint reachability only. It does **not** claim a proxy is working.
- **Real Verify (optional backend):** actual proxy traffic through `sing-box`, with repeated attempts and a score.

Live frontend: `https://aliramezan5.github.io/trojan-tester/`
Live Railway backend: `https://trojan-tester-production.up.railway.app`

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

### Railway deployment
The repository includes [`railway.toml`](railway.toml). Railway builds `backend/Dockerfile`, checks `/health`, and restarts failed deployments automatically.

Current Railway trial: up to 30 days with a one-time $5 credit for new accounts. For this project, use the **Full Trial** by connecting/verifying the Railway account with GitHub; the Limited Trial restricts outbound networking and can prevent proxy verification from working correctly.

Deploy steps:
1. Open `https://railway.com/new` and choose **Deploy from GitHub repo**.
2. Select `aliramezan5/trojan-tester`.
3. In the service **Variables** tab add:
   - `TT_API_TOKEN=<a-long-random-secret>`
   - `TT_ALLOWED_ORIGINS=https://aliramezan5.github.io`
   - `TT_RATE_LIMIT=12`
   - `TT_MAX_BATCH=20`
   - `TT_VERIFY_CONCURRENCY=4`
   - `TT_TRUST_PROXY=false`
4. Railway injects `PORT` automatically; do not hard-code it.
5. In **Settings → Region**, prefer **EU West / Amsterdam** for this deployment.
6. In **Settings → Networking**, generate or keep the public domain.
7. Current backend URL: `https://trojan-tester-production.up.railway.app`
8. Put the same `TT_API_TOKEN` into **Backend Token**, press **بررسی Backend**, then **Real Verify**.

When running on Railway, the backend reads Railway's trusted `X-Real-IP` header for per-client rate limiting. `TT_TRUST_PROXY` can therefore remain `false` unless the service is later placed behind another controlled proxy.

Once the GitHub repository is connected, pushes to the tracked branch can auto-deploy through Railway.

## Deployment
`.github/workflows/pages.yml` runs tests, builds a static GitHub Pages artifact, fetches the pinned QR dependency, verifies its Git blob SHA, and deploys. This avoids a runtime dependency while keeping the build reproducible and checksum-gated.

## Third-party software
See [`THIRD_PARTY_NOTICES.md`](THIRD_PARTY_NOTICES.md).
