# Real Verify backend

This optional backend runs actual proxy traffic through `sing-box`. GitHub Pages cannot run this component.

## Security model
- Optional bearer token via `TT_API_TOKEN` (strongly recommended on the public internet).
- Origin allow-list via `TT_ALLOWED_ORIGINS`.
- Per-IP rate limiting and maximum 20 configs/request by default.
- `X-Forwarded-For` is ignored unless `TT_TRUST_PROXY=true` is explicitly set behind a controlled reverse proxy.
- Proxy endpoints are DNS-resolved before use and private/reserved IPs are rejected.
- The resolved public IP is pinned into the temporary sing-box config to reduce DNS-rebinding risk.
- Subscription proxy accepts HTTPS/443 only, re-validates every redirect, pins validated DNS, limits redirects and caps response size at 2 MiB.
- The test destination is fixed by the server; clients cannot turn the endpoint into a generic port scanner.
- Temporary sing-box configs are mode 0600 and deleted after each test. Raw URIs are not logged.

## Railway
The repository root contains `railway.toml`, which builds `backend/Dockerfile` and uses `/health` as the deployment health check.

Required production setup in Railway Variables:
```text
TT_API_TOKEN=<long-random-secret>
TT_ALLOWED_ORIGINS=https://aliramezan5.github.io
TT_RATE_LIMIT=12
TT_MAX_BATCH=20
TT_VERIFY_CONCURRENCY=4
TT_TRUST_PROXY=false
```

Railway injects `PORT` automatically and the backend already listens on `0.0.0.0`. Generate a public domain under **Settings → Networking** and use that HTTPS URL in the frontend's **Backend URL** field.

For proxy verification, use a Railway **Full Trial** or paid plan with normal outbound networking. A Limited Trial can restrict outbound traffic and make valid proxy configurations appear to fail.

## Local Docker
```bash
docker compose -f backend/docker-compose.yml up -d --build
```
Put a TLS reverse proxy in front of `127.0.0.1:8787` and set the resulting HTTPS URL in the frontend.

## Environment
| variable | default | purpose |
|---|---|---|
| `TT_API_TOKEN` | empty | Bearer token; set in production |
| `TT_ALLOWED_ORIGINS` | GitHub Pages + localhost | CORS allow-list |
| `TT_RATE_LIMIT` | `12` | requests/minute/IP |
| `TT_MAX_BATCH` | `20` | max configs per verify request |
| `TT_VERIFY_CONCURRENCY` | `4` | concurrent isolated sing-box workers |
| `TT_TRUST_PROXY` | `false` | trust X-Forwarded-For only behind a controlled reverse proxy |
| `SING_BOX_BIN` | `sing-box` | binary path |

## Endpoints
- `GET /health`
- `GET /api/subscription?url=https://...`
- `POST /api/verify`

Real Verify performs three attempts by default through an isolated local SOCKS inbound, records proxy handshake, destination TLS, HTTP TTFB, Cloudflare exit IP, and a small fixed throughput probe. A config is `verified` when at least two of three attempts succeed.
