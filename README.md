# postern

> [!WARNING]
> This project was vibe-coded by an AI using [private-landing](https://github.com/vhscom/private-landing) as a reference implementation. It is an experiment in reproducing a full auth system in minimal Go and is **not intended for production use**.

Single-binary auth server with session management, an operational API, adaptive proof-of-work challenges, and an optional control proxy. Pure Go, no CGO, SQLite embedded.

## Quick start

```bash
export JWT_ACCESS_SECRET=your-access-secret
export JWT_REFRESH_SECRET=your-refresh-secret
go build -o postern && ./postern
```

Open `http://localhost:8080` to register and log in.

## Environment variables

| Variable | Required | Default | Description |
|---|---|---|---|
| `JWT_ACCESS_SECRET` | yes | | HMAC-SHA256 key for access tokens |
| `JWT_REFRESH_SECRET` | yes | | HMAC-SHA256 key for refresh tokens |
| `ADDR` | no | `:8080` | Listen address |
| `DB_PATH` | no | `postern.db` | SQLite database file path |
| `ENVIRONMENT` | no | `development` | Set `production` for secure cookies |
| `AGENT_PROVISIONING_SECRET` | no | | Enables `/ops` surface when set |
| `GATEWAY_URL` | no | | Upstream URL for control proxy |
| `GATEWAY_TOKEN` | no | | Token injected into control proxy WebSocket frames |
| `WS_ALLOWED_ORIGINS` | no | | Comma-separated origin allowlist for browser WebSocket connections |
| `CONTROL_ALLOWED_IPS` | no | | Comma-separated IP allowlist for control proxy access |

## Routes

**Public**
- `GET /` — Login/register UI
- `GET /health` — Health check (pings database)

**Auth lifecycle**
- `POST /auth/register` — Create account
- `POST /auth/login` — Authenticate (adaptive PoW when under attack)
- `POST /auth/logout` — End session

**Account management** (authenticated)
- `POST /account/password` — Change password (revokes all sessions)
- `GET /account/me` — Current user info

**Ops surface** (hidden when `AGENT_PROVISIONING_SECRET` is absent)
- `POST /ops/agents` — Provision agent key (requires provisioning secret)
- `DELETE /ops/agents/{name}` — Revoke agent
- `GET /ops/agents` — List agents (requires agent key)
- `GET /ops/sessions` — Query sessions
- `POST /ops/sessions/revoke` — Revoke sessions (requires write trust)
- `GET /ops/events` — Query security events
- `GET /ops/events/stats` — Event type counts
- `GET /ops/ws` — WebSocket (Bearer for agents, Cookie for control bridge)

## Docker

```bash
docker build -t postern .
docker run -p 8080:8080 \
  -e JWT_ACCESS_SECRET=secret1 \
  -e JWT_REFRESH_SECRET=secret2 \
  postern
```

## Cross-compile

No C compiler required. Pure Go SQLite via `modernc.org/sqlite`.

```bash
GOOS=linux GOARCH=amd64 go build -o postern
GOOS=linux GOARCH=arm64 go build -o postern
GOOS=darwin GOARCH=arm64 go build -o postern
```

## Testing

```bash
go test ./...
```

## Architecture

12 Go files in a single `package main`:

| File | Responsibility |
|---|---|
| `main.go` | Config, routes, server lifecycle |
| `db.go` | SQLite init, schema migrations |
| `auth.go` | Register, login, logout, password change |
| `session.go` | Session CRUD, sliding expiry, max enforcement |
| `crypto.go` | PBKDF2-SHA384, JWT, API key hashing |
| `events.go` | Security event logging, adaptive PoW, realtime broadcast |
| `middleware.go` | Auth, rate limiting, security headers, access logging |
| `respond.go` | Content negotiation, validation, cookies, helpers |
| `ops.go` | Agent and event/session query handlers |
| `ws.go` | Agent WebSocket protocol, subscriptions |
| `bridge.go` | Control proxy WebSocket bridge |
| `proxy.go` | Control proxy HTTP reverse proxy |

## Security

- PBKDF2-SHA384 with 210,000 iterations (OWASP 2025)
- JWT dual-token pattern (15-minute access, 7-day refresh)
- Constant-time comparison for all secret material
- Adaptive proof-of-work challenges on brute-force detection
- Full session revocation on password change
- OWASP security headers
- Rate limiting on all auth endpoints
- `/ops` surface cloaked as 404 when disabled
