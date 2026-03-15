# postern

WireGuard mesh automation you own completely, in a single binary.

> [!WARNING]
> This project is an experiment in building a full mesh control plane in minimal Go. It is **not yet intended for production use**.

Stop hand-editing WireGuard configs across 6 machines. Postern puts an agent on every node that monitors its environment, keeps the mesh connected, and collaborates with other agents to respond to threats — with built-in auth and billing so you can self-host or run it as a service. One binary, pure Go, no CGO, embedded SQLite.

## Quick start

```bash
# Server setup (generates secrets, writes .env)
postern init
postern serve

# Register and log in (register via web UI at http://localhost:8080, then:)
postern login http://localhost:8080

# Add your first node
postern node add --label gateway

# Invite another machine
postern invite
# On the other machine (joins and starts the agent automatically):
postern join https://postern.example.com <token>
```

Each node runs an agent that handles the rest: endpoint discovery, peer sync, NAT traversal, relay fallback, key rotation, and local environment monitoring.

## Why postern

| | Tailscale | Headscale | Netbird | Postern |
|---|---|---|---|---|
| Control plane | Their servers | Self-hosted | Self-hosted or SaaS | Self-hosted |
| Node software | Tailscale client | Tailscale client | Netbird client | Autonomous agent |
| Relay | Separate DERP fleet | Separate DERP fleet | Separate TURN server | Built into the binary |
| Codebase | ~400K lines | ~50K lines | ~80K lines | ~10K lines |
| Billing | They charge you | N/A | They charge you | Stripe built in |
| TUI dashboard | No | Third-party | No | Included |
| Dependencies | Many | PostgreSQL or SQLite | Many | None (embedded SQLite) |

**You run it, you own it.** The same binary is the server, the agent, the CLI, and the TUI. No SaaS dependency, no external database, no separate relay infrastructure.

Tailscale has clients. Postern has agents. A client follows instructions. An agent acts on your behalf — it discovers its own network environment, maintains its own connections, and reports what it sees back to the mesh.

## Architecture overview

```
                  ┌───────────────────┐
                  │      Server       │
                  │  REST · WS · DB   │
                  └─────┬───────┬─────┘
               WebSocket│       │WebSocket
           ┌────────────┘       └────────────┐
           │                                 │
     ┌─────┴──────┐                    ┌─────┴──────┐
     │  Agent A   │◄── WireGuard UDP ──►  Agent B   │
     │  utun/wg0  │    (direct)        │  utun/wg0  │
     └─────┬──────┘                    └──────┬─────┘
           │      relay fallback when         │
           │      NAT blocks direct           │
           │     ┌──────────────────┐         │
           └────►│  Server (relay)  │◄────────┘
                 └──────────────────┘
```

### Control proxy (optional)

When `GATEWAY_URL` is configured, postern acts as an authenticated reverse proxy to an upstream service.

```
  ┌──────────────┐        ┌──────────────────┐        ┌──────────────┐
  │   Operator   │───────►│     Server       │───────►│   Gateway    │
  │   (browser)  │ cookie │ /ops/control/*   │ proxy  │  (upstream)  │
  │              │        │ /ops/ws (bridge) │        │              │
  └──────────────┘        └──────────────────┘        └──────────────┘
                            uid=1 required
                            GATEWAY_TOKEN injected
                            into WebSocket frames
```

Only the operator (uid=1) can access the control proxy. The server handles auth, injects the gateway token into WebSocket frames, and proxies HTTP and WebSocket traffic to the upstream. The operator never handles the gateway token directly.

## How it works

1. `postern init` generates secrets and writes a `.env` you can review, then `postern serve` starts the server
2. `postern node add --label <name>` generates WireGuard keys, registers the node, and gets a mesh IP
3. `postern join <server> <token>` redeems an invite, writes config, and starts the agent automatically
4. The agent connects via WebSocket, discovers its public endpoint via STUN, and reports it
5. The server pushes peer lists to all connected agents — each agent configures WireGuard automatically
6. When direct NAT traversal fails, agents relay encrypted WireGuard packets through the WebSocket
7. Agents rotate keys periodically and report node health, handshake status, and environment observations
8. The TUI (`postern ctl`) gives you a live view of the mesh — node status, events, and agent reports

## Environment variables

| Variable | Required | Default | Description |
|---|---|---|---|
| `JWT_ACCESS_SECRET` | yes | | HMAC-SHA256 key for access tokens |
| `JWT_REFRESH_SECRET` | yes | | HMAC-SHA256 key for refresh tokens |
| `ADDR` | no | `:8080` | Listen address for user surface |
| `OPS_ADDR` | no | | Listen address for ops surface (e.g. `:9090`) |
| `DB_PATH` | no | `postern.db` | SQLite database file path |
| `ENVIRONMENT` | no | `development` | Set `production` for secure cookies |
| `BASE_URL` | no | `http://localhost:8080` | Public URL for invite links |
| `AGENT_PROVISIONING_SECRET` | no | | Enables ops surface (generated by `postern init`) |
| `GATEWAY_URL` | no | | Upstream URL for control proxy |
| `GATEWAY_TOKEN` | no | | Token injected into control proxy WebSocket frames |
| `WS_ALLOWED_ORIGINS` | no | | Comma-separated origin allowlist for browser WebSocket |
| `CONTROL_ALLOWED_IPS` | no | | Comma-separated IP allowlist for control proxy |
| `STRIPE_SECRET_KEY` | no | | Stripe API key (enables billing) |
| `STRIPE_WEBHOOK_SECRET` | no | | Stripe webhook signing secret |
| `STRIPE_PRICE_PRO_ID` | no | | Stripe price ID for Pro tier |
| `STRIPE_PRICE_TEAM_ID` | no | | Stripe price ID for Team tier |

## Routes

**Public**
- `GET /` — Web UI (login, register, node management)
- `GET /health` — Health check
- `POST /join` — Redeem invite token

**Auth**
- `POST /auth/register` — Create account
- `POST /auth/login` — Authenticate (adaptive PoW under attack)
- `POST /auth/logout` — End session

**Account** (authenticated)
- `GET /account/me` — Current user info
- `POST /account/password` — Change password (revokes all sessions)
- `DELETE /account` — Delete account and all associated data
- `GET /account/nodes` — List nodes
- `POST /account/nodes` — Create node (generates agent key + mesh IP)
- `PUT /account/nodes/{label}` — Update node
- `DELETE /account/nodes/{label}` — Delete node
- `POST /account/nodes/invite` — Generate invite token
- `GET /account/services` — List services (shows access status)
- `POST /account/services` — Register service (operator only)
- `DELETE /account/services/{name}` — Remove service (operator only)
- `POST /account/services/{name}/grant` — Grant user access (operator only)
- `DELETE /account/services/{name}/grant/{user_id}` — Revoke user access (operator only)

**Billing** (when Stripe is configured)
- `POST /account/billing/checkout` — Start checkout
- `POST /account/billing/portal` — Open billing portal
- `POST /webhooks/stripe` — Stripe webhook

**Ops** (separate listener when `OPS_ADDR` is set)
- `POST /ops/agents` — Provision agent (requires provisioning secret)
- `DELETE /ops/agents/{name}` — Revoke agent
- `GET /ops/agents` — List agents
- `GET /ops/sessions` — Query sessions
- `POST /ops/sessions/revoke` — Revoke sessions (write trust)
- `GET /ops/events` — Query security events
- `GET /ops/events/stats` — Event counts
- `GET /ops/subscriptions/{user_id}/history` — Subscription history
- `GET /ops/nodes` — List all nodes
- `GET /ops/ws` — Agent WebSocket (Bearer) / control bridge (Cookie)

## Architecture

```
postern
├── main.go              Server lifecycle, config, routing
├── auth.go              Register, login, logout, password change
├── session.go           Session CRUD, sliding expiry
├── crypto.go            PBKDF2-SHA384, JWT, API key hashing
├── node.go              Node CRUD, mesh IP allocation
├── node_registry.go     In-memory connected nodes, wg.sync broadcast
├── invite.go            Invite token create/redeem
├── billing.go           Stripe checkout, portal, webhooks
├── tier.go              Tier limits (free/pro/team)
├── ws.go                Agent WebSocket protocol, capabilities
├── ws_events.go         Event subscriptions, session queries over WS
├── relay.go             Server-side relay router
├── ops.go               Ops REST handlers
├── events.go            Security event logging, adaptive PoW
├── middleware.go         Auth, rate limiting, security headers
├── respond.go           Content negotiation, cookies, helpers
├── validate.go          Input validation (email, password, label, pubkey, CIDR)
├── db.go                SQLite init, schema
├── bridge.go            Control proxy WebSocket bridge
├── proxy.go             Control proxy HTTP reverse proxy
└── internal/
    ├── agent/           Autonomous node agent (STUN, relay, key rotation, monitoring)
    ├── cli/             CLI commands (init, login, node, invite, join)
    ├── crypto/          Shared cryptographic utilities
    ├── ctl/             TUI dashboard
    ├── api/             API client library
    ├── wgkey/           WireGuard keypair generation
    └── ui/              Shared TUI styles
```

## Docker

```bash
postern init              # generate .env
docker compose up -d      # build and start
docker compose logs -f    # tail logs
```

The compose file persists the database in a named volume. Edit `.env` before starting — see the environment variables table above.

For production behind Cloudflare or a reverse proxy, set:

```
ENVIRONMENT=production
BASE_URL=https://yourdomain.com
WS_ALLOWED_ORIGINS=https://yourdomain.com
```

## Build

No C compiler required. Pure Go SQLite via `modernc.org/sqlite`.

```bash
make build          # local binary
make dist           # cross-compile linux/darwin amd64/arm64
make test           # run tests
```

## Security

- PBKDF2-SHA384 with 210,000 iterations (OWASP 2025)
- JWT dual-token pattern (15-minute access, 7-day refresh)
- Constant-time comparison for all secret material
- Adaptive proof-of-work challenges on brute-force detection
- Full session revocation on password change
- OWASP security headers
- Rate limiting on all auth endpoints
- Ops surface cloaked as 404 when disabled
- Relay forwards opaque WireGuard-encrypted packets (zero knowledge)
- Agent keys are 256-bit, hashed before storage
- Structured logging via `log/slog` for monitoring integration

## Security defaults

Postern is secure by default. Several surfaces are intentionally hidden or restricted until you explicitly enable them:

- **Ops surface returns 404** unless `AGENT_PROVISIONING_SECRET` is set. This is `cloakOps` — the entire `/ops/*` tree is invisible without it.
- **Browser WebSocket is default-deny.** Connections with an `Origin` header are rejected unless the origin is listed in `WS_ALLOWED_ORIGINS`.
- **Control proxy requires uid=1.** Only the first registered user (the operator) can access `/ops/control/*`. Optionally restricted further by `CONTROL_ALLOWED_IPS`.

These are not bugs. If you're getting 404s or WebSocket disconnects, check the troubleshooting section below.

## Troubleshooting

**`GET /ops/*` returns 404**
`AGENT_PROVISIONING_SECRET` is not set. The ops surface is cloaked when this variable is absent.

**Control proxy (`/ops/control/`) returns 404**
Either `AGENT_PROVISIONING_SECRET` is not set (ops is cloaked), or `GATEWAY_URL` / `GATEWAY_TOKEN` are not configured.

**WebSocket disconnects with code 1006**
Origin mismatch. `WS_ALLOWED_ORIGINS` must exactly match the origin your browser sends. If you open `http://localhost:8080` but your allowlist only has `http://127.0.0.1:8080`, the connection will be rejected. Include both if you use both:
```
WS_ALLOWED_ORIGINS=http://127.0.0.1:8080,http://localhost:8080
```

**Control proxy returns 404 but other ops routes work**
You're not logged in as uid=1 (the first registered account), or your IP isn't in `CONTROL_ALLOWED_IPS` if that variable is set.

**WebSocket connects but upstream doesn't respond**
Check that `GATEWAY_TOKEN` matches what the upstream expects. Postern injects this token into the WebSocket `connect` frame — if it's wrong, the upstream will silently ignore the request.

## License

AGPL-3.0 — see [COPYING](COPYING).
