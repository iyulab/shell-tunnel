# shell-tunnel

[![CI](https://github.com/iyulab/shell-tunnel/actions/workflows/ci.yml/badge.svg)](https://github.com/iyulab/shell-tunnel/actions/workflows/ci.yml)
[![Crates.io](https://img.shields.io/crates/v/shell-tunnel.svg)](https://crates.io/crates/shell-tunnel)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

**Ultra-lightweight remote shell gateway.**

A zero-dependency single binary that exposes command execution on a machine as a structured
REST/WebSocket API — typed JSON requests and responses, resource-style sessions — so scripts,
tools, and services can drive that machine programmatically.

**Not** a browser terminal or screen-sharing UI (cf. ttyd, gotty, wetty, sshx), not a
remote-desktop product, not a general-purpose tunneling / reverse-proxy product, not a
multi-user collaboration surface. The consumer is a program calling an API, not a person at
a terminal.

**Status.** The base platform — sessions, execution, streaming, capability-scoped auth,
rate limiting, public exposure via tunnel or self-hosted relay — is implemented. The rest of
the control-protocol layer (audit trail, filesystem guards) is on the roadmap.

## How it works

There is no separate server to install: **the binary *is* the server.** You run it on the
machine you want to control (dev box, build server, container), it listens on an HTTP port,
and clients drive that machine by calling the API.

```
client ──HTTP/WS──▶ shell-tunnel (on the target machine) ──▶ shell
```

Behind NAT, the bound port is not reachable on its own. `--tunnel` closes that gap by running
a tunnel client for you and printing the public URL it allocates — see
[Public access](#public-access), or run your own [relay](#self-hosted-relay) if you want no
third-party service in the path. Without either you are back to port forwarding or a VPN.

## Install

```bash
# From crates.io
cargo install shell-tunnel

# From GitHub Releases (linux-x64 / macos-arm64 / windows-x64)
curl -LO https://github.com/iyulab/shell-tunnel/releases/latest/download/shell-tunnel-linux-x64.tar.gz
tar xzf shell-tunnel-linux-x64.tar.gz && sudo mv shell-tunnel /usr/local/bin/

# From source
cargo build --release
```

## Quick Start

On the machine you want to expose, start the listener:

```bash
# 1. Local only, no auth — for trying it out on your own machine
shell-tunnel                        # listens on 127.0.0.1:3000

# 2. Auth on, key generated for you and printed to the log at startup
shell-tunnel --require-auth         # logs e.g. st_18f2a91c40_9b3e5d71c0a24f68

# 3. Your own key, reachable from other hosts on port 8080
shell-tunnel -H 0.0.0.0 -p 8080 -k my-secret-key
```

`-k` takes any string you choose — treat it like a password, and prefer `--require-auth`
(which generates one) over inventing a weak one. `-H` is the *bind* address: `127.0.0.1`
accepts only local connections, `0.0.0.0` accepts connections from other hosts (needed for
remote use — plus whatever forwarding/tunnel gets traffic to that port). Scope the key down
with `--preset` / `--capabilities`; see [Security](#security).

Then, from the client side:

```bash
curl -X POST http://localhost:3000/api/v1/execute \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer my-secret-key" \
  -d '{"command": "echo Hello World"}'
# {"success":true,"exit_code":0,"output":"Hello World\n","duration_ms":5,"timed_out":false}
```

Sessions: `POST /api/v1/sessions` → `{"session_id": 1, ...}`, then
`POST /api/v1/sessions/1/execute`, then `DELETE /api/v1/sessions/1`.

## Public access

`--tunnel` runs [`cloudflared`](https://developers.cloudflare.com/cloudflare-one/connections/connect-networks/downloads/)
for you and prints the public URL it allocates. No Cloudflare account is involved:

```bash
shell-tunnel --tunnel --preset operator
```

```
Public URL:  https://caring-brave-fox-mint.trycloudflare.com   (via cloudflared)
API key:     st_18c432ca0b988868_1376c761ea5f8453   (generated)
Try:         curl -X POST https://caring-brave-fox-mint.trycloudflare.com/api/v1/execute \
               -H "Authorization: Bearer st_18c432ca0b988868_1376c761ea5f8453" \
               -H "Content-Type: application/json" \
               -d '{"command":"echo hi"}'
```

`cloudflared` must be installed — shell-tunnel neither bundles nor downloads it. Any other
tunnel client works through `--tunnel-command`, which runs the command you give and picks up
the first URL it prints:

```bash
shell-tunnel --tunnel-command "ngrok http 3000" --preset operator
shell-tunnel --tunnel-command "bore local 3000 --to bore.pub" --preset operator
```

**A tunnel turns on authentication**, generating a key if you did not supply one (that
printed key is your only copy). `--no-auth --tunnel` is refused rather than silently
overridden. Scope the token with `--preset`/`--capabilities` — an unscoped token has full
control of the machine on a public URL, and shell-tunnel warns when you leave it that way.

If the tunnel cannot be established, startup fails instead of quietly serving local-only. If
the tunnel client dies later, the server exits too: the URL it advertised is gone, and a
restart would allocate a different one.

**Quick tunnel limits** (Cloudflare's, not ours): documented as **testing/development only**,
no SLA, a **new URL on every restart**, and a cap of ~200 concurrent in-flight requests.
Server-sent events are unsupported; WebSockets work. For anything durable, use a Cloudflare
named tunnel or another provider via `--tunnel-command`.

> Exposing a shell on a public URL means anyone holding the token can run commands as the
> user running shell-tunnel. Scope the token, keep rate limiting on, and treat the URL as a
> credential.

### Self-hosted relay

To keep third parties out of the path entirely, run the relay yourself — it is the same
binary. Devices dial *out* to it, so they still need no inbound port:

```bash
# On a host with a public address
shell-tunnel relay -H 0.0.0.0 -p 8443 --public-base https://relay.example.com
# prints an enroll token (or pass your own with --enroll-token)

# On each machine you want to reach
shell-tunnel --relay https://relay.example.com --enroll-token <token> --preset operator
# Public URL:  https://relay.example.com/d/<device-id>   (via relay)
```

Requests to `https://relay.example.com/d/<device-id>/api/v1/execute` reach that device.
Unlike a quick tunnel, the device keeps its URL across reconnects, so the client reconnects
with backoff instead of exiting.

**Two separate secrets, deliberately.** The enroll token only decides *which devices may
attach* to your relay. What a caller may then do is decided by the capability token, which
the relay forwards untouched and never inspects or logs — attaching a relay does not put it
inside your trust boundary.

The relay server runs in any build. The *device* side needs the `relay-client` feature — it is
**bundled in the official release binaries**, and off by default from source (the core build
links no TLS or WebSocket client): `cargo build --release --features relay-client`.

**Current limitation:** the relay proxies ordinary request/response HTTP. WebSocket
streaming (`/api/v1/ws`) works over `--tunnel` but not yet through the relay.

## API

Full reference: [`docs/openapi.json`](docs/openapi.json) (OpenAPI 3.0, authoritative).

Required capability applies only when auth is enabled; `*` (full-control) tokens satisfy
every route.

| Method | Endpoint | Capability |
|--------|----------|------------|
| `GET` | `/health` | *(none — no auth)* |
| `GET` | `/api/v1` | *(authenticated only)* |
| `GET` | `/api/v1/sessions` | `session.read` |
| `POST` | `/api/v1/sessions` | `session.manage` |
| `GET` | `/api/v1/sessions/{id}` | `session.read` |
| `DELETE` | `/api/v1/sessions/{id}` | `session.manage` |
| `POST` | `/api/v1/sessions/{id}/execute` | `exec` |
| `POST` | `/api/v1/execute` | `exec` |
| `WS` | `/api/v1/sessions/{id}/ws` | `exec` |
| `WS` | `/api/v1/ws` | `exec` |

## CLI Options

| Option | Description | Default |
|--------|-------------|---------|
| `-H, --host <ADDR>` | Host address to bind | `127.0.0.1` |
| `-p, --port <PORT>` | Port to listen on | `3000` |
| `-c, --config <FILE>` | Path to config file (JSON) | - |
| `-k, --api-key <KEY>` | API key for authentication | - |
| `-l, --log-level <LVL>` | error / warn / info / debug / trace | `info` |
| `--no-auth` | Disable authentication | `false` |
| `--require-auth` | Require auth, auto-generating a key if none given | `false` |
| `--capabilities <C>` | Scope issued token(s), e.g. `exec,session.read` | full-control |
| `--preset <NAME>` | Scope by role preset (`operator` / `read-only` / `full-control`) | full-control |
| `--no-rate-limit` | Disable rate limiting | `false` |
| `--tunnel` | Publish via a Cloudflare quick tunnel (needs `cloudflared`; implies auth) | `false` |
| `--tunnel-command <C>` | Publish by running your own tunnel client; its printed URL is used | - |
| `--relay <URL>` | Attach to a self-hosted relay (needs `--enroll-token`; implies auth) | - |
| `relay` *(subcommand)* | Run as a relay: `shell-tunnel relay -H .. -p .. [--enroll-token T] [--public-base URL]` | - |
| `--cors-allow-any` | Allow any CORS origin (opt-in; for browser UIs) | `false` |
| `--check-update` / `--update` / `--no-update-check` | *(self-update builds only)* | - |
| `-h, --help` / `-V, --version` | Help / version | - |

Environment: `SHELL_TUNNEL_HOST`, `SHELL_TUNNEL_PORT`, `SHELL_TUNNEL_API_KEY`,
`SHELL_TUNNEL_LOG_LEVEL`, `RUST_LOG`.

## Configuration File

```json
{
  "server": { "host": "0.0.0.0", "port": 8080, "graceful_shutdown": true },
  "security": {
    "auth": { "enabled": true, "api_keys": ["key1"], "preset": "operator", "capabilities": [] },
    "rate_limit": { "enabled": true, "requests_per_window": 100, "window_secs": 60 }
  },
  "transport": { "mode": "none" },
  "logging": { "level": "info" }
}
```

`transport.mode` is `none` (local only), `cloudflared`, or `command` — with `command` naming
the tunnel client to run. CLI flags override it, as with every other setting.

```bash
shell-tunnel -c /etc/shell-tunnel/config.json
```

## Security

**Authentication & capabilities.** Opaque bearer tokens via `Authorization: Bearer <token>`;
`/health` bypasses auth. Auth is off by default — enable with `--api-key <KEY>`, or
`--require-auth` to auto-generate (and log) a key at startup.

Each token carries a set of capabilities and each route declares a required one:
`exec` (run commands), `session.read` (list/inspect), `session.manage` (create/delete),
`*` (wildcard). Missing/invalid token → **401**; valid token lacking the capability → **403**.
Presets: `operator` = `{exec, session.read, session.manage}`, `read-only` = `{session.read}`,
`full-control` = `{*}`.

`--capabilities`/`--preset` turn auth on (`--no-auth` still overrides). Without them a key is
full-control, so existing `--api-key` setups never hit a 403.

```bash
shell-tunnel -k readonly-key --preset read-only
shell-tunnel -k ci-key --capabilities exec,session.read
```

**Command content is not filtered.** A `CommandValidator` / path-validator primitive ships in
the crate but is **not wired into the server** — a token holding `exec` can run any command
today. The capability token is the primary access control: withhold `exec` and a token cannot
execute.

**Rate limiting.** 100 requests/minute per IP by default; `X-RateLimit-Limit`,
`X-RateLimit-Remaining`, and `Retry-After` on a 429.

**CORS.** Restrictive by default (browser-only mechanism, so no effect on non-browser clients);
opt in with `--cors-allow-any` or `security.cors.allow_any`. Note that CORS does not stop
DNS rebinding — Host-header validation is on the roadmap.

## Auto-Update

The core binary ships without an update stack. Self-update is an opt-in build feature,
**bundled in the official release binaries**; from source use
`cargo build --release --features self-update`.

Such builds check for a newer release on startup and **log a notice — nothing is downloaded
or installed automatically.** Installing is always explicit:

```bash
shell-tunnel --check-update   # report only
shell-tunnel --update         # download and replace the binary
shell-tunnel --no-update-check # skip the startup check
```

## License

MIT — see [LICENSE](LICENSE).
