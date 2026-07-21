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
rate limiting — is implemented. The control-protocol layer (audit trail, self-hosted relay,
filesystem guards) is on the roadmap.

## How it works

There is no separate server to install: **the binary *is* the server.** You run it on the
machine you want to control (dev box, build server, container), it listens on an HTTP port,
and clients drive that machine by calling the API.

```
client ──HTTP/WS──▶ shell-tunnel (on the target machine) ──▶ shell
```

Reachability is *your* responsibility today. The binary binds a local port; if the target
machine sits behind NAT, you still need port forwarding, a VPN, or an SSH/ngrok-style tunnel
to reach it. The self-hosted relay that would remove that step is **on the roadmap, not
implemented**.

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
  "logging": { "level": "info" }
}
```

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
