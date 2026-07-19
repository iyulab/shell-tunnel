# shell-tunnel

[![CI](https://github.com/iyulab/shell-tunnel/actions/workflows/ci.yml/badge.svg)](https://github.com/iyulab/shell-tunnel/actions/workflows/ci.yml)
[![Crates.io](https://img.shields.io/crates/v/shell-tunnel.svg)](https://crates.io/crates/shell-tunnel)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

**Ultra-lightweight shell tunnel for AI agent integration.**

A zero-dependency, single binary that enables AI agents to control remote terminals via REST/WebSocket API.

## What it is (and isn't)

shell-tunnel is a gateway **for AI agents**, not a human-facing web terminal. It exposes
remote command execution as a structured REST/WebSocket API — typed JSON requests and
responses, resource-style sessions — so an agent can drive a remote environment
programmatically. The base platform (sessions, execution, streaming, auth, rate limiting)
is implemented; the differentiating **safe control protocol** (permission-scoped tokens,
audit trail, self-hosted relay, native MCP tools) is on the roadmap — see
[`docs/CURRENT-STATUS.md`](docs/CURRENT-STATUS.md).

**Non-Goals**

- **Not** a browser terminal emulator or screen-sharing UI (cf. ttyd / gotty / wetty /
  sshx) — there is no xterm.js front-end and no human terminal-sharing.
- **Not** a remote-desktop or mobile control app — the consumer is an agent/program, not a
  person at a screen.
- **Not** a general-purpose tunneling / reverse-proxy product — transport is borrowed; the
  value is the agent-facing *control protocol* layered on top.
- **Not** a multi-user collaboration surface.

## Features

- **Cross-platform**: Windows (ConPTY), Linux, macOS (PTY)
- **Lightweight**: ~2MB binary, minimal resource footprint
- **Real-time streaming**: WebSocket support for live output
- **Secure**: capability-scoped bearer tokens (fine-grained `exec` / `session.read` / `session.manage`, with role presets) and rate limiting (command-*content* validation primitives ship but are not yet wired into the server — see [Input Validation](#input-validation))
- **Zero-dependency core**: the default build links no update/HTTP stack
- **Self-updating** *(opt-in)*: in-binary updates from GitHub Releases — bundled in official release binaries, enabled for source builds with `--features self-update`

## Installation

### From GitHub Releases (Recommended)

Download the latest binary for your platform:

```bash
# Linux x64
curl -LO https://github.com/iyulab/shell-tunnel/releases/latest/download/shell-tunnel-linux-x64.tar.gz
tar xzf shell-tunnel-linux-x64.tar.gz
sudo mv shell-tunnel /usr/local/bin/

# macOS (Apple Silicon)
curl -LO https://github.com/iyulab/shell-tunnel/releases/latest/download/shell-tunnel-macos-arm64.tar.gz
tar xzf shell-tunnel-macos-arm64.tar.gz
sudo mv shell-tunnel /usr/local/bin/

# Windows (PowerShell)
Invoke-WebRequest -Uri "https://github.com/iyulab/shell-tunnel/releases/latest/download/shell-tunnel-windows-x64.zip" -OutFile "shell-tunnel.zip"
Expand-Archive shell-tunnel.zip -DestinationPath .
```

### From crates.io

```bash
cargo install shell-tunnel
```

### From Source

```bash
git clone https://github.com/iyulab/shell-tunnel.git
cd shell-tunnel
cargo build --release
```

## Quick Start

```bash
# Start server with defaults (localhost:3000, no auth)
shell-tunnel

# Start with API key authentication
shell-tunnel -k my-secret-key

# Start on all interfaces
shell-tunnel -H 0.0.0.0 -p 8080 -k my-secret-key

# Development mode (no security)
shell-tunnel --no-auth --no-rate-limit
```

## CLI Options

| Option | Description | Default |
|--------|-------------|---------|
| `-H, --host <ADDR>` | Host address to bind | `127.0.0.1` |
| `-p, --port <PORT>` | Port to listen on | `3000` |
| `-c, --config <FILE>` | Path to config file (JSON) | - |
| `-k, --api-key <KEY>` | API key for authentication | - |
| `-l, --log-level <LVL>` | Log level (error, warn, info, debug, trace) | `info` |
| `--no-auth` | Disable authentication | `false` |
| `--require-auth` | Require auth, auto-generating an API key if none given | `false` |
| `--capabilities <C>` | Scope issued token(s) to comma-separated capabilities (e.g. `exec,session.read`) | full-control |
| `--preset <NAME>` | Scope issued token(s) by role preset (`operator` / `read-only` / `full-control`) | full-control |
| `--no-rate-limit` | Disable rate limiting | `false` |
| `--cors-allow-any` | Allow any CORS origin (opt-in; for browser UIs) | `false` |
| `--check-update` | Check for updates and exit *(self-update builds only)* | - |
| `--update` | Download and install latest version *(self-update builds only)* | - |
| `--no-update-check` | Disable automatic update check on startup *(self-update builds only)* | `false` |
| `-h, --help` | Print help | - |
| `-V, --version` | Print version | - |

## Environment Variables

| Variable | Description |
|----------|-------------|
| `SHELL_TUNNEL_HOST` | Host address |
| `SHELL_TUNNEL_PORT` | Port number |
| `SHELL_TUNNEL_API_KEY` | API key |
| `SHELL_TUNNEL_LOG_LEVEL` | Log level |
| `RUST_LOG` | Alternative log level |

## API Usage

### Health Check

```bash
curl http://localhost:3000/health
# OK
```

### Execute Command (One-shot)

```bash
curl -X POST http://localhost:3000/api/v1/execute \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer my-secret-key" \
  -d '{"command": "echo Hello World"}'
```

Response:
```json
{
  "success": true,
  "exit_code": 0,
  "output": "Hello World\n",
  "duration_ms": 5,
  "timed_out": false
}
```

### Session-based Execution

```bash
# Create session
curl -X POST http://localhost:3000/api/v1/sessions \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer my-secret-key" \
  -d '{}'

# Response: {"session_id": 1, "session_id_str": "sess-00000001"}

# Execute in session
curl -X POST http://localhost:3000/api/v1/sessions/1/execute \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer my-secret-key" \
  -d '{"command": "pwd"}'

# Delete session
curl -X DELETE http://localhost:3000/api/v1/sessions/1 \
  -H "Authorization: Bearer my-secret-key"
```

### API Endpoints

Required capability applies only when auth is enabled. A route with no specific
capability just needs a valid token; `*` (full-control) tokens satisfy every route.

| Method | Endpoint | Description | Required capability |
|--------|----------|-------------|---------------------|
| `GET` | `/health` | Health check | *(none — no auth)* |
| `GET` | `/api/v1` | API information | *(authenticated only)* |
| `GET` | `/api/v1/sessions` | List all sessions | `session.read` |
| `POST` | `/api/v1/sessions` | Create a new session | `session.manage` |
| `GET` | `/api/v1/sessions/{id}` | Get session status | `session.read` |
| `DELETE` | `/api/v1/sessions/{id}` | Delete a session | `session.manage` |
| `POST` | `/api/v1/sessions/{id}/execute` | Execute command in session | `exec` |
| `POST` | `/api/v1/execute` | Execute command (one-shot) | `exec` |
| `WS` | `/api/v1/sessions/{id}/ws` | WebSocket streaming | `exec` |
| `WS` | `/api/v1/ws` | WebSocket one-shot | `exec` |

## Configuration File

Create a JSON config file for complex setups:

```json
{
  "server": {
    "host": "0.0.0.0",
    "port": 8080,
    "graceful_shutdown": true
  },
  "security": {
    "auth": {
      "enabled": true,
      "api_keys": ["key1", "key2"],
      "preset": "operator",
      "capabilities": []
    },
    "rate_limit": {
      "enabled": true,
      "requests_per_window": 100,
      "window_secs": 60
    }
  },
  "logging": {
    "level": "info"
  }
}
```

```bash
shell-tunnel -c /etc/shell-tunnel/config.json
```

## Auto-Update

The core binary is zero-dependency and ships **without** an update stack. In-binary
self-update is an opt-in build feature (`self-update`): it is **bundled in the official
release binaries**, so downloads from GitHub Releases already support it. When building
from source, enable it explicitly:

```bash
cargo build --release --features self-update
```

With the feature enabled:

```bash
# Check for updates
shell-tunnel --check-update

# Self-update to latest version
shell-tunnel --update
```

Such builds check for updates on startup (can be disabled with `--no-update-check`).
Builds without the feature omit these flags entirely.

## Security

### Authentication & Capabilities
- Opaque bearer tokens via the `Authorization: Bearer <token>` header.
- `/health` bypasses authentication (for monitoring).
- Disabled by default for ease of use. Enable with `--api-key <KEY>`, or with
  `--require-auth` to turn auth on and have a key auto-generated (and logged) at startup.

**Capability model.** Each token carries a *set* of capability strings; each route
declares a *required capability*, and access is a set-membership check:
- Capabilities: `exec` (run commands), `session.read` (list/inspect sessions),
  `session.manage` (create/delete sessions). `*` is a wildcard satisfying every check.
- Missing/invalid token → **401**; valid token lacking the required capability → **403**.
- Role presets (convenience, not a wire contract): `operator` = `{exec, session.read,
  session.manage}`, `read-only` = `{session.read}`, `full-control` = `{*}`.

**Issuing scoped tokens.** Passing `--capabilities`/`--preset` turns auth on (a scope with auth
off would be silently ignored), so `--preset read-only` alone starts a locked server; `--no-auth`
still overrides. Without `--capabilities`/`--preset`, a key is **full-control** (backward-compatible
— an existing `--api-key` / `--require-auth` key can never hit a 403):

```bash
# A read-only token (may list/inspect sessions, cannot exec or create)
shell-tunnel -k readonly-key --preset read-only

# A token scoped to exactly these capabilities
shell-tunnel -k agent-key --capabilities exec,session.read
```

### Rate Limiting
- Default: 100 requests/minute per IP
- Response headers: `X-RateLimit-Limit`, `X-RateLimit-Remaining` (and `Retry-After` on a 429)

### Input Validation

> **Status: library primitive, not yet enforced by the built-in server.**

shell-tunnel ships a `CommandValidator` primitive (command-length limits, dangerous-pattern
detection for fork bombs / `rm -rf /` / disk-wipe / `shutdown`, and null-byte rejection) and a
companion path validator (traversal / null-byte / length). These are **public, unit-tested library
primitives, but the built-in server does not currently invoke them on the execute paths** — a
command sent to `/api/v1/execute` (or a session/WS execute) is not pattern-filtered today, and a
`working_dir` is not traversal-checked.

The primary access control is the [capability token](#authentication--capabilities): withhold
`exec` and a token cannot run commands at all. Command-*content* filtering (dangerous-substring
matching) is a *bypassable secondary* defence and remains unwired — so a token that **does** hold
`exec` can run any command today. Consumers embedding the crate can call
`CommandValidator::validate_command` directly in the meantime; wiring it into the server is a
deferred product decision.

### CORS
- **Restrictive by default**: no permissive CORS headers are emitted. CORS is a
  browser-only mechanism, so this has no effect on AI-agent/CLI clients, while it
  reduces the CSRF / cross-origin surface a malicious web page could exploit against a
  local instance (the JSON execute endpoints require a preflight, which is not approved).
- Enable permissive CORS for a trusted browser UI with `--cors-allow-any` (or
  `security.cors.allow_any` in the config file).
- Scope note: CORS does **not** stop DNS-rebinding attacks (the request is same-origin
  after rebinding); Host-header validation is the complementary control and is tracked
  on the roadmap.

## License

MIT License - see [LICENSE](LICENSE) for details.
