# Shell-Tunnel: Current Status

**Last Updated:** 2026-07-19

## Status

**Base platform: implemented and hardened.** The foundational gateway (sessions,
execution, REST/WebSocket API, auth, rate limiting, CLI/config) is in place and
the core agent flow (create → execute, one-shot execute, streaming) works
out-of-the-box.

**Differentiation layer for the "safe control protocol" positioning: not yet
started.** shell-tunnel's direction is a single binary + protocol for
controlling remote environments *safely and deterministically* — the
capability/permission tokens, audit trail, pluggable transport / self-hosted
relay, filesystem & destructive-operation guards, and native MCP exposure that
define that positioning are still ahead (see **What's next** below).

| Metric | Result |
|--------|--------|
| Tests | 203 passed default / 204 with `self-update`, 4 ignored (unit + integration + doc) |
| Binary | ~1–2MB (release, LTO) |

## Execution model

Non-interactive commands (session `execute`, one-shot `/execute`, and WebSocket
streaming) run via a piped `std::process` child, **not** a PTY. This gives real
EOF, working completion detection, an enforceable timeout, and process-tree
termination — properties a PTY (Windows ConPTY in particular) does not provide
for one-shot commands. Every execution:

- runs off the async runtime workers (`spawn_blocking`), so `/health` and the
  accept loop stay responsive regardless of a slow or hung command;
- honors its `timeout_secs`, killing the **whole process tree** on expiry
  (`taskkill /T` on Windows, process-group signal on Unix);
- merges stdout and stderr into a single output stream.

The PTY abstraction (`pty` module) is retained as public API and the intended
foundation for future *interactive* sessions that need real TTY semantics; it is
not currently on the non-interactive execution path.

## Recent hardening (2026-07-18)

- Fixed: freshly created session was stuck in `Created` and rejected `execute`
  (`INVALID_STATE`). Sessions are now ready-to-execute on creation.
- Fixed: a single one-shot `/execute` could hang the entire server (including
  `/health`). Root cause was blocking work on async workers plus ConPTY never
  signalling completion. Resolved by the piped execution model above.
- Added enforceable timeouts with process-tree kill across all execution paths.
- Added cross-platform executor integration tests.

## Implemented Features

### Core Foundation
- Cross-platform PTY abstraction (portable-pty) — foundation for interactive sessions
- Session management (ID, State, Store)
- Async I/O adapters

### Execution & Output
- Piped command execution (enforceable timeout, process-tree kill)
- WebSocket streaming (real-time output)
- Output Sanitization (VTE parser)
- Virtual Screen (vt100 emulation)
- State Tracking (SessionContext)

### API Layer
- REST API (axum 0.8)
- JSON request/response format
- CORS: restrictive by default (browser-only mechanism; no effect on agent/CLI
  clients), permissive `Any` opt-in via `--cors-allow-any`

### Security & Production
- API Key Authentication (Bearer token)
- Rate Limiting (IP-based sliding window)
- Input Validation *(library primitive — **not yet wired** into the server execute paths)*:
  `CommandValidator` (length, dangerous-pattern, null-byte) + path validator ship and are
  unit-tested, but no handler invokes them today, so commands are not pattern-filtered on
  `/execute`. Enforcement is deferred to Phase A, where the primary control is an operator-scoped
  capability token (substring matching = bypassable secondary) — see **What's next**, Phases A/B
- Graceful Shutdown (SIGTERM/Ctrl+C handling)

### Tooling
- CLI interface (lexopt - minimal footprint)
- JSON configuration file support
- Environment variable configuration
- Integration tests
- OpenAPI 3.0 specification

## CLI Usage

```bash
# Show help
shell-tunnel --help

# Start with defaults (localhost:3000, no auth)
shell-tunnel

# Start on all interfaces with API key
shell-tunnel -H 0.0.0.0 -p 8080 -k my-secret-key

# Start with config file
shell-tunnel -c /etc/shell-tunnel/config.json

# Development mode (no security)
shell-tunnel --no-auth --no-rate-limit
```

### CLI Options

| Option | Description | Default |
|--------|-------------|---------|
| `-H, --host` | Host address to bind | 127.0.0.1 |
| `-p, --port` | Port to listen on | 3000 |
| `-c, --config` | Path to config file (JSON) | - |
| `-k, --api-key` | API key for authentication | - |
| `-l, --log-level` | Log level | info |
| `--no-auth` | Disable authentication | false |
| `--no-rate-limit` | Disable rate limiting | false |

### Environment Variables

| Variable | Description |
|----------|-------------|
| `SHELL_TUNNEL_HOST` | Host address |
| `SHELL_TUNNEL_PORT` | Port number |
| `SHELL_TUNNEL_API_KEY` | API key |
| `SHELL_TUNNEL_LOG_LEVEL` | Log level |
| `RUST_LOG` | Alternative log level |

## Configuration File

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
      "api_keys": ["key1", "key2"]
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

## API Endpoints

### Health & Info
- `GET /health` - Health check (no auth)
- `GET /api/v1` - API information

### Sessions
- `GET /api/v1/sessions` - List all sessions
- `POST /api/v1/sessions` - Create a new session
- `GET /api/v1/sessions/{id}` - Get session status
- `DELETE /api/v1/sessions/{id}` - Delete a session
- `POST /api/v1/sessions/{id}/execute` - Execute command
- `WS /api/v1/sessions/{id}/ws` - WebSocket streaming

### One-shot Execution
- `POST /api/v1/execute` - Execute without session
- `WS /api/v1/ws` - WebSocket one-shot

## Security Features

### Authentication
- Bearer token API keys
- Auto-generated keys if none provided
- `/health` endpoint bypass (for monitoring)

### Rate Limiting
- Default: 100 requests/minute per IP
- Configurable via config file or CLI
- `X-RateLimit-*` response headers

### Input Validation
*(available in the `CommandValidator` / path-validator primitives — **not invoked** by the
built-in server today; see Security & Production above. Enforcement deferred to Phase A.)*
- Command length limits
- Dangerous pattern detection (fork bomb, rm -rf /, etc.)
- Path traversal prevention (path validator)
- Null byte injection prevention

## Commands

```bash
cargo build --release    # Build
cargo test --all         # Test
cargo clippy             # Lint
cargo fmt                # Format
RUST_LOG=debug cargo run # Run with debug logging
```

## API Documentation

OpenAPI 3.0 specification available at `docs/openapi.json`.

## What's next

The base platform is complete; the differentiating "safe control protocol"
layer is the active roadmap, in priority order:

| Phase | Direction | Status |
|-------|-----------|--------|
| A | Permission-scope tokens · audit trail · versioned capability wire contract · pluggable transport / self-hosted relay | Not started (top priority) |
| B | Security hardening & resilience (CORS/auth defaults, request isolation, risk-detection as secondary defense) | Partially done — timeout enforcement + process-tree kill + `/health` independence (2026-07-18); CORS secure-by-default + opt-out (2026-07-19). Remaining: local-binding token opt-in, Host-header validation (DNS-rebinding, folds into Phase A) |
| C | Cross-platform FS abstraction · filesystem read/write APIs · destructive-operation guards | Not started |
| D | Native MCP server exposure (`remote_shell_exec`, `remote_fs_read`, …) | Not started |

Cross-cutting: `self_update` is now an opt-in `self-update` cargo feature
(default-off) so the core build is zero-dependency (2026-07-19); `rust-version`
corrected to 1.78 for the default graph. Positioning re-confirmed with explicit
Non-Goals in the README (2026-07-19). Remaining: full `self_update` removal
(product decision — official binaries still bundle it), and session state-model
redesign.
