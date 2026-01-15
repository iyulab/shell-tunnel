# Shell-Tunnel: Current Status

**Last Updated:** 2026-01-15

## Status: Phase 5 Complete

| Metric | Result |
|--------|--------|
| Tests | 193 passed, 4 ignored |
| Binary | 2.0MB |

## Implemented Features

### Phase 1 - Core Foundation
- Cross-platform PTY (portable-pty)
- Session management (ID, State, Store)
- Async I/O adapters

### Phase 2 - Core Features
- Command Execution Engine (sync/async)
- Output Sanitization (VTE parser)
- Virtual Screen (vt100 emulation)
- State Tracking (SessionContext)

### Phase 3 - API Layer
- REST API (axum 0.8)
- WebSocket streaming (real-time output)
- JSON request/response format
- CORS support (tower-http)

### Phase 4 - Security & Production
- API Key Authentication (Bearer token)
- Rate Limiting (IP-based sliding window)
- Input Validation (dangerous command detection)
- Graceful Shutdown (SIGTERM/Ctrl+C handling)

### Phase 5 - Polish & Documentation
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
- Command length limits
- Dangerous pattern detection (fork bomb, rm -rf /, etc.)
- Path traversal prevention
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

## Project Complete

All planned phases have been implemented:

| Phase | Description | Status |
|-------|-------------|--------|
| 1 | Core Foundation | Done |
| 2 | Core Features | Done |
| 3 | API Layer | Done |
| 4 | Security & Production | Done |
| 5 | Polish & Documentation | Done |
