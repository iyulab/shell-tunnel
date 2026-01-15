# shell-tunnel

[![CI](https://github.com/iyulab/shell-tunnel/actions/workflows/ci.yml/badge.svg)](https://github.com/iyulab/shell-tunnel/actions/workflows/ci.yml)
[![Crates.io](https://img.shields.io/crates/v/shell-tunnel.svg)](https://crates.io/crates/shell-tunnel)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

**Ultra-lightweight shell tunnel for AI agent integration.**

A zero-dependency, single binary that enables AI agents to control remote terminals via REST/WebSocket API.

## Features

- **Cross-platform**: Windows (ConPTY), Linux, macOS (PTY)
- **Lightweight**: ~2MB binary, minimal resource footprint
- **Real-time streaming**: WebSocket support for live output
- **Secure**: API key authentication, rate limiting, command validation
- **Self-updating**: Automatic updates from GitHub Releases

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
| `--no-rate-limit` | Disable rate limiting | `false` |
| `--check-update` | Check for updates and exit | - |
| `--update` | Download and install latest version | - |
| `--no-update-check` | Disable automatic update check on startup | `false` |
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

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/health` | Health check (no auth) |
| `GET` | `/api/v1` | API information |
| `GET` | `/api/v1/sessions` | List all sessions |
| `POST` | `/api/v1/sessions` | Create a new session |
| `GET` | `/api/v1/sessions/{id}` | Get session status |
| `DELETE` | `/api/v1/sessions/{id}` | Delete a session |
| `POST` | `/api/v1/sessions/{id}/execute` | Execute command in session |
| `POST` | `/api/v1/execute` | Execute command (one-shot) |
| `WS` | `/api/v1/sessions/{id}/ws` | WebSocket streaming |
| `WS` | `/api/v1/ws` | WebSocket one-shot |

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

```bash
shell-tunnel -c /etc/shell-tunnel/config.json
```

## Auto-Update

shell-tunnel includes built-in auto-update functionality:

```bash
# Check for updates
shell-tunnel --check-update

# Self-update to latest version
shell-tunnel --update
```

By default, shell-tunnel checks for updates on startup (can be disabled with `--no-update-check`).

## Security

### Authentication
- Bearer token API keys via `Authorization` header
- `/health` endpoint bypasses authentication (for monitoring)

### Rate Limiting
- Default: 100 requests/minute per IP
- Response headers: `X-RateLimit-Limit`, `X-RateLimit-Remaining`, `X-RateLimit-Reset`

### Input Validation
- Command length limits
- Dangerous pattern detection (fork bombs, `rm -rf /`, etc.)
- Path traversal prevention

## License

MIT License - see [LICENSE](LICENSE) for details.
