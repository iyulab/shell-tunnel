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

## How it works

There is no separate server to install: **the binary *is* the server.** You run it on the
machine you want to control, it listens on an HTTP port, and clients drive that machine by
calling the API.

```
client ──HTTP/WS──▶ shell-tunnel (on the target machine) ──▶ shell
```

Behind NAT that port is not reachable on its own, so shell-tunnel can publish it for you —
either through a tunnel client (`--tunnel`) or through a relay you run yourself (`--relay`).
Only the server side ever needs inbound connectivity; callers behind NAT are fine.

## Install

```bash
cargo install shell-tunnel

# or a release binary (linux x64/arm64, macOS x64/arm64, windows x64)
curl -LO https://github.com/iyulab/shell-tunnel/releases/latest/download/shell-tunnel-linux-x64.tar.gz
tar xzf shell-tunnel-linux-x64.tar.gz && sudo mv shell-tunnel /usr/local/bin/
```

## Quick start

```bash
# Local, with a generated API key
shell-tunnel --require-auth --preset operator

# Public URL right now (needs cloudflared on PATH)
shell-tunnel --tunnel --preset operator

# Through your own relay, no third party in the path
shell-tunnel --relay https://relay.example.com --enroll-token <secret> \
             --device-name build-box --preset operator
```

Whichever you pick, the server prints the URL and the key to use:

```bash
curl -X POST "$URL/api/v1/execute" \
  -H "Authorization: Bearer $KEY" \
  -H "Content-Type: application/json" \
  -d '{"command":"echo hello"}'
# {"success":true,"exit_code":0,"output":"hello\n","duration_ms":5,"timed_out":false}
```

Publishing a shell means anyone holding the token can run commands as the user running
shell-tunnel. Scope the token with `--preset` / `--capabilities`, keep rate limiting on, and
treat the URL as a credential. A public path turns authentication on and refuses `--no-auth`.

## Documentation

| | |
|---|---|
| [docs/USAGE.md](docs/USAGE.md) | Operating guide — every flag, endpoint, and failure mode |
| [docs/openapi.json](docs/openapi.json) | Machine-readable API contract (OpenAPI 3.0) |

## Status

Sessions, execution, WebSocket streaming, capability-scoped auth, rate limiting, and public
exposure (tunnel or self-hosted relay) are implemented. Audit logging and filesystem
operations are on the roadmap.

## License

MIT — see [LICENSE](LICENSE).
