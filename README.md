# shell-tunnel

[![CI](https://github.com/iyulab/shell-tunnel/actions/workflows/ci.yml/badge.svg)](https://github.com/iyulab/shell-tunnel/actions/workflows/ci.yml)
[![Crates.io](https://img.shields.io/crates/v/shell-tunnel.svg)](https://crates.io/crates/shell-tunnel)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

**Ultra-lightweight remote shell gateway.**

A single binary that exposes command execution on a machine as a structured REST/WebSocket
API — typed JSON requests and responses, resource-style sessions — so scripts, tools, and
services can drive that machine programmatically.

**Not** a browser terminal or screen-sharing UI (cf. ttyd, gotty, wetty, sshx), not a
remote-desktop product, not a general-purpose tunneling / reverse-proxy product, not a
multi-user collaboration surface. The consumer is a program calling an API, not a person at
a terminal.

## Try it in 30 seconds

```bash
cargo install shell-tunnel      # or grab a release binary, below

shell-tunnel                    # listens on 127.0.0.1:3000, no auth, local only
```

From another terminal:

```bash
curl -X POST http://127.0.0.1:3000/api/v1/execute \
  -H "Content-Type: application/json" \
  -d '{"command":"echo hello"}'
# {"success":true,"exit_code":0,"output":"hello\n","duration_ms":5,"timed_out":false}
```

That's the whole loop: run the binary, POST a command, get structured output. No config, no
account, no daemon. When you want auth, a public URL, or TLS, add one flag at a time — the
next section shows each.

## Install

```bash
cargo install shell-tunnel

# or a release binary (linux x64/arm64, macOS x64/arm64, windows x64)
curl -LO https://github.com/iyulab/shell-tunnel/releases/latest/download/shell-tunnel-linux-x64.tar.gz
tar xzf shell-tunnel-linux-x64.tar.gz && sudo mv shell-tunnel /usr/local/bin/
```

Release binaries can update themselves: `shell-tunnel --update`.

## How it works

There is no separate server to install: **the binary *is* the server.** You run it on the
machine you want to control, it listens on an HTTP port, and clients drive that machine by
calling the API.

```
client ──HTTP/WS──▶ shell-tunnel (on the target machine) ──▶ shell
```

Behind NAT that port is not reachable on its own, so shell-tunnel can publish it for you —
either through a tunnel client (`--tunnel`) or through a relay you run yourself (`--relay`).
Only the server side ever needs inbound connectivity; a caller behind NAT is fine, because it
only makes outbound requests.

## Reaching a machine behind NAT

The intended shape: a target you cannot reach directly, a relay with a public address, and
you calling in from wherever.

```
target (NAT) ──dials out──▶ relay (public) ◀──you call── caller (NAT)
```

**On the relay host** — the only machine that needs an inbound port:

```bash
shell-tunnel relay -H 0.0.0.0 -p 8443 --tls-self-signed --public-base https://relay.example.com
```

`--public-base` names the host; the advertised URL uses this relay's port (`8443`).
It generates a certificate and an enrolment token on first run and prints the exact command a
device needs — including the certificate fingerprint, so nothing has to be copied:

```
Devices join with:
    shell-tunnel --relay https://relay.example.com:8443 --enroll-token st_… --relay-fingerprint sha256:…
```

**On the target** — no port forwarding, it dials out:

```bash
shell-tunnel --relay https://relay.example.com:8443 --enroll-token st_… \
             --relay-fingerprint sha256:… -k my-api-key --preset operator
```

**From anywhere** — the target is now reachable at `/d/<name>`:

```bash
curl -X POST https://relay.example.com:8443/d/<name>/api/v1/execute \
  -H "Authorization: Bearer my-api-key" \
  -H "Content-Type: application/json" \
  -d '{"command":"hostname"}'
```

To list what is attached without logging into any target:
`curl -H "Authorization: Bearer <enroll-token>" https://relay.example.com:8443/relay/v1/devices`.

No public relay of your own? `shell-tunnel --tunnel --preset operator` runs `cloudflared` and
prints a `trycloudflare.com` URL instead — quick to try, but Cloudflare documents it as
testing-only. See [docs/USAGE.md](docs/USAGE.md) for both paths in full.

## A word on exposure

Publishing a shell means anyone holding the token can run commands as the user running
shell-tunnel. So a public path (`--tunnel` or `--relay`) turns authentication on, generates a
key if you gave none, and refuses `--no-auth`. Scope the token with `--preset operator` rather
than leaving it full-control, keep rate limiting on, and treat the URL and token as
credentials. TLS is not optional over the internet — `--tls-self-signed` on the relay is one
flag, and the fingerprint it prints keeps the connection authenticated, not just encrypted.

## Documentation

| | |
|---|---|
| [docs/USAGE.md](docs/USAGE.md) | Operating guide — every flag, endpoint, and failure mode |
| [docs/openapi.json](docs/openapi.json) | Machine-readable API contract (OpenAPI 3.0) |

## Status

Implemented: sessions, one-shot and streaming execution, WebSocket, capability-scoped auth,
rate limiting, public exposure (Cloudflare tunnel or self-hosted relay), in-process TLS with
self-signed generation and fingerprint pinning, host-header checking, and an append-only audit
trail. On the roadmap: filesystem operations and native MCP tools.

## License

MIT — see [LICENSE](LICENSE).
