# shell-tunnel — operating guide

Complete reference for running shell-tunnel and calling its API. The
[README](../README.md) is the introduction; this is the working document.
[`openapi.json`](openapi.json) is the machine-readable contract for the HTTP API.

- [0. Quickest start](#0-quickest-start)
- [1. Choosing how to reach the machine](#1-choosing-how-to-reach-the-machine)
- [2. Running it](#2-running-it)
- [3. Calling the API](#3-calling-the-api)
- [4. Authentication and capabilities](#4-authentication-and-capabilities)
- [5. Self-hosted relay](#5-self-hosted-relay)
- [6. CLI reference](#6-cli-reference)
- [7. Configuration file](#7-configuration-file)
- [8. Failure modes](#8-failure-modes)
- [9. Build features](#9-build-features)
- [10. Limits](#10-limits)

---

## 0. Quickest start

Local, no configuration:

```bash
shell-tunnel                                   # 127.0.0.1:3000, no auth
curl -X POST http://127.0.0.1:3000/api/v1/execute \
  -H "Content-Type: application/json" -d '{"command":"echo hello"}'
```

Reachable from the internet, one relay and one flag — the relay prints the exact
command each target needs:

```bash
# on a host with a public address
shell-tunnel relay -H 0.0.0.0 -p 8443 --tls-self-signed --public-base https://relay.example.com

# on the machine you want to reach (behind NAT is fine)
shell-tunnel --relay https://relay.example.com:8443 --enroll-token <printed> \
             --relay-fingerprint <printed> -k <your-key> --preset operator
```

Everything after this adds one capability at a time. Pick the row that matches
your situation in §1, then read the section it points to.

---

## 1. Choosing how to reach the machine

The binary listens on a local port. Only that port needs to be reachable — and
only the *server* side needs inbound connectivity. A caller behind NAT is never
a problem, because callers only make outbound requests.

| Situation | Use | Command |
|---|---|---|
| Calling from the same machine | nothing | `shell-tunnel` |
| Machine has a reachable address | plain bind | `shell-tunnel -H 0.0.0.0 -p 8080 -k <key>` |
| Machine is behind NAT, want a URL now | tunnel | `shell-tunnel --tunnel` |
| Behind NAT, no third party in the path | relay | `shell-tunnel --relay <url> --enroll-token <t>` |
| Behind NAT, different tunnel client | custom | `shell-tunnel --tunnel-command "<cmd>"` |

Tunnel and relay are mutually exclusive; asking for both is refused at startup.

---

## 2. Running it

### Local only

```bash
shell-tunnel                      # 127.0.0.1:3000, no authentication
shell-tunnel --require-auth       # generates and logs an API key
shell-tunnel -k my-key --preset operator
```

### Public URL through a tunnel

```bash
shell-tunnel --tunnel --preset operator
```

Requires [`cloudflared`](https://developers.cloudflare.com/cloudflare-one/connections/connect-networks/downloads/)
on `PATH`; shell-tunnel neither bundles nor downloads it. Prints:

```
Public URL:  https://<random>.trycloudflare.com   (via cloudflared)
API key:     st_18c432ca0b988868_1376c761ea5f8453   (generated)
Try:         curl -X POST https://<random>.trycloudflare.com/api/v1/execute ...
```

Any other tunnel client works through `--tunnel-command`; the first URL it
prints is used. The local address is exported to that command as
`SHELL_TUNNEL_LOCAL_ADDR` / `SHELL_TUNNEL_LOCAL_PORT`.

```bash
shell-tunnel --tunnel-command "ngrok http 3000" --preset operator
shell-tunnel --tunnel-command "bore local 3000 --to bore.pub" --preset operator
```

Cloudflare documents quick tunnels as **testing/development only**: no SLA, a
new URL on every restart, ~200 concurrent in-flight requests, no SSE
(WebSockets do work). For anything durable use a named Cloudflare tunnel,
another provider, or the relay.

### Attached to a relay

See [§5](#5-self-hosted-relay).

### What a public path changes

Publishing turns weak defaults into internet-facing ones, so it is enforced
rather than advised:

- authentication is switched on; a key is generated and printed if none was given
- `--no-auth` combined with a tunnel or relay is **refused**, not overridden
- warnings for an unscoped full-control token, disabled rate limiting, and a
  non-loopback bind
- only a *generated* key is echoed — a key you supplied is never written to stdout

---

## 3. Calling the API

Base URL is whatever the server prints: `http://127.0.0.1:3000`, a tunnel URL,
or `<relay>/d/<device-id>`.

### One-shot execution

```bash
curl -X POST "$BASE/api/v1/execute" \
  -H "Authorization: Bearer $KEY" \
  -H "Content-Type: application/json" \
  -d '{"command":"echo hello"}'
```

Request fields: `command` (required), `working_dir`, `env` (object),
`timeout_secs` (default 30).

```json
{"success":true,"exit_code":0,"output":"hello\n","duration_ms":5,"timed_out":false}
```

`output` merges stdout and stderr. On timeout, `timed_out` is `true` and the
whole process tree is killed.

### Sessions

```bash
curl -X POST "$BASE/api/v1/sessions" -H "Authorization: Bearer $KEY" \
     -H "Content-Type: application/json" -d '{}'
# {"session_id":1,"session_id_str":"sess-00000001"}

curl -X POST "$BASE/api/v1/sessions/1/execute" -H "Authorization: Bearer $KEY" \
     -H "Content-Type: application/json" -d '{"command":"pwd"}'

curl -X DELETE "$BASE/api/v1/sessions/1" -H "Authorization: Bearer $KEY"
```

Create accepts `shell`, `working_dir`, `env`. Sessions are ready to execute the
moment they are created.

### Streaming over WebSocket

Connect to `$BASE/api/v1/ws` (one-shot) or `$BASE/api/v1/sessions/<id>/ws`,
sending the same `Authorization` header. Messages are JSON, tagged by `type`:

| Direction | Message |
|---|---|
| → server | `{"type":"execute","command":"...","timeout_secs":30}` |
| ← server | `{"type":"output","data":"...","is_final":false}` |
| ← server | `{"type":"result","success":true,"exit_code":0,"duration_ms":5,"timed_out":false}` |
| ← server | `{"type":"error","code":"...","message":"..."}` |
| both | `{"type":"ping"}` / `{"type":"pong"}` |

WebSockets work over a direct connection, through a tunnel, and through the
relay. Server-sent events do not pass through the relay.

### Endpoints

| Method | Path | Capability |
|---|---|---|
| `GET` | `/health` | *(none, no auth)* |
| `GET` | `/api/v1` | *(any valid token)* |
| `GET` | `/api/v1/sessions` | `session.read` |
| `POST` | `/api/v1/sessions` | `session.manage` |
| `GET` | `/api/v1/sessions/{id}` | `session.read` |
| `DELETE` | `/api/v1/sessions/{id}` | `session.manage` |
| `POST` | `/api/v1/sessions/{id}/execute` | `exec` |
| `POST` | `/api/v1/execute` | `exec` |
| `WS` | `/api/v1/ws`, `/api/v1/sessions/{id}/ws` | `exec` |
| `GET` | `/api/v1/fs/list`, `/api/v1/fs/stat`, `/api/v1/fs/file` | `fs.read` |
| `DELETE` | `/api/v1/fs/file` | `fs.write` |
| `POST` | `/api/v1/fs/uploads`, `/api/v1/fs/uploads/{id}/complete` | `fs.write` |
| `GET`, `PATCH`, `DELETE` | `/api/v1/fs/uploads/{id}` | `fs.write` |

`GET /api/v1/fs/uploads/{id}` needs `fs.write`, not `fs.read` — an upload session is a
write operation end to end, including checking where it left off. See [§3.1](#31-files)
for the file endpoints in full, and [§4](#4-authentication-and-capabilities) for why
`fs.read`/`fs.write` need to be requested explicitly. Relay-only endpoints are in
[§5](#5-self-hosted-relay).

### 3.1 Files

By default these reach whatever the account running the server reaches, and `path` is an
absolute path (`C:/data/x.bin`, `/srv/deploy/x.bin`; either separator works). Start with
`--fs-root <dir>` to confine them to one directory instead, and `path` becomes relative
to it. The startup banner names the effective scope either way.

The confinement is worth something for a token holding `fs.read`/`fs.write` and **not**
`exec`. It is not a boundary against a token that can run commands, which can already
read and write anything the server can — see [§4](#4-authentication-and-capabilities).

`stat` and `list` share one entry shape:

```bash
curl "$BASE/api/v1/fs/stat?path=app/payload.bin"
# {"path":"app/payload.bin","size":6291456,"mtime_ms":1785399156632,"is_dir":false}

curl "$BASE/api/v1/fs/list?path=app"
# {"entries":[{"path":"app/payload.bin","size":6291456,"mtime_ms":1785399156632,"is_dir":false}]}
```

`list` is paginated by an opaque path cursor (`?cursor=...&limit=...`), not an offset —
the tree is walked and sorted once per page, so a file added or removed mid-walk shifts
which entries fall on which page but never invalidates a cursor already handed out. Add
`&recursive=true` to walk subdirectories, `&hash=sha256` to get a content hash on every
file in that page (never per whole tree, so a large recursive listing cannot outrun the
relay's 120s request timeout).

`GET /api/v1/fs/file?path=...` serves the whole file, or a `Range` of it — ordinary HTTP,
so any client that already speaks `Range`/`If-Range` gets resumable downloads for free.

`DELETE` removes the named entry. A file, symlink, or other non-directory node needs no
flags — `204`, no body, the same answer this route has always given. A real directory
needs `recursive=true`; without it the request is refused with `400 recursive-required`
naming the flag, so a call meaning to remove one file cannot take a whole tree with it by
mistake. Add `dry_run=true` to see what a removal would take instead of doing it — the
same walk the removal itself uses, without touching anything:

```bash
curl -X DELETE "$BASE/api/v1/fs/file?path=app/build&recursive=true&dry_run=true"
# {"removed":3,"bytes":142311,"entries":["app/build/index.html","app/build/app.js","app/build"],
#  "truncated":false,"dry_run":true}
```

Children are counted before their parent, so a directory follows its own contents in
`entries` rather than leading them — and falls off the list entirely once `limit` cuts it
short. `removed`/`bytes` still cover the whole tree regardless of where the list stops.

Drop `dry_run` (or set it to `false`, the default) and the same request performs the
removal, answering the same body shape. `removed`/`bytes` are exact there — but only when
nothing failed. A tree holding an upload in flight is refused whole, `409
staging-in-tree`, rather than partly removed. A removal where some entries survived
answers `500 partial-delete` with those same fields plus `failures`, the paths that did
not go; a `dry_run` that could not enumerate everything answers `500 preview-incomplete`
instead — nothing was removed there, so its counts are a lower bound rather than exact.
The two share a body shape but not a meaning: treating them alike reports a deletion that
never happened.

This guards against a caller's mistake, not against a caller. A token holding `fs.write`
can already remove anything the server can reach, so `recursive` and `dry_run` exist to
keep an automated caller from taking more than it meant to — they are not a permission
boundary.

**The full upload round trip**, run against a local server with `--fs-root` set and no
auth (the same commands work with an `Authorization: Bearer <key>` header once auth is
on). Real output from a 6 MiB file, split into the default 4 MiB chunk size:

```bash
sha256sum payload.bin
# 94efbf93ba2381251901f7f7a62fe7d57647d3ea17714d6aa5e4f720aa7c210e

split -b 4194304 -d -a 3 payload.bin chunk-
```

```bash
# Open the session: declare the destination, total size, and whole-file digest.
curl -s -X POST "$BASE/api/v1/fs/uploads" \
  -H 'content-type: application/json' \
  -d '{"path":"app/payload.bin","size":6291456,"sha256":"94efbf93ba2381251901f7f7a62fe7d57647d3ea17714d6aa5e4f720aa7c210e"}'
# {"upload_id":"up-0000000000000000","offset":0,"chunk_size":4194304}
```

```bash
# Send each chunk. Content-Range names the offset the chunk starts at; a chunk
# that arrives twice is refused by position (409 offset-mismatch), not silently
# re-appended.
curl -s -X PATCH "$BASE/api/v1/fs/uploads/up-0000000000000000" \
  -H 'content-range: bytes 0-4194303/6291456' --data-binary @chunk-000
# {"upload_id":"up-0000000000000000","offset":4194304,"chunk_size":4194304}

curl -s -X PATCH "$BASE/api/v1/fs/uploads/up-0000000000000000" \
  -H 'content-range: bytes 4194304-6291455/6291456' --data-binary @chunk-001
# {"upload_id":"up-0000000000000000","offset":6291456,"chunk_size":4194304}
```

```bash
# After a drop, ask where to resume from instead of resending from zero.
curl -s "$BASE/api/v1/fs/uploads/up-0000000000000000"
# {"upload_id":"up-0000000000000000","offset":6291456,"chunk_size":4194304}
```

```bash
# Verify the digest and publish. Nothing appears at the destination before this
# call succeeds — the assembled bytes are renamed onto it atomically.
curl -s -X POST "$BASE/api/v1/fs/uploads/up-0000000000000000/complete"
# {"path":"app/payload.bin","sha256":"94efbf93ba2381251901f7f7a62fe7d57647d3ea17714d6aa5e4f720aa7c210e","size":6291456}
```

A checksum mismatch at `complete` returns `422 checksum-mismatch` with `expected` and
`actual` in the body and discards the session — there is nothing to resume, only a new
one to open. `DELETE .../uploads/{id}` abandons a session early, freeing its staged
bytes; an idle session is swept automatically after an hour either way, so an abandoned
transfer never accumulates forever.

---

## 4. Authentication and capabilities

Opaque bearer tokens in `Authorization: Bearer <token>`. `/health` never
requires one. Authentication is off by default and on whenever a public path is
used.

Each token carries a set of capabilities; each route declares the one it needs:

| Capability | Grants |
|---|---|
| `exec` | run commands (HTTP and WebSocket) |
| `session.read` | list and inspect sessions |
| `session.manage` | create and delete sessions |
| `fs.read` | `list`, `stat`, read/download a file |
| `fs.write` | delete a file or a directory tree, and the whole upload-session lifecycle (including reading a session's own resume point) |
| `*` | everything |

Missing or unknown token → **401**. Valid token without the capability → **403**
(empty body; the reason is in the server's debug log).

Presets are a convenience, not a wire contract:

| Preset | Capabilities |
|---|---|
| `operator` | `exec`, `session.read`, `session.manage`, `fs.read`, `fs.write` |
| `read-only` | `session.read` |
| `full-control` | `*` |

**`operator` carries the file capabilities; `read-only` does not, and the difference is
`exec`.** A token that can run commands can already read and write every file the server
can, so withholding the file API from `operator` confined nothing — it only pushed
callers onto a slower route to the same bytes. `read-only` has no `exec`, so withholding
`fs.read` there is a real boundary: such a token has no other way to a file's contents.
Name the capability explicitly if you want a read-only token to read files.

That also means `--fs-root` is a meaningful jail only for a token holding `fs.*` without
`exec` — a deploy push, say:

```bash
shell-tunnel -k readonly-key --preset read-only
shell-tunnel -k ci-key --capabilities exec,session.read
shell-tunnel --fs-root /srv/deploy -k deploy-key --capabilities fs.write
```

Passing `--capabilities` or `--preset` turns authentication on, since a scope
with auth off would be silently meaningless. `--no-auth` still overrides, except
on a public path where it is refused. A key issued without either is
full-control, so existing setups never start failing with 403.

### Host checking

A loopback-bound server answers only to `localhost`, `127.0.0.1`, and `::1`. This
is the one attack CORS cannot stop: a page can have its own name resolved to
`127.0.0.1` (DNS rebinding), which makes the request same-origin, but the `Host`
header still carries the attacker's name. Anything else is refused with a message
naming the host and the `--allow-host` that would permit it.

The check applies only where that threat exists. A server bound to a public
address, or published through a tunnel or relay, is deliberately reachable under
a name shell-tunnel may not know, so checking there would refuse legitimate
traffic instead.

### Audit trail

`--audit-log <file>` appends one JSON object per line for every execution and
every refusal. Off unless a path is given — creating a file nobody asked for is
its own kind of surprise.

If `--fs-root` is also given, the audit log may not resolve inside it: startup
is refused rather than allowed, since an `fs.write` token could otherwise delete
or overwrite the trail recording its own actions. Point `--audit-log` at a
directory outside the fs root.

```bash
shell-tunnel --tunnel --preset operator --audit-log /var/log/shell-tunnel.jsonl
```

```json
{"at_ms":1784646769697,"kind":"execute","identity":{"token_id":"tok_78c6b1db17d3","label":"configured"},
 "route":"POST /api/v1/execute","command":"echo audited","exit_code":0,"timed_out":false,"duration_ms":170}
{"at_ms":1784646769917,"kind":"denied","route":"POST /api/v1/execute","status":401,"reason":"invalid-token"}
{"at_ms":1784646795525,"kind":"denied","identity":{"token_id":"tok_99b8787ac16b","label":"configured"},
 "route":"POST /api/v1/execute","status":403,"reason":"missing-capability:exec"}
```

Logs go to stderr and this banner-style output to stdout, so
`shell-tunnel --tunnel | grep "Public URL"` works.

Read it with `tail -f` or `jq`; entries are appended and never rewritten, and
each is flushed as it happens so a crash does not take the last ones with it.
Executions over WebSocket are recorded the same way — a trail that only saw the
REST path would miss whichever caller preferred streaming.

`--audit-max-bytes <N>` rotates the file to `<file>.1` once it passes that size,
keeping one generation. Unbounded by default; a trail that grows forever
eventually fills the disk it was meant to protect, but how much history to keep
belongs to whoever runs the machine.

**The token is never written.** Entries carry a `token_id` assigned at
registration and the token's label, which identify a caller across a run without
putting a credential in a file that tends to be kept and copied. That id is
per-process: tokens are not persisted, so neither is it.

**Commands are written in full**, which is the substance of the trail — "someone
called `/execute`" says almost nothing. A command that embeds a secret therefore
puts that secret in the log; that is the trade an audit trail makes.

Command *content* is not filtered. A `CommandValidator` primitive ships in the
crate but no handler calls it: a token holding `exec` can run any command. The
capability token is the access control — withhold `exec` to deny execution.

**Event kinds.** `kind` is one of:

| `kind` | Recorded when | Notable fields |
|---|---|---|
| `execute` | a command ran | `command`, `exit_code`, `timed_out`, `duration_ms`, `session_id` (if not one-shot) |
| `denied` | a request was refused | `status`, `reason` |
| `fs.delete` | a file removed, or a whole directory tree removed cleanly | `file`; `bytes`/`entries` (a count) only for a tree removal — a single entry carries neither |
| `fs.delete.dry_run` | a preview that enumerated everything — nothing changed on disk | `file`, `bytes`; `entries` (a count) only when previewing a tree |
| `fs.delete.preview_incomplete` | a preview that hit an enumeration failure — nothing changed on disk | `file`, `bytes`, `entries` (a count — a lower bound here: an entry that could not be enumerated was never counted) |
| `fs.delete.partial` | a directory removal where some entries survived | `file`, `bytes`, `entries` (a count — not a lower bound: an entry whose removal itself failed is still counted, so this is what was attempted, not what actually disappeared) |
| `upload.start` | a session opened | `file` (destination), `bytes` (declared size), `upload_id` |
| `upload.complete` | the digest verified and the file was published | `file`, `bytes`, `digest_ok: true`, `upload_id` |
| `upload.rejected` | the digest did not match at `complete` | `file`, `digest_ok: false`, `upload_id` |
| `upload.failed` | `complete` failed for a reason other than the digest | `file`, `bytes`, `status`, `reason`, `upload_id` |
| `upload.cancel` | a session was cancelled before completing | `file`, `bytes`, `upload_id` |
| `upload.expired` | an idle session was swept automatically after an hour | `file`, `bytes`, `upload_id` |
| `upload.orphaned` | a staging file from a previous run was found and removed at startup | `bytes`, `upload_id` (no `file` — its destination lived only in the session a restart already discarded) |

The four `fs.delete*` kinds carry the outcome in the kind itself rather than in a field
on one shared kind — the same convention the `upload.*` kinds already use. It is what
makes the trail greppable for the one case worth finding on its own: matching `kind`
exactly against `fs.delete` (`jq 'select(.kind == "fs.delete")'`, say) silently misses
every `fs.delete.partial`, which is precisely the removal that did not fully succeed. The
split between `fs.delete.dry_run` and `fs.delete.preview_incomplete` exists for the same
reason: a preview that could not enumerate everything reports the same HTTP `error` and
status as a real partial removal, and needs its own kind so it isn't mistaken for one —
nothing was removed either way, but a plain `fs.delete.dry_run` promises an exact count
that an incomplete one cannot back up.

---

## 5. Self-hosted relay

The relay removes the third-party service from the path. Devices dial **out** to
it, so they need no inbound port; only the relay does.

```
device (NAT) ──outbound──▶ relay (public) ◀──outbound── caller (NAT)
```

### Running the relay

```bash
shell-tunnel relay -H 0.0.0.0 -p 8443 --enroll-token <secret>
```

Omit `--enroll-token` and one is generated and printed. `-H`/`-p` set the bind
address, as everywhere else. Terminate TLS in front of it — one line of Caddy is
enough:

```
relay.example.com { reverse_proxy 127.0.0.1:8443 }
```

The relay derives the URL it advertises from each connection's `Host` /
`X-Forwarded-*` headers, so nothing else is needed behind a proxy.
`--public-base https://relay.example.com` pins a canonical one.

### TLS without a proxy

A relay can terminate TLS itself, which is the difference between tokens
travelling in clear and not:

```bash
# With a certificate you already have
shell-tunnel relay -H 0.0.0.0 -p 8443 --tls-cert fullchain.pem --tls-key key.pem

# Or generate one, no openssl needed. --public-base names the advertised host;
# the URL uses this relay's port (name a port only when a proxy remaps it). With
# fingerprint pinning (below) --public-base is optional.
shell-tunnel relay -H 0.0.0.0 -p 8443 --tls-self-signed --public-base https://relay.example.com
```

`--tls-self-signed` writes `shell-tunnel-cert.pem` and `shell-tunnel-key.pem` on
first run and reuses them afterwards — a relay that minted a fresh certificate on
every restart would invalidate the trust every device was configured with. Name
the paths with `--tls-cert`/`--tls-key` to put them elsewhere.

The startup banner prints the join command a device needs, including a
`--relay-fingerprint` that pins this exact certificate — so a device trusts it by
copying one string, not a file, and the certificate does not need to name the
public address (see below). `--public-base` only sets the URL the banner
advertises; with fingerprint pinning it is optional.

A certificate without its key (or the reverse) is refused at startup, and an
unreadable or mismatched pair stops the relay rather than letting it serve
plaintext. The advertised URL becomes `https://…` automatically.

Renewed certificates are picked up without a restart: the files are checked once
a minute, and a replacement is loaded for new handshakes while existing
connections keep the certificate they started with. A file that is unreadable
mid-renewal leaves the previous certificate in place rather than serving none.

A certificate that is not publicly signed has to be vouched for somehow, and
there are two ways. The banner suggests the first:

**Pin the certificate** (`--relay-fingerprint`). The relay prints a fingerprint;
the device is told to expect exactly that certificate:

```bash
shell-tunnel --relay https://relay.internal:8443 --enroll-token <t> --relay-fingerprint sha256:9f2a1c...
```

This is the SSH model. Nothing is copied but the string — which travels in the
same block of text as the enrolment token — and the certificate does not need to
name the address being dialled, because the certificate itself is what was
verified. Use it for self-signed relays. Do **not** use it for a publicly-signed
certificate, which is replaced on every renewal; there the authority is the
stable thing.

**Name the authority** (`--relay-ca`), for a private CA that signs several
relays:

```bash
shell-tunnel --relay https://relay.internal:8443 --enroll-token <t> --relay-ca ca.pem
```

`--relay-ca` *adds* to the public trust anchors, so a mixed fleet does not become
an all-or-nothing choice. Unlike a fingerprint, it requires the certificate to
name the address being dialled — start the relay with `--public-base` for that
name.

There is deliberately no option to skip verification. Encryption without
authentication stops passive eavesdropping but not an active intermediary, who
would read the enrolment and capability tokens in the clear — and those are
shell access. Requires the `tls` build feature on the relay and
`relay-client` on the device; both ship in the release binaries.

### Attaching a device

```bash
shell-tunnel --port 3000 --preset operator \
  --relay https://relay.example.com --enroll-token <secret> \
  --device-name build-box -k <your-api-key>
```

```
Public URL:  https://relay.example.com/d/build-box   (via relay)
```

The device is named after the machine it runs on, so its URL survives restarts
without anyone naming hosts by hand. `--device-name` overrides that. Names accept
letters, digits, `-` and `_`, up to 64 characters; anything else is refused
rather than sanitized, because the name lands in a URL path. Re-attaching under a
name already held replaces the previous entry, so a device recovers immediately
after a network drop — two machines sharing a hostname would displace each other,
which is when to name them explicitly.

The local port is chosen by the OS unless `-p` says otherwise: behind a relay the
listener only ever talks to this process, so a port in use elsewhere is no reason
for startup to fail.

Set `-k` explicitly when the caller cannot read the device's console — otherwise
the generated key is only visible there.

### Finding attached devices

```bash
curl -H "Authorization: Bearer <enroll-token>" https://relay.example.com/relay/v1/devices
```

```json
{"devices":[{"id":"build-box","label":null,"attached_secs":42,"last_seen_secs":3,
             "public_url":"https://relay.example.com/d/build-box"}]}
```

### Calling a device

```bash
curl -X POST "https://relay.example.com/d/build-box/api/v1/execute" \
  -H "Authorization: Bearer <api-key>" \
  -H "Content-Type: application/json" -d '{"command":"echo hello"}'
```

### Trust model

Two secrets, deliberately separate — they are not interchangeable:

| | Held by | Answers |
|---|---|---|
| `--enroll-token` | the relay | which **devices** may attach, and who may list them |
| `-k` / `--api-key` | each device | which **callers** may run commands there |

The relay forwards `Authorization` untouched and never inspects, stores, or logs
it. Neither secret travels in a URL, so nothing leaks into the access logs of a
proxy in front of the relay.

**Single-tenant.** All devices share one enrol token, so anyone holding it can
attach connections for any device on that relay. Run a relay for devices you
own; it does not isolate tenants from each other.

### Rate limiting on the relay

Every relay route except `/health` is limited per client IP (100/minute by
default, `--no-rate-limit` to disable). This is not decoration: enrolment
attempts land on `/relay/v1/control`, so without a limit a weak enrolment token
can be guessed at line speed.

It is also the *only* place per-caller limiting can work for proxied traffic. A
device replays each request to its own loopback listener, so the device's own
limiter sees `127.0.0.1` for every caller and cannot tell them apart. The relay
still sees the real address.

### Relay endpoints

| Method | Path | Auth |
|---|---|---|
| `GET` | `/health` | none |
| `GET` | `/relay/v1/devices` | `Authorization: Bearer <enroll-token>` |
| `WS` | `/relay/v1/control` | enrol frame (device only) |
| `WS` | `/relay/v1/data` | attach frame (device only) |
| `ANY` | `/d/<device-id>/…` | forwarded to the device unchanged |

---

## 6. CLI reference

| Option | Description | Default |
|---|---|---|
| `-H, --host <ADDR>` | Bind address | `127.0.0.1` |
| `-p, --port <PORT>` | Port | `3000`, or OS-chosen with `--relay` |
| `-c, --config <FILE>` | JSON config file | - |
| `-k, --api-key <KEY>` | Key callers present to run commands here | - |
| `-l, --log-level <LVL>` | error / warn / info / debug / trace | `info` |
| `--no-auth` | Disable authentication | `false` |
| `--require-auth` | Enable auth, generating a key if none given | `false` |
| `--capabilities <C>` | Scope issued tokens, e.g. `exec,session.read` | full-control |
| `--preset <NAME>` | `operator` / `read-only` / `full-control` | full-control |
| `--no-rate-limit` | Disable rate limiting | `false` |
| `--cors-allow-any` | Allow any CORS origin | `false` |
| `--tunnel` | Publish via a Cloudflare quick tunnel | `false` |
| `--tunnel-command <C>` | Publish by running your own tunnel client | - |
| `--relay <URL>` | Attach to a relay (needs `--enroll-token`) | - |
| `--device-name <N>` | Stable name to claim on the relay | this machine's name |
| `--tls-self-signed` | Serve HTTPS with a generated certificate, reused across restarts | `false` |
| `--tls-cert <FILE>` / `--tls-key <FILE>` | Serve HTTPS directly (given together) | `shell-tunnel-{cert,key}.pem` with `--tls-self-signed` |
| `--allow-host <HOST>` | Also answer to this host name (repeatable) | local names only |
| `--relay-fingerprint <FP>` | Expect exactly this certificate (no file, no name matching) | - |
| `--relay-ca <FILE>` | Also trust this authority when dialling a relay | public roots |
| `--audit-log <FILE>` | Append executions and refusals as JSON lines | off |
| `--audit-max-bytes <N>` | Rotate the trail past this size (keeps one generation) | unbounded |
| `--fs-root <PATH>` | Enable the filesystem API, confined to this directory | off |
| `--fs-chunk-size <N>` | Upload chunk size in bytes. Must stay under the relay's 8 MiB body ceiling — refused at startup at or above it | `4194304` (4 MiB) |
| `--check-update` / `--update` / `--no-update-check` | *(self-update builds)* | - |

`shell-tunnel relay [OPTIONS]` additionally accepts:

| Option | Description | Default |
|---|---|---|
| `--enroll-token <T>` | Secret devices present to attach (not `--api-key`) | generated |
| `--public-base <URL>` | Canonical public URL of the relay | derived from headers |

Environment: `SHELL_TUNNEL_HOST`, `SHELL_TUNNEL_PORT`, `SHELL_TUNNEL_API_KEY`,
`SHELL_TUNNEL_LOG_LEVEL`, `RUST_LOG`.

---

## 7. Configuration file

```json
{
  "server": { "host": "0.0.0.0", "port": 8080, "graceful_shutdown": true },
  "security": {
    "auth": { "enabled": true, "api_keys": ["key1"], "preset": "operator", "capabilities": [] },
    "rate_limit": { "enabled": true, "requests_per_window": 100, "window_secs": 60 },
    "cors": { "allow_any": false }
  },
  "transport": { "mode": "none", "command": null },
  "logging": { "level": "info" }
}
```

`transport.mode` is `none`, `cloudflared`, or `command` (with `command` naming
the client to run). CLI flags override the file, as with every setting.

```bash
shell-tunnel -c /etc/shell-tunnel/config.json
```

---

## 8. Failure modes

Nothing fails silently: a requested public path that cannot be established ends
startup rather than serving local-only.

| Symptom | Meaning | Action |
|---|---|---|
| `tunnel error: \`cloudflared\` is not installed` | not on `PATH` | install it, or use `--tunnel-command` |
| `did not publish a public URL within 30s` | tunnel client never printed one | check its own output at `-l debug` |
| `Tunnel closed: the public URL is no longer reachable` | tunnel client died; server exited with it | restart (a new URL is allocated) |
| `--no-auth cannot be combined with a public tunnel` | refused by design | drop `--no-auth` |
| `relay refused this device (bad-token)` | enrol token mismatch | device retries with backoff |
| `relay refused this device (bad-device-name)` | name is not URL-path safe | letters, digits, `-`, `_`, ≤64 |
| **401** on an API call | missing or unknown token | supply `Authorization: Bearer …` |
| **403** on an API call | token lacks the capability | issue with `--preset`/`--capabilities` |
| **429** | rate limit | see `Retry-After`, `X-RateLimit-Remaining` |
| `invalid peer certificate: BadSignature` | `--relay-ca` is not the certificate the relay is serving | copy the relay's *current* `shell-tunnel-cert.pem` |
| `invalid peer certificate: NotValidForName` | certificate does not cover the dialled name | restart the relay with `--public-base <name>` after deleting the certificate and key |
| **502** from a relay URL | device is not attached | check `/relay/v1/devices` |
| **503** from a relay URL | device attached, no free connection | retry; `Retry-After: 1` |
| **504** from a relay URL | device did not answer in 120s | check the device |
| **413** | request body over 8 MiB, or an upload chunk over `chunk_size` | split the request |
| **409** `offset-mismatch` on a chunk `PATCH` | chunk does not continue from the session offset | resend from the `offset` in the body |
| **422** `checksum-mismatch` on `.../complete` | assembled bytes do not match the declared `sha256` | the session is discarded; open a new one |
| **507** on an upload | destination's filesystem is out of space or quota | free space and retry (Windows quota reporting is not covered, only `EDQUOT` on Unix) |
| **400** `recursive-required` on `DELETE .../fs/file` | path is a real directory | pass `recursive=true` to remove it and everything under it |
| **409** `staging-in-tree` on `DELETE .../fs/file` | an upload is in flight somewhere under this directory | cancel it or wait for it to finish, then retry |
| **500** `partial-delete` / `preview-incomplete` on `DELETE .../fs/file?recursive=true` | some entries survived a removal, or could not even be enumerated during a preview | see `failures` in the body; nothing was removed for `preview-incomplete` |

A relay connection that drops is retried with exponential backoff (1s→60s); the
device keeps its URL, so callers need no change. A *tunnel* that dies takes the
server down instead, because a restart would allocate a different URL.

---

## 9. Build features

The default build links no TLS stack, HTTP client, or WebSocket client.

| Feature | Adds | In release binaries |
|---|---|---|
| *(default)* | nothing | ✅ |
| `self-update` | `--update` / `--check-update` | ✅ |
| `tls` | `--tls-cert` / `--tls-key` (serve HTTPS in-process) | ✅ |
| `relay-client` | `--relay` (device side; TLS + WS client) | ✅ |

```bash
cargo build --release                              # zero-dependency core
cargo build --release --features relay-client      # + relay device support
```

The relay *server* (`shell-tunnel relay`) runs in any build. Official release
binaries include both features, so a downloaded binary can do everything
documented here.

---

## 10. Limits

- **Relay proxies request/response HTTP and WebSocket.** Server-sent events
  buffer instead of streaming.
- **Relay is single-tenant** (one shared enrol token, no isolation between devices).
- **8 MiB** request body limit through the relay.
- Each device keeps **4 idle connections** pre-opened; beyond that, requests wait
  briefly for a refill and get **503** after 5 seconds.
- **`--fs-chunk-size` is refused at startup only at or above 8 MiB**, not below it — a
  value one byte under the ceiling (`8388607`) is accepted and sits directly against the
  relay's own body limit, leaving no margin. The default (4 MiB) is the one to keep for
  anything that will ever run behind a relay.
- Quick tunnels change URL on every restart and are documented by Cloudflare as
  testing-only.
- Command content is not filtered; capability scoping is the control.
