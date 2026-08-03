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
shell-tunnel --require-auth       # generates a key and prints it on stdout
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
             not saved: a restart generates a new one and every existing caller is refused. Pass --api-key (or SHELL_TUNNEL_API_KEY) to keep it across restarts.
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

### What else a reachable server does

Two things the table below doesn't cover:

- a warning, not a refusal, is printed if rate limiting is disabled — turning it
  off is a legitimate, deliberate choice, so it stays a warning
- only a *generated* key is echoed — a key you supplied is never written to stdout

### What reachability changes

The defaults follow the reachability you asked for. There is no flag to pick a
posture — the bind address and the public path decide it.

| | Loopback bind, no tunnel or relay | Tunnel, relay, or a non-loopback bind |
|---|---|---|
| Authentication | as configured | **required**; a key is generated if none is given |
| Issued token | full control (wildcard) | **`operator`** — the same reach today, but it does not inherit capabilities added later |
| Audit trail | off | **on**, at `shell-tunnel-audit.jsonl` in the working directory unless `--audit-log` says otherwise |
| `--no-auth` | honoured | **refused** |

These rows are not all the same kind of rule. Authentication and the `--no-auth`
refusal are *enforced*: nothing you pass turns them off on a reachable server.
The audit trail is enforced only in that one exists — `--audit-log` moves it.
The issued token's scope is a *default*: naming a scope explicitly (`--preset`,
`--capabilities`) always wins over it, and `--preset full-control` keeps the
wildcard on a reachable server.

A non-loopback bind counts on its own: a LAN is other people's machines. Host
checking (`--allow-host`) answers a different question — which names this server
responds to — and does not narrow what a token can do.

### Surviving a reboot

Losing the connection is already handled: a relay-attached device reconnects
with backoff, and `--device-name` (defaulting to the machine's name) keeps the
same public URL across reconnects. Losing the *process* is not — nothing starts
shell-tunnel again after a reboot, so unattended operation means a service unit.

**Pin these first. Each one changes on restart if you leave it out, and each
break is silent from the server's side:**

| Leave it out | What breaks on restart |
|---|---|
| `-k <key>` | a new key is generated, and every existing caller gets `401`. The new key is only on the console, and the banner warns when it generated one. Behind a relay this is the quietest of the three: `--device-name` keeps the URL alive, so the address you handed out goes on answering — with `401` to everyone. |
| `--device-name <n>` | defaults to the machine's name, which is stable — but if you set one, keep setting it, or the device URL moves |
| `--enroll-token <t>` **on the relay** | a new one is generated and stored nowhere, so every attached device's join line stops working. The devices retry quietly in backoff; nothing says why. The relay's own banner warns when it generated one. |

Use a relay rather than a tunnel for anything unattended. A quick tunnel gets a
new URL on every restart, and the server exits when the tunnel client does; a
relay-attached device keeps one URL.

```ini
# systemd: /etc/systemd/system/shell-tunnel.service
[Unit]
Description=shell-tunnel
After=network-online.target
Wants=network-online.target

[Service]
ExecStart=/usr/local/bin/shell-tunnel --relay https://relay.example.com:8443 --enroll-token st_... --relay-fingerprint sha256:... -k <key> --preset operator --audit-log /var/log/shell-tunnel.jsonl
Restart=always
RestartSec=5
User=shell-tunnel

[Install]
WantedBy=multi-user.target
```

```powershell
# Windows: a service via sc.exe, one line, quoted as one binPath
sc.exe create shell-tunnel binPath= "\"C:\Program Files\shell-tunnel\shell-tunnel.exe\" --relay https://relay.example.com:8443 --enroll-token st_... --relay-fingerprint sha256:... -k <key> --preset operator" start= auto
sc.exe failure shell-tunnel reset= 86400 actions= restart/5000
```

```xml
<!-- launchd: ~/Library/LaunchAgents/com.example.shell-tunnel.plist -->
<key>ProgramArguments</key>
<array>
  <string>/usr/local/bin/shell-tunnel</string>
  <string>--relay</string><string>https://relay.example.com:8443</string>
  <string>--enroll-token</string><string>st_...</string>
  <string>-k</string><string>&lt;key&gt;</string>
</array>
<key>KeepAlive</key><true/>
```

**The enrolment token ends up in the service definition, in the clear.** The
relay join flags are command line only — there is no `relay` section in the
config file and no `SHELL_TUNNEL_RELAY_*` variable — so a unit file holds the
secret where the process list shows it (`ps`, Task Manager) and where anyone who
can read the unit can read it. The API key does not have this problem: put it in
the config file or `SHELL_TUNNEL_API_KEY` and leave `-k` out. Until the join
flags have the same options, restrict who can read the unit file, and treat the
enrolment token as rotatable — a relay restarted with a new `--enroll-token`
invalidates every device's join line at once, which is the recovery path as well
as the hazard.

**What a reboot takes with it, by design:**

- Every session under `/api/v1/sessions`. They live in memory; a client that
  held a session id gets `404` and opens a new one.
- Every upload in flight. Its staging file is left behind and swept as an
  orphan; the transfer starts over rather than resuming.

Neither is recovered on restart, and neither is a failure to report — but a
caller that assumes a session id outlives the process will see it as one.

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
`timeout_secs` (default 30), `max_output_bytes` (default 1 MiB, ceiling 8 MiB).

`command` is the **whole command line**, and there is no `args` array — unlike
`spawn`-style APIs, where the program and its arguments are separate. Sending
one is refused (see below), which it was not before 0.15.0: `{"command":"cmd",
"args":["/c","echo","hi"]}` used to drop the `args`, start a bare shell, and
answer `success: true, exit_code: 0` without running the command.

**The string is handed to a shell as written**, so quoting, redirection, pipes
and `&&` are the shell's to interpret, and quoting a path with spaces works the
way it does at a prompt:

```bash
curl -X POST http://127.0.0.1:3000/api/v1/execute \
  -H "Content-Type: application/json" \
  -d '{"command":"dir /b \"C:\\Program Files\\Common Files\""}'
```

That shell is `cmd /c` on Windows and `/bin/sh -c` on Unix, on **both**
`/execute` and a session's execute (§3.2) — a session runs each command in a
fresh shell of its own, not in a persistent one. `POST /api/v1/sessions` accepts
a `shell` field and it currently has no effect; nothing but `cmd`/`sh` is
spawned either way. Neither does a session carry state between calls: `set
FOO=bar` followed by `echo %FOO%` prints `%FOO%`.

Before 0.15.1 a quote in `command` reached the Windows shell as `\"`, so
`dir /b "C:\Program Files"` was a syntax error and `powershell -c "a | b"` ran
only `a`. A path containing a space had no working form at all.

**A field this server does not recognise is refused, not ignored.** Misspell one
— `workingDir` for `working_dir`, `timeoutSecs` for `timeout_secs` — and the
request fails naming the field and listing the accepted ones, rather than
running with that field's default and reporting success. This matters most on
`DELETE .../fs/file`, where `?dryRun=true` used to delete the file it was asked
to preview (§3.1). The refusal is **422** for a JSON body and **400** for a
query string; the codes differ because the body and the query string are parsed
by different layers, and the message is the same in both.

```json
{"success":true,"exit_code":0,"output":"hello\n","duration_ms":5,"timed_out":false,
 "total_bytes":6,"truncated":false}
```

`output` merges stdout and stderr. On timeout, `timed_out` is `true` and the
whole process tree is killed.

**Output is capped.** `output` carries at most `max_output_bytes` — 1 MiB unless
the request says otherwise — and `total_bytes` reports what the command actually
produced. When the two differ, `truncated` is `true`:

```bash
curl -X POST "$BASE/api/v1/execute" -H "Authorization: Bearer $KEY" \
  -H "Content-Type: application/json" \
  -d '{"command":"cat big.log","max_output_bytes":4096}'
# {"success":true,"exit_code":0,"output":"…4096 bytes…","duration_ms":31,
#  "timed_out":false,"total_bytes":65536,"truncated":true}
```

`truncated` is always present, including when `false`, so a complete answer
never has to be inferred from a missing field. A request may lower the cap or
raise it to the 8 MiB ceiling; a larger value is clamped rather than refused,
and there is no way to disable the cap — an uncapped response is one the relay
cannot deliver (§10). To read more than the cap allows, write the output to a
file and fetch it with `GET /api/v1/fs/file`, which supports `Range`.

The cap applies to the collected result, not to the stream: a WebSocket
consumer receives every chunk regardless, and its `result` message carries
`total_bytes` to confirm the whole stream arrived.

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

**A session groups commands; it does not keep a shell alive.** Each execute runs
in its own `cmd /c` (Windows) or `sh -c` (Unix), the same as `/execute` — so
`set FOO=bar` is not visible to the next call, a `cd` does not persist, and the
`shell` field above currently changes nothing. What a session does give you is
an id the audit trail records against, per-session `working_dir` and `env`, and
a place for streaming to attach. Use `working_dir` rather than a leading `cd`,
and pass what you need in `env`.

### Streaming over WebSocket

Connect to `$BASE/api/v1/ws` (one-shot) or `$BASE/api/v1/sessions/<id>/ws`,
sending the same `Authorization` header. Messages are JSON, tagged by `type`:

| Direction | Message |
|---|---|
| → server | `{"type":"execute","command":"...","timeout_secs":30}` |
| ← server | `{"type":"output","data":"...","is_final":false}` |
| ← server | `{"type":"result","success":true,"exit_code":0,"duration_ms":5,"timed_out":false,"total_bytes":6}` |
| ← server | `{"type":"error","code":"...","message":"..."}` |
| both | `{"type":"ping"}` / `{"type":"pong"}` |

The two directions are not equally strict, and the asymmetry is deliberate. A
message **to** the server carrying a field it does not recognise is answered
with `{"type":"error","code":"PARSE_ERROR"}` rather than being accepted with
that field dropped — `timeoutSecs` for `timeout_secs` otherwise ran the command
with no timeout and reported `timed_out: false`. A message **from** the server
may carry fields a given client does not know, so a consumer should ignore
those rather than reject the message; that is what lets a client keep working
against a later version. Sending a server-shaped message (`output`, `result`,
`error`) to the server is a `PARSE_ERROR` as of 0.15.0, where it was previously
ignored.

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
#  "truncated":false,"dry_run":true,"staging_in_tree":false}
```

Children are counted before their parent, so a directory follows its own contents in
`entries` rather than leading them — and falls off the list entirely once `limit` cuts it
short. `removed`/`bytes` still cover the whole tree regardless of where the list stops.

**A preview reports everything the removal would take, which can include the
`.shell-tunnel-uploads` directory that `list` hides.** The two disagree only while a
transfer is in flight — the directory is removed once the last transfer through it ends —
and `staging_in_tree: true` in the same response is what says so. The preview is not
filtering the trees it reports to match `list`: a preview that hid part of what the
removal would take would be the one lying, and this feature exists on the premise that
it does not.

Drop `dry_run` (or set it to `false`, the default) and the same request performs the
removal, answering the same body shape. `removed`/`bytes` are exact there — but only when
nothing failed. A tree holding an upload in flight is refused whole, `409
staging-in-tree`, rather than partly removed. **A preview is not refused there** — it
touches nothing, so there is no upload to protect it from, and "why can this tree not be
removed" is the question a preview exists to answer. It answers `200` with
`staging_in_tree: true`, which is what keeps a successful preview from reading as
permission to proceed; the removal itself is still refused while that is true. The field
is present on every preview, `false` included, so its absence never has to be
interpreted. A removal where some entries survived
answers `500 partial-delete` with those same fields plus `failures`, the paths that did
not go; a `dry_run` that could not enumerate everything answers `500 preview-incomplete`
instead — nothing was removed there, so its counts are a lower bound rather than exact.
The two share a body shape but not a meaning: treating them alike reports a deletion that
never happened.

**Spell it `dry_run`.** A parameter this server does not recognise is refused with
`400` rather than dropped, which it was not before 0.15.0: `?dryRun=true` used to fall
back to the default `false` and **delete the tree it was asked to preview**, answering
`204` — the same status an ordinary removal answers. The two spellings differed by one
letter's case and both looked like success. The refusal names the parameter and lists
the accepted ones.

`recursive` never had that failure mode, and the asymmetry is worth understanding
before adding a parameter here: omitting `recursive` is already a `400`, so a
misspelling of it lands on the refusal either way. `dry_run` is the opposite shape — an
opt-in to the *safer* behaviour — so dropping it silently left the destructive default
in place. An optional parameter that makes a request safer is only as reliable as the
server's willingness to reject a name it does not know.

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

**While a transfer is in flight the bytes live in a `.shell-tunnel-uploads`
directory**, beside the destination when the file API reaches the whole machine and at
the root of `--fs-root` when one is given. It is removed once the last transfer staging
through it ends — completed, abandoned, or swept — so a directory that receives an
upload does not keep a marker afterwards. `list` never shows it and `stat` and `delete`
refuse it by name while it exists, since a predictable session id would otherwise let
one caller reach into another's transfer.

---

## 4. Authentication and capabilities

Opaque bearer tokens in `Authorization: Bearer <token>`. `/health` never
requires one. Authentication is off by default and on whenever the server is
reachable from other machines — a tunnel, a relay, or a non-loopback bind; see
[§2](#2-running-it).

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
| `file-write` | `fs.read`, `fs.write` — no `exec` |
| `file-read` | `fs.read` — no `exec` |
| `full-control` | `*` |

The cut line is `exec`. A token holding it reaches every file this process can,
so withholding the file API from it confines nothing — which is why `operator`
carries `fs.*`. The `file-*` presets carry no `exec`, and there a `--fs-root`
jail is a real boundary rather than a slow path.

`read-only` was removed in 0.14.0: it granted only `session.read`, so it could
not read a file despite its name. Use `file-read` to read files, or
`--capabilities session.read` for the old set.

**A `file-*` preset is only meaningfully confined when paired with `--fs-root`.**
Without it, a `file-read` token on a reachable server reads every file the
process can — there is no `exec` to make that moot, only the fact that nobody
narrowed the file API. This hazard was always reachable with
`--capabilities fs.read`; a friendly preset name just makes it far easier to
reach by accident. Pair the preset with `--fs-root` whenever the token is meant
to stay inside one directory:

```bash
shell-tunnel -k readonly-key --preset file-read --fs-root /srv/deploy
shell-tunnel -k ci-key --capabilities exec,session.read
shell-tunnel --fs-root /srv/deploy -k deploy-key --preset file-write
```

Passing `--capabilities` or `--preset` turns authentication on, since a scope
with auth off would be silently meaningless. `--no-auth` still overrides, except
on a reachable server (tunnel, relay, or non-loopback bind), where it is
refused. A key issued without either is full-control unless the server is
reachable, in which case it is `operator`; either way existing setups never
start failing with 403.

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

**So `--allow-host` does nothing on such a server, and the startup banner now
says so** rather than accepting the flag in silence. It is not access control —
withholding a name from the list does not keep anyone out, since a caller
holding the token reaches the server under whatever name the tunnel or relay
publishes. Narrow what a token can do with `--capabilities` or `--preset`.

### Audit trail

`--audit-log <file>` appends one JSON object per line for every execution, for
every request the authentication layer refuses, and for the file operations
listed in the `kind` table below. **That table is the whole list** — an outcome
absent from it leaves no entry. Three gaps are worth naming rather than leaving
to be discovered.

**Reading is not recorded.** `list`, `stat` and `download` write nothing when
they succeed: the only file kinds in the table are `fs.delete*` and `upload.*`.
This is the gap with the widest operational reach — on a server started without
`--fs-root`, a token holding `fs.read` can read every file the process can
reach, and the trail stays empty throughout. Three successful reads, zero
entries, measured against a running server rather than read off the table.

A request whose *path* does not resolve — missing, malformed, or escaping
`--fs-root` — is turned away by machinery shared with `list`, `stat`, and
`download`, and writes nothing on any of those routes.

A request turned away **before any handler runs** writes nothing either, and
that is more than the one case this paragraph used to name. Each of these was
sent to a running server with a valid token and left the trail empty:

| Refusal | Status |
|---|---|
| a body carrying a field this server does not recognise (§3) | `422` |
| a query string carrying one | `400` |
| a malformed JSON body | `400` |
| a path parameter that does not parse | `400` |
| a body over the size limit | `413` |

A caller probing `?dryRun=true` against `DELETE .../fs/file` therefore leaves no
trace of having tried — though it also changes nothing, which is the point of
the refusal. Requests the authentication layer turns away first are unaffected:
those are recorded as `denied`, including when the request would also have
failed to parse.

A `denied` entry names the path that was refused, and an unmatched path is
recorded as the caller sent it rather than as a router template — that is the
only description of a probe that exists. Such a path is truncated past 256
bytes, with ` (truncated)` appended; the marker starts with a space, which a
request path cannot contain, so it cannot be forged by a caller who ends a short
path with the same text.

Off on a loopback bind with no tunnel or relay — creating a file
nobody asked for is its own kind of surprise there. A server reachable from
other machines writes one by default, at `shell-tunnel-audit.jsonl` in the
working directory, unless `--audit-log` names another path; see
[§2](#2-running-it).

If `--fs-root` is also given, the audit log — named or defaulted — may not
resolve inside it: startup is refused rather than allowed, since an `fs.write`
token could otherwise delete or overwrite the trail recording its own actions.
This can catch a reachable server that named no `--audit-log`: its default path
lives in the working directory, and if `--fs-root` covers the working directory
too, startup refuses over a file nobody explicitly asked for. Point
`--audit-log` at a directory outside the fs root, or point `--fs-root`
somewhere that excludes the working directory.

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
`shell-tunnel --tunnel | grep "Public URL"` works. Log lines carry no ANSI
escapes: colour is off unconditionally rather than detected, so nothing depends
on where the stream ends up.

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
| `execute` | a command ran | `command`, `exit_code`, `timed_out`, `duration_ms`, `session_id` (if not one-shot), `output_bytes` (**only** when the output was capped — see below) |
| `denied` | a request was refused | `status`, `reason` |
| `fs.delete` | a file removed, or a whole directory tree removed cleanly | `file`; `bytes`/`entries` (a count) only for a tree removal — a single entry carries neither |
| `fs.delete.dry_run` | a preview that enumerated everything — nothing changed on disk | `file`, `bytes`; `entries` (a count) only when previewing a tree |
| `fs.delete.preview_incomplete` | a preview that hit an enumeration failure — nothing changed on disk | `file`, `bytes`, `entries` (a count — a lower bound here: an entry that could not be enumerated was never counted) |
| `fs.delete.partial` | a directory removal where some entries survived | `file`, `bytes`, `entries` (a count — not a lower bound: an entry whose removal itself failed is still counted, so this is what was attempted, not what actually disappeared) |
| `fs.delete.refused` | a removal the server turned away before touching the disk | `file`, `status`, `reason` (`recursive-required`, `staging-in-tree`, or `reserved-path` — the same code the HTTP body carries) |
| `fs.delete.failed` | a removal that was attempted and the filesystem refused | `file`, `status`, `reason` (the underlying error) |
| `upload.start` | a session opened | `file` (destination), `bytes` (declared size), `upload_id` |
| `upload.complete` | the digest verified and the file was published | `file`, `bytes`, `digest_ok: true`, `upload_id` |
| `upload.rejected` | the digest did not match at `complete` | `file`, `digest_ok: false`, `upload_id` |
| `upload.failed` | `complete` failed for a reason other than the digest | `file`, `bytes`, `status`, `reason`, `upload_id` |
| `upload.cancel` | a session was cancelled before completing | `file`, `bytes`, `upload_id` |
| `upload.expired` | an idle session was swept automatically after an hour | `file`, `bytes`, `upload_id` |
| `upload.orphaned` | a staging file from a previous run was found and removed at startup | `bytes`, `upload_id` (no `file` — its destination lived only in the session a restart already discarded) |

`output_bytes` appears on an `execute` entry **only when the output was capped**, and
carries what the command produced rather than what the response returned (§3). Its
presence is the signal — an entry without it describes a response that carried
everything — so a truncated result stays distinguishable from a command that simply
printed little, which is a question the response itself cannot answer once it is gone.
Streaming (`WS …/ws`) executions never carry it: a WebSocket consumer receives every
chunk regardless of the cap, so there is nothing about that delivery to flag.

The `fs.delete*` kinds carry the outcome in the kind itself rather than in a field
on one shared kind — the same convention the `upload.*` kinds already use. It is what
makes the trail greppable for the one case worth finding on its own: matching `kind`
exactly against `fs.delete` (`jq 'select(.kind == "fs.delete")'`, say) silently misses
every `fs.delete.partial`, which is precisely the removal that did not fully succeed. The
split between `fs.delete.dry_run` and `fs.delete.preview_incomplete` exists for the same
reason: a preview that could not enumerate everything reports the same HTTP `error` and
status as a real partial removal, and needs its own kind so it isn't mistaken for one —
nothing was removed either way, but a plain `fs.delete.dry_run` promises an exact count
that an incomplete one cannot back up.

`fs.delete.refused` and `fs.delete.failed` stop there rather than splitting further: the
kinds above are separate because the *accuracy of their counts* differs, and neither of
these carries counts at all — `reason` distinguishes them, and a kind per reason would
widen the grep surface without telling an operator anything the field does not. The two
are separate from each other because they answer different questions: a refusal means the
server said no and the disk was never touched, while a failure means the removal was
attempted and the filesystem turned it down.

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
Try:         curl -X POST https://relay.example.com/d/build-box/api/v1/execute ...
```

Printed when the relay accepts the device, so it lands after the startup log
lines rather than with them. A key this server generated is announced before
that — it has to be, because a relay that never accepts the device leaves the
client retrying in backoff and the key would never be printed at all — so it is
not repeated here; the command above carries it.

A reconnect does not reprint this block. The URL is the same URL, and repeating
it would push the block you are reading off the screen; re-attaching is an
`INFO` line instead, on the same stream that reported the drop.

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
| `-H, --host <ADDR>` | Bind address | `server.host` or `SHELL_TUNNEL_HOST`, else `127.0.0.1` |
| `-p, --port <PORT>` | Port | `server.port` or `SHELL_TUNNEL_PORT`, else `3000`; OS-chosen with `--relay` |
| `-c, --config <FILE>` | JSON config file | - |
| `-k, --api-key <KEY>` | Key callers present to run commands here. **Adds to** a config file's keys rather than replacing them (§7) — unlike `--capabilities`/`--preset`, which replace | - |
| `-l, --log-level <LVL>` | error / warn / info / debug / trace | `info` |
| `--no-auth` | Disable authentication | `false` |
| `--require-auth` | Enable auth, generating a key if none given and printing it on stdout | `false` |
| `--capabilities <C>` | Scope issued tokens, e.g. `exec,session.read` | full-control; `operator` when reachable |
| `--preset <NAME>` | `operator` / `file-write` / `file-read` / `full-control` | full-control; `operator` when reachable |
| `--no-rate-limit` | Disable rate limiting | `false` |
| `--cors-allow-any` | Allow any CORS origin | `false` |
| `--tunnel` | Publish via a Cloudflare quick tunnel | `false` |
| `--tunnel-command <C>` | Publish by running your own tunnel client | - |
| `--relay <URL>` | Attach to a relay (needs `--enroll-token`) | - |
| `--device-name <N>` | Stable name to claim on the relay | this machine's name |
| `--allow-host <HOST>` | Also answer to this host name (repeatable) | local names, when loopback-bound and unpublished; no host checking otherwise |
| `--relay-fingerprint <FP>` | Expect exactly this certificate (no file, no name matching) | - |
| `--relay-ca <FILE>` | Also trust this authority when dialling a relay | public roots |
| `--audit-log <FILE>` | Append executions, denied requests, and file operations as JSON lines — [§4](#audit-trail) lists the kinds | off locally; `shell-tunnel-audit.jsonl` when reachable from other machines |
| `--audit-max-bytes <N>` | Rotate the trail past this size (keeps one generation) | unbounded |
| `--fs-root <PATH>` | Confine the filesystem API to this directory | the whole machine |
| `--fs-chunk-size <N>` | Upload chunk size in bytes. Must stay under the relay's 8 MiB body ceiling — refused at startup at or above it | `4194304` (4 MiB) |
| `--check-update` / `--update` / `--no-update-check` | *(self-update builds)* | - |

The gateway's own socket is plaintext, and `--tls-cert`/`--tls-key`/
`--tls-self-signed` are refused at startup if given to one. Reach it through a
tunnel or a relay, which carry their own TLS, or put a reverse proxy in front —
[§5](#tls-without-a-proxy) covers terminating TLS on the relay instead.

`shell-tunnel relay [OPTIONS]` additionally accepts:

| Option | Description | Default |
|---|---|---|
| `--enroll-token <T>` | Secret devices present to attach (not `--api-key`) | generated |
| `--public-base <URL>` | Canonical public URL of the relay | derived from headers |
| `--tls-self-signed` | Serve HTTPS with a generated certificate, reused across restarts | `false` |
| `--tls-cert <FILE>` / `--tls-key <FILE>` | Serve HTTPS on the relay (given together) | `shell-tunnel-{cert,key}.pem` with `--tls-self-signed` |

Environment: `SHELL_TUNNEL_HOST`, `SHELL_TUNNEL_PORT`, `SHELL_TUNNEL_API_KEY`,
`SHELL_TUNNEL_LOG_LEVEL`, `RUST_LOG`.

`SHELL_TUNNEL_HOST` and `SHELL_TUNNEL_PORT` set the bind address and the port
unless `-H` or `-p` names one, and a config file's `server.host`/`server.port`
work the same way. Until 0.14.0 none of them did: both fields were taken from
`-H` and `-p` on every start, and those flags carry their own defaults
(`127.0.0.1`, `3000`), so a configured value was overwritten even when you
passed no flag at all. **A config file that names `"host": "0.0.0.0"` now
binds there** — and a non-loopback bind is a reachable posture, so that server
requires authentication and writes an audit trail; see
[§2](#what-reachability-changes). Under `--relay` the local port is deliberately
left for the OS to pick, since nothing outside this machine dials it; passing
`-p` is what overrides that.

---

## 7. Configuration file

```json
{
  "server": { "host": "127.0.0.1", "port": 3000, "graceful_shutdown": true },
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
the client to run).

For most keys, passing the matching CLI flag overrides what the file says.
Three cases do not work that way, and each can surprise you:

- **`--api-key` adds to the file rather than replacing it.** A key in the file
  stays valid alongside a key given with `-k`, and alongside
  `SHELL_TUNNEL_API_KEY`. Replacing a key means editing the file, not passing a
  different one on the command line.
- **The `--no-auth`, `--require-auth`, `--no-rate-limit` and `--cors-allow-any`
  flags are one-way.** Passing one sets it; omitting one leaves whatever the
  file said. There is no flag that turns rate limiting back on for a file that
  disabled it.
- **A file asking for a tunnel or a relay changes the auth keys by itself.**
  `transport.mode` of `cloudflared` or `command` makes the server reachable, and
  a reachable server turns `security.auth.enabled` on and scopes an otherwise
  unscoped token to `operator` — with no flag passed at all. See
  [§2](#what-reachability-changes).

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
| `--no-auth cannot be combined with a publicly reachable server` | a tunnel, a relay, or a non-loopback bind | drop `--no-auth`, or bind loopback |
| `A publicly reachable server writes an audit trail, and its default location (shell-tunnel-audit.jsonl) resolves inside --fs-root` | the working directory (where the default audit log lands) sits inside `--fs-root`, and no `--audit-log` was given | pass `--audit-log` with a path outside the fs root, or point `--fs-root` elsewhere |
| `A publicly reachable server writes an audit trail, and its default location (shell-tunnel-audit.jsonl) cannot be created` | the working directory is not writable — a read-only service directory, a share, a protected install location | start the server somewhere writable, or pass `--audit-log` with a path elsewhere |
| `relay refused this device (bad-token)` | enrol token mismatch | device retries with backoff |
| `relay refused this device (bad-device-name)` | name is not URL-path safe | letters, digits, `-`, `_`, ≤64 |
| `cannot start the server/relay: <addr> is already in use by another program` | something else holds that port | `-p` with another port, or stop the holder — the message names the command that finds it. Nothing is printed before the port is taken, so a banner means the port is genuinely held |
| `cannot reach relay: … Nothing answered at <host:port>` | the connection was neither answered nor refused — something between the device and the relay is dropping it | not a flag problem. Check whether the device can open *any* outbound connection to that port; a relay on a port the network already allows out is the usual fix |
| `cannot reach relay: … <host:port> was reached, and nothing is listening on it` | the address and route are fine; the relay is not serving there | check the relay is running and bound to that port |
| `… is set, and this client does not use it` | a proxy environment variable is set, and the device dials the relay directly | on a network that requires a proxy for outbound connections, that alone explains the failure — there is no proxy support to turn on |
| **401** on an API call | missing or unknown token | supply `Authorization: Bearer …` |
| **403** on an API call | token lacks the capability | issue with `--preset`/`--capabilities` |
| **429** | rate limit | see `Retry-After`, `X-RateLimit-Remaining` |
| `invalid peer certificate: BadSignature` | `--relay-ca` is not the certificate the relay is serving | copy the relay's *current* `shell-tunnel-cert.pem` |
| `invalid peer certificate: NotValidForName` | certificate does not cover the dialled name | restart the relay with `--public-base <name>` after deleting the certificate and key |
| **502** `device is not connected` | device is not attached | check `/relay/v1/devices`. The request never reached the device — safe to retry |
| **502** `device did not answer` | the relay could not complete the exchange with the device | see below. The request may already have run |
| **502** on a large `GET .../fs/file` | response body over the relay's 16 MiB ceiling (§10) | fetch it in pieces with `Range` (§3.1); the whole-file form cannot cross the relay |
| **503** from a relay URL | device attached, no free connection | retry; `Retry-After: 1`. The request never reached the device — safe to retry |
| **504** from a relay URL | device did not answer in 120s | check the device. The command may still be running there |
| **413** | request body over 8 MiB (refused by the relay), over 2 MiB on a route that does not set its own ceiling — `.../execute`, `POST .../fs/uploads` — (refused by the server), or an upload chunk over `chunk_size` | split the request. Bulk bytes belong in an upload session, not in a JSON body |
| **409** `offset-mismatch` on a chunk `PATCH` | chunk does not continue from the session offset | resend from the `offset` in the body |
| **422** `checksum-mismatch` on `.../complete` | assembled bytes do not match the declared `sha256` | the session is discarded; open a new one |
| **507** on an upload | destination's filesystem is out of space or quota | free space and retry (Windows quota reporting is not covered, only `EDQUOT` on Unix) |
| **422** `unknown field \`…\`, expected one of …` | a JSON body carries a field this server does not recognise — usually a misspelling such as `workingDir` for `working_dir`, or an `args` array, which `/execute` does not take (§3) | use the name the message lists. Nothing ran |
| **400** `Failed to deserialize query string: … unknown field \`…\`` | a query string carries a parameter this server does not recognise, such as `dryRun` for `dry_run` | use the name the message lists. Nothing was changed |
| **400** `recursive-required` on `DELETE .../fs/file` | path is a real directory | pass `recursive=true` to remove it and everything under it |
| **409** `staging-in-tree` on `DELETE .../fs/file` | an upload is in flight somewhere under this directory | cancel it or wait for it to finish, then retry. `dry_run=true` still answers `200`, with `staging_in_tree: true` |
| **500** `partial-delete` / `preview-incomplete` on `DELETE .../fs/file?recursive=true` | some entries survived a removal, or could not even be enumerated during a preview | see `failures` in the body; nothing was removed for `preview-incomplete` |

A relay connection that drops is retried with exponential backoff (1s→60s); the
device keeps its URL, so callers need no change. A *tunnel* that dies takes the
server down instead, because a restart would allocate a different URL.

### Which failures are safe to retry

A relay failure does not tell you, on its own, whether the request ran. Two of them do:

- **`502 device is not connected`** and **`503`** are decided *before* the relay hands the
  request to a device. Nothing ran. Retrying is safe for any request.
- **`502 device did not answer`** and **`504`** happen *after* the exchange started. The
  device may have run the command and failed only on the way back. Do not blindly retry a
  request that is not safe to run twice.

shell-tunnel does not deduplicate requests: there is no request id, and no result cache.
A retried `POST /execute` is a second execution. Callers that issue commands which must
not run twice need to check the effect themselves before retrying — via a subsequent
`fs` or `execute` call that observes whether the first one landed.

---

## 9. Build features

The default build links no TLS stack, HTTP client, or WebSocket client.

| Feature | Adds | In release binaries |
|---|---|---|
| *(default)* | nothing | ✅ |
| `self-update` | `--update` / `--check-update` | ✅ |
| `tls` | `--tls-cert` / `--tls-key` — a relay serving HTTPS in-process (§6) | ✅ |
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
- **8 MiB** request body limit through the relay. Over it, the relay answers **413**.
- **2 MiB** request body limit on the server's own routes — the lower of these two, so an
  oversized `POST .../execute` or `POST .../fs/uploads` meets it first, with or without a
  relay, and gets **413**. The `.../fs/uploads/{id}` routes are the ones that set their own
  ceiling instead (8 MiB), which is what lets `chunk_size` be as large as it is. Bulk bytes
  belong in an upload session; a large JSON body is not a supported way to move them.
- **16 MiB** response body limit through the relay — a separate ceiling, and the one a
  `GET .../fs/file` on a large file reaches first. Over it, the relay answers **502**:
  the device carries a response body in a single frame, and a frame that large cannot be
  read. Range requests are the way to fetch a bigger file (§3.1); nothing about the file
  itself is wrong.
- Each device keeps **4 idle connections** pre-opened; beyond that, requests wait
  briefly for a refill and get **503** after 5 seconds.
- **`--fs-chunk-size` is refused at startup only at or above 8 MiB**, not below it — a
  value one byte under the ceiling (`8388607`) is accepted and sits directly against the
  relay's own body limit, leaving no margin. The default (4 MiB) is the one to keep for
  anything that will ever run behind a relay.
- Quick tunnels change URL on every restart and are documented by Cloudflare as
  testing-only.
- Command content is not filtered; capability scoping is the control.
