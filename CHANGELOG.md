# Changelog

Notable changes per release. Dates are UTC. This project is pre-1.0, so a minor
bump may carry a behaviour change; breaking items are called out explicitly.

## Unreleased

### Fixed

- **`timeout_secs` is now bounded by the range the API reference has always declared.**
  `docs/openapi.json` has carried `"minimum": 1, "maximum": 300` on that field since the
  route existed, and nothing enforced either. `timeout_secs: 999999999` was accepted and
  honoured — one caller could hold a blocking thread for decades while the published
  reference said the maximum was five minutes. At the other end, `timeout_secs: 0` was
  taken literally as a deadline that had already passed, so the command was killed on the
  control loop's first pass having run nothing at all, and the caller got
  `timed_out: true` for a command that never started.

  Values are **clamped, not refused**, which is the shape `max_output_bytes` already uses:
  a larger value asks for as long as possible and gets 300, a zero asks for the shortest
  timeout there is and gets 1. `timed_out` and `duration_ms` report what actually happened
  either way. The same range now applies over the WebSocket, whose `timeout_secs` carried
  no declared bounds at all.

  The deadline is computed in exactly one place (`Command::effective_timeout`). It had
  been worked out twice — once to time the command out and once to decide when a stalled
  streaming consumer stops being waited on — and clamping only the first would have killed
  a command at the ceiling while still feeding its stream for the hours originally asked
  for.

  **This can change behaviour for a caller who was relying on the unenforced range**: a
  request for longer than 300 seconds now ends at 300 with `timed_out: true`. That is the
  reference being made true rather than a new limit being invented, but it is a behaviour
  change and is called out here for that reason.

- **A command that left a background process behind leaked a thread and a pipe handle,
  every time, for the life of the server.** Each execution attended its two output pipes
  with a dedicated thread doing a blocking `read()`. Such a thread ends only at EOF, and
  EOF needs *every* holder of the write end to close it — so a grandchild that inherited
  those pipes (a daemon, a watcher, anything started in the background) held them open
  for as long as it ran, and the thread blocked forever. Nothing joined those threads,
  so nothing noticed.

  Measured on Windows before the fix: 30 such commands took a server from 21 threads and
  81 handles to 52 and 122, with no path back short of killing the background process.
  Two threads per command rather than one when the background process was quiet on both
  pipes — the common case, since a daemon usually redirects its own output. Commands that
  leave nothing running were never affected: 30 of those moved the figures not at all.

  The pipes are now drained without blocking, from the control loop that already enforces
  the timeout — `PeekNamedPipe` on Windows, `O_NONBLOCK` on Unix — so there is no thread
  to leak and the loop can close its read ends and move on. After the fix the same 30
  commands leave both figures where they started. No new dependency: the one Windows call
  is declared directly.

  **What has not changed:** a background process a command started is still left running.
  Only a timeout kills a process tree; a command that exits on its own has nothing killed
  for it, and that is deliberate — deciding to kill what a caller deliberately started is
  a product question, not a leak fix. What is fixed is narrower and is the part that
  belongs to this server: **its own resources are released either way.**

### Changed

- Two documentation sentences promised more than the code delivers, and are now conditional.
  `docs/USAGE.md` §3 and the `total_bytes` description in `docs/openapi.json` both said a
  streaming consumer receives every chunk. It holds for a consumer that keeps reading; one
  that stops reading while its command runs on can miss chunks produced after that command's
  timeout has passed, which 0.20.0 recorded as the price of removing a stall. The same
  sentence was corrected in §4 at the time; these two were missed.

- `docs/USAGE.md` §3 now states what happens to a process a command leaves running, which
  nothing said before.

## 0.20.0 — 2026-08-05

> ⚠ **Breaking for HTTP callers**, not only for library consumers. The HTTP changes are
> to the session routes; `/execute`, streaming, and the filesystem API are untouched.
> The PTY removal below is breaking for library consumers only — it changes no endpoint,
> no response body, and no CLI flag.

### Removed

- **The `pty` module is gone, and with it the `portable-pty` dependency.**
  `NativePty`, `PtySize`, `PtyHandle`, `AsyncPtyReader`, `AsyncPtyWriter` and
  `default_shell` are no longer exported. The crate has run commands through pipes
  since execution moved off the PTY layer; nothing on any execute path called this
  module afterwards, so it was a published API over code the product itself did not
  use — including a `default_shell()` returning `powershell.exe` / `$SHELL`, which is
  not the shell anything here runs. A command has been executed by `cmd /c` on Windows
  and `/bin/sh -c` elsewhere throughout.

  **If you depended on it**: `NativePty`, `PtySize`, `PtyHandle` and `default_shell` were a
  thin layer over `portable-pty`, so depend on that directly. `AsyncPtyReader` and
  `AsyncPtyWriter` were not — they were this crate's own `spawn_blocking` adapters bridging
  a blocking PTY handle to tokio, and they have no upstream equivalent to swap to. Nothing
  else here changes: no endpoint, no response field, no flag.

  A feature that genuinely needs a terminal brings a PTY layer back deliberately.
  Keeping this one exported meant advertising terminal control the gateway does not
  perform.

- **Three `#[ignore]`d tests came off the shelf rather than being deleted.**
  `test_execute_simple_echo`, `test_execute_with_timeout` and `test_execute_oneshot`
  were skipped as "requires PTY execution". They did not: all three passed on the
  first run once the label was questioned, and they now run on every platform in CI.
  No `#[ignore]`d test remains in the tree.

### Changed

- **`POST /api/v1/sessions` takes no fields.** It used to accept `shell`,
  `working_dir` and `env`. None of the three ever reached a command: a session's
  execute consults the session only for whether it may run, and builds the command
  from the execute request alone. A session created with a `working_dir` ran `cd`
  in the server's own directory; one created with an `env` ran with none of those
  variables set. Sending any of them now answers `422` naming the field, rather
  than accepting it and dropping it. The body may be omitted entirely.

  They are removed rather than wired up because where a command runs is a
  per-execute decision, and `working_dir` and `env` on the execute request already
  carry it — those do take effect and always did.

- **Session status reports `running` instead of `state` and `working_dir`.**
  `state` published a four-value internal enum (`Created`/`Active`/`Idle`/
  `Terminated`) of which two values this API can never return: a session is moved
  past `Created` before the create response is written, and removed from the store
  in the same request that marks it `Terminated`. `working_dir` echoed back what
  creation was given, unchanged, for a directory nothing ran in.

  `running` is the one fact neither `idle_seconds` nor the caller can derive: the
  clock is touched when a command *starts* as well as when it ends, so a session
  thirty seconds into a build and one idle for thirty seconds report the same
  `idle_seconds`. Keeping the enum out of the contract also means a state can be
  added without breaking a caller. `GET /api/v1/sessions` reports the same field
  per entry.

- **Library:** `SessionConfig` and `StateProbe` are gone, `SessionStore::create`
  takes no argument, and `SessionContext` no longer carries a working directory or
  an environment. `StateProbe` existed to recover shell state from a persistent
  shell this product does not keep; nothing called it.

### Fixed

- **A caller that hangs up mid-command no longer leaves the session reporting it
  forever.** A session's execute marked the session busy, awaited the command, and
  marked it idle again — but a caller that disconnects before its response is written
  has the handler's future dropped at that await, so the second half never ran. The
  session stayed busy indefinitely: measured at 44.7 s after the caller of a
  nine-second command vanished, and it would not have recovered on its own. The pair
  is now a guard whose destructor restores the session, which covers cancellation as
  well as every ordinary way out.

- **A consumer that stops reading its stream can now miss chunks, and that is the
  price of the fix below.** Forwarding waits while the channel is full only until the
  command's own deadline; past it, chunks are dropped rather than allowed to hold the
  command open. A consumer that keeps reading is unaffected, and `total_bytes` still
  counts everything the command produced — which is how a short stream is told from a
  quiet command. Measured at 2 KB of 1 MB for a consumer that read nothing until three
  seconds into a two-second command. The audit section's note on streaming said such a
  consumer receives every chunk; it now says under what condition.

- **A streaming consumer that stops reading can no longer stop a command's timeout
  from being enforced.** Output is handed to a WebSocket over a bounded channel, from
  inside the same loop that watches the deadline and reaps the child. A handler that
  stopped receiving without dropping its receiver therefore parked that loop once the
  channel filled: the command ran past its own timeout, its child was never killed,
  and a blocking thread was held for good. Both WebSocket handlers now release the
  receiver as soon as they stop reading, and forwarding gives up on its own once the
  command's deadline has passed — enforcing the timeout is this crate's job, not
  something each consumer has to re-earn.

- **A command driven over a session's WebSocket now counts as running in that session.**
  `/api/v1/sessions/{id}/ws` verifies the session at connect and then hands the command
  straight to the executor, bypassing the one place session state is touched. So a
  session streaming a build reported `running: false` for its whole duration, and its
  idle clock kept running — which, with `running` newly documented as "whether a command
  is running in this session right now", would have been a fresh way for that sentence to
  be false. The socket path now marks the session busy and idle again on every way out,
  including the ones that never reach the executor.

- **The audit section no longer claims every execution is recorded.** It said the trail
  carries "every execution"; a command whose caller hangs up before its result is
  handled writes no entry at all, and it did run. Measured against a running server:
  one completed `/execute` wrote its entry, an identical one abandoned after a second
  left the trail unchanged twelve seconds later. §4 now names this alongside the three
  gaps it already named, and says why it is the one to weigh — in a trail, "no entry"
  and "never ran" look the same.

- **The documentation no longer tells callers to use session fields that do nothing.**
  `docs/USAGE.md` named per-session `working_dir` and `env` as what a session gives
  you and said to use `working_dir` rather than a leading `cd`; following that ran
  the command in the server's directory with no variables set, and reported success.
  `docs/openapi.json` described the same two as taking effect and called the echoed
  `working_dir` the "current working directory". `shell` had been corrected earlier
  and its neighbours had not, which made the rest of the paragraph read as checked.

## 0.19.0 — 2026-08-04

> ⚠ **A minor bump rather than a patch, because of the breaking library changes**
> listed under *Changed*. HTTP callers need no change.

### Added

- **`GET /relay/v1/devices` reports how long each device has been taking to answer.**
  Four fields per device — `exchanges`, `last_exchange_ms`, `mean_exchange_ms`,
  `slowest_exchange_ms` — so a slow relayed request can be attributed without guessing.
  They appear only once a device has answered something; a device nothing has called
  reports none of them rather than zero, which would read as answering instantly. What one
  measurement covers is stated rather than implied: transfer *and* the device's own
  processing together, which the relay cannot separate, with the wait for a free
  connection excluded and failures counted. Reached with the enrol token, as the rest of
  that endpoint is. This replaces a request for an endpoint echoing arbitrary bytes, which
  was declined — it would have been an unauthenticated bandwidth amplifier.

### Fixed

- **A `429` that crossed a relay no longer claims the caller has requests to spare.**
  Two rate limiters sit in series on the proxied path, and the middleware overwrote
  whatever the response already carried — so a refusal from a device with an empty
  bucket arrived stamped with the *relay's* spare budget, up to `X-RateLimit-Remaining: 92`
  beside a `429`. A consumer pacing itself by that header reads a refusal as room to
  continue. The device's headers are now kept where it sent them, and the relay fills
  them in only where the device sent none. Nor is a count added to a `429` that is not a
  rate limit at all — `too-many-uploads` carries no limiter headers, and the limiter that
  *allowed* the request has no spare capacity to claim on somebody else's refusal.
  `Retry-After` was correct all along and is unchanged. §5 of the operating guide states
  which set of headers arrives in each case.
- **A mismatched `--relay-fingerprint` now names the fingerprint.** Pinning worked; the
  diagnostic said nothing. A wrong value produced `cannot reach relay: IO error: invalid
  peer certificate: ApplicationVerificationFailure` — four wrappings ending in a library's
  enum name, never once saying `fingerprint`, and opening with a phrase that sends an
  operator to firewalls and DNS for a relay that answered and offered its certificate. The
  failure now names the flag, prints the pinned value beside the one the relay actually
  sent, says where to copy the current one from, and says that retrying does not help until
  the pin or that certificate changes. §8 of the operating guide gained the row: it listed
  both `--relay-ca` failures and neither of the fingerprint path's, which is the one the
  banner recommends. A dial failure is explained in full once and then referred to by its
  first line: these explanations are paragraphs, a device that cannot attach retries
  forever, and the first live run of the new one produced 47 log lines in six seconds.

- **The `Reachable:` banner no longer presents `operator` as a boundary it is not.** It
  read `tokens are scoped to \`operator\`, not wildcard` under the reachability label, which
  says *reachable now, but narrowed in exchange*. Nothing was narrowed: `operator` holds
  all five capabilities this version defines, so a token scoped to it meets no `403` on any
  route that exists — confirmed by issuing one and walking them. The banner now names the
  capabilities a token actually holds, and where they cover everything, says outright that
  nothing is withheld today. A scope that genuinely narrows, such as `file-read`, does not
  carry that line.

- **An unauthenticated gateway now says so when it can see it is behind a proxy.** Which
  posture a gateway takes is read from its bind address, so a reverse proxy — the
  arrangement its own TLS error message tells an operator to set up — leaves it treating
  itself as local, with authentication off and no audit trail, while being reachable from
  wherever the proxy is. Every request arrives from `127.0.0.1`, so nothing in the bind
  address can reveal it. The first request carrying `X-Forwarded-For`, `X-Real-IP` or
  `Forwarded` now draws a one-time warning naming what is at stake and what to restart
  with. It remains a warning and refuses nothing: the headers are forgeable, and forging
  them only makes the server warn about itself. A proxy that passes none of them leaves no
  evidence and draws no warning — the documented `--require-auth` is still the thing to do,
  not something this replaces. **The default is unchanged**: loopback still means no auth,
  because trading that away is a product decision rather than a bug fix.

- **Public traffic can no longer starve a device off the relay it shares an address with.**
  The relay's per-address limit exists to stop an enrolment token being guessed at line
  speed, but the same bucket also counted the data connections an already-enrolled device
  opens — and since the relay has a device open a fresh one for every proxied request, the
  device's share of that budget was set by whoever called it. Load on an address could
  therefore refuse the enrolments of a device on that address, which is the ordinary case
  when a relay and its devices sit behind one outbound address; it happened, and the device
  backed off in silence. A device's connections are now charged and then **refunded once it
  has proven the enrol token**, so only failed and abandoned attempts accumulate. A guess is
  still charged, so the defence the limit was written for is unchanged.
- **A device refused with `429` says so, and says it will recover.** It reported
  `cannot reach relay: … HTTP error: 429`, which sends an operator to firewalls and DNS for
  a relay that is up and answering. A refusal carrying an HTTP status now reads as a
  refusal rather than a failure to connect, and the `429` case additionally names rate
  limiting as the cause and says the retry recovers on its own.
- **A server started with `--no-rate-limit` no longer advertises a rate limit.**
  It answered `X-RateLimit-Limit: 100 / X-RateLimit-Remaining: 100` on every response —
  a budget nothing was counting, with the remaining count frozen at full forever. A
  client that throttles itself by the header held itself to a limit that did not exist.
  No `X-RateLimit-*` header is sent when limiting is off.
- **Writing the audit trail no longer runs on a runtime worker.** `AuditSink::record`
  opens, writes and flushes a file. The filesystem handlers already threaded that into the
  `spawn_blocking` bodies they were running in, so a slow disk could not starve the pool
  that also serves `/health` and the accept loop — but the execute, WebSocket and
  denial paths have no blocking body of their own and called it from the runtime thread,
  which is the case a trail on a network share or a busy disk turns into stalled unrelated
  requests. Those six call sites now go through a new `AuditSink::record_async`, which is
  awaited rather than detached: the entry still lands before the response, because a trail
  that drops its last entries under load is untrustworthy exactly where it is load-bearing.
  With no trail configured the hop is skipped entirely. What is recorded, and in what
  order, is unchanged.
- **An upload stopped by a Windows disk quota now answers `507`, not `500`.** A quota is
  exhausted with the volume itself far from full, and that case had a counterpart on Unix
  (`EDQUOT`) and none on Windows — so the one answer a client can act on, "free something
  up and retry", arrived as "the server has a bug, file a report". `ERROR_DISK_QUOTA_EXCEEDED`
  now reads as out-of-space alongside the two full-volume codes. `ERROR_NOT_ENOUGH_QUOTA`
  deliberately does not: despite the name it reports a process memory quota, which freeing
  disk space does not resolve. §8 of the operating guide and `docs/openapi.json` both said
  Windows quotas were uncovered; both now state what each platform reports.
- **A server no longer dies because whatever was reading its stdout went away first.**
  `println!` panics on a failed write — the right answer for a command whose output *is*
  the job, and the wrong one for a process that serves afterwards. A banner written into a
  pipe with no reader left is a failed write, so the process exited mid-banner with
  `failed printing to stdout: The pipe is being closed. (os error 232)`, taking the server
  with it. A log shipper restarting, a wrapper's `| head` exiting, a supervisor rotating a
  pipe — the operating guide's own service recipes put a long-lived consumer there, and
  none of this is defensible from outside the process. The banner and the notes a running
  process writes now go through a locked handle and drop a line that cannot be written.
  The startup refusals are unchanged: they write and exit on the next line, so there is
  nothing left running for a panic there to take down.
- **A key the server generates for itself no longer goes to the log.** `serve_on`
  generates an API key when authentication is on and no key was registered, and wrote it
  with `tracing::info!` — a plaintext secret landing in whatever an embedding consumer's
  logs go to, at the level normal operation already runs at. The binary's key stopped
  going there when key issuing moved up to the configuration layer, and appears on the
  startup banner instead; this branch is the one a library consumer reaches, and it kept
  the old line. The key is now sent to `ServerConfig::generated_key`, and where that
  channel is unset the server says it is holding a key nothing can read — the key is
  neither logged nor silently kept, because a generated key nobody has authenticates
  nobody.

### Changed

- **Breaking (library):** `RateLimiter::check` returns `RateLimitDecision` instead of
  `Result<u32, Duration>`. The three variants are `Unlimited`,
  `Allowed { remaining, charge }` and `Limited { retry_after }`; the old signature had no
  way to say "no limit applies" except by reporting a full bucket, which is the defect
  above. Callers matching on `Ok`/`Err` need the two allowed cases separated.
- **Breaking (library):** `relay::registry::DeviceSummary` gained four fields, and
  `RateLimiter::refund` is new — it takes the `RateLimitCharge` from an `Allowed`
  decision, which the rate-limit middleware puts in the request's extensions. Naming the
  slot is what keeps a refund from returning a different caller's; an opaque "give one
  back" cannot tell the difference once the charge it meant has aged out of the window.
- **Breaking (library):** `api::ServerConfig` gained a `generated_key` field — breaking
  for code that constructs it as a struct literal, and `None` (what the builders set)
  restores the previous behaviour minus the log line. `ServerConfig::report_generated_key_to`
  sets it. This is the arrangement `relay::client::RelayClientConfig`'s `enrolled` already
  uses: the library reports the fact and the caller decides where it goes, rather than the
  library choosing a stream on its behalf.

## 0.18.0 — 2026-08-04

> ⚠ **A minor bump rather than a patch, because of one breaking library change**
> (`UploadError::Conflict`, below). HTTP callers need no change.

### Fixed

- **A device reached through a relay no longer advertises an upload chunk size that
  cannot get through.** The relay buffers a request body whole and forwards it as one
  frame, and gives the device a *fixed* 120s for the round trip — so the time a chunk
  needs grows with its size while the budget does not. The advertised default was
  chosen against the relay's body-size ceiling and never against that deadline, which
  left it silently requiring roughly 35 KB/s on the relay↔device leg. Below that a
  transfer did not run slowly, it failed at **zero bytes**, every time, with a `504`
  the caller could not tell apart from a broken link. A relay-joined device now
  advertises 256 KiB, derived from the deadline and a declared floor throughput rather
  than picked, with the relationship held by compile-time assertions.
- **`409 destination-busy` now names the session holding the destination.** A transfer
  lost to a timeout leaves a live session on the path, and every retry bounced off a
  refusal that identified nothing — the destination could be neither resumed nor
  cancelled, because every session route is keyed by an id the refusal declined to
  give. The body now carries `upload_id`.
- **A refused upload session is recorded in the audit trail.** The `upload.*` kinds all
  described sessions that had already opened, so a refusal left silence. This mattered
  most for the concurrent-session cap, which is a capability boundary — it stops a token
  holding only `fs.write` from exhausting process file descriptors and degrading routes
  that token has no capability over — and which fired with no trace at all.
- The startup banner names the effective upload chunk size whenever it is not the
  default, so a deployment that hands out a different number says so.

### Changed

- **Breaking (library):** `UploadError::Conflict` is now `Conflict { upload_id: String }`
  rather than a unit variant. Code matching it needs the field added. HTTP callers are
  unaffected except that the `409` body gained a key.
- Upload session ids are no longer a dense sequence — a refused create consumes one.
  They were never documented as contiguous, and nothing in this crate depends on it.

### Added

- `fs::RELAY_CHUNK_SIZE`, the chunk size advertised over a relay.
- `upload.refused` audit event, carrying `file`, `status`, and `reason`.
- `.cargo/config.toml` with `test-all` and `clippy-all` aliases. With `default = []`,
  a plain `cargo test --all` builds 9 test binaries instead of 16 and reports `ok` —
  the feature-gated suites compile to zero tests rather than failing. The existing
  CI feature-gate check now holds these aliases to the same rule it holds CI to.

### Documentation

- `USAGE.md` §3.2: **a timeout means the outcome is unknown, not that it failed.** A
  chunk that answered `504` may well have been written. The protocol already tolerated
  this — resending the chunk unchanged answers `409 offset-mismatch` with the true
  offset, no extra round trip — but nothing said so, and a consumer discarded 12 MB of
  a completed transfer as a result. No code changed for this; the contract existed and
  the documentation did not.
- `upload_id` format is documented (`^up-[0-9a-f]{16}$`) in `openapi.json`. It is
  lowercase hex, which every worked example had hidden by using session zero.
- `USAGE.md` §8 gains rows for `409 destination-busy` and a corrected `504`.

## 0.17.0 — 2026-08-03

### Fixed

- **The relay banner no longer announces certificate names the certificate does
  not have.** `--tls-self-signed` generates a certificate on first run and
  reuses it afterwards, so the names it carries are fixed at generation. The
  banner reported the names it had *requested* rather than the ones on disk: a
  relay restarted with a `--public-base` its certificate predates printed
  `Certificate covers: relay.example.com` for a certificate that did not name
  it, then offered `--relay-ca` as an alternative that could not verify that
  name. Devices joining with `--relay-fingerprint` were unaffected — that path
  pins the certificate and never checks the name — which is why this stayed
  hidden. The banner now asks the certificate on disk, lists only what it
  genuinely covers, names anything asked for and absent, and says how to
  reissue. Found by running a relay, not by reading it.

### Added

- `TlsFiles::covered_names`, reporting which of a set of names the certificate
  on disk is valid for. No new dependency — the check is `rustls`'s own name
  verification.

### Documentation

- The relay TLS section said `--public-base` gives the certificate that name.
  It does so only when the certificate is generated; a reused one is unchanged.
  Both cases are stated now, in place of the one sentence that covered neither.
- The troubleshooting row for a name mismatch quoted an error string the client
  no longer emits, so searching for what the screen said did not find it. (The
  neighbouring `BadSignature` row was re-checked against a running client and
  is unchanged.)
- `--help` presented `--relay-ca` as how devices trust a self-signed relay. The
  fingerprint printed in the banner is that path, and the caveat about which
  names a generated certificate carries belongs beside the flag that generates
  it.

## 0.16.0 — 2026-08-03

Everything below is startup output — what the program says about itself in the
first second, which is the one surface no test was watching and every operator
reads. Each item was found by running the binary, not by reading it.

### Fixed

- **Logs no longer carry ANSI escapes.** Colour was switched on whenever the
  logging crate was compiled with its `ansi` feature, and that default asks
  nothing about what is downstream: it does not test whether stderr is a
  terminal, and on Windows it does not enable the console's virtual-terminal
  mode. So escapes went wherever the logs went — into the file a service unit
  redirects to, into a pipe, and onto consoles that print them literally as
  `←[2m` in front of every line. Colour is now off unconditionally rather than
  guessed at: answering "can this terminal render an escape?" honestly on
  Windows needs the Win32 console API, which is a platform dependency and a
  block of `unsafe` bought for decoration on a headless gateway. The banner an
  operator actually reads was never coloured.

- **A generated API key now says it is not saved.** The key exists only in
  memory, so a restart issues a different one and every caller configured with
  the old value is refused — exactly the failure the relay's generated
  enrolment token already warned about, on a credential that said nothing.
  Behind a relay it is the quieter of the two: `--device-name` keeps the public
  URL stable across restarts by design, so the address you handed out goes on
  answering, with `401` to everyone. The banner now names `--api-key` and
  `SHELL_TUNNEL_API_KEY` as the way to pin it.

- **A relay's join line is the command, not a template.** It carried a literal
  `--enroll-token <token>` while the URL and certificate fingerprint on the
  same line were filled in, so the one line printed to be copied was the one
  line that could not be. A token the relay generated is already on screen
  three lines above, so the placeholder protected nothing. It is now
  interpolated when the relay generated it; a token you supplied stays a
  placeholder, since you have it already.

- **The audit trail's path is announced once.** An exposed server named it both
  in the posture banner and in a log line, two lines apart. The log line
  remains where it is the only announcement — a local server has no posture
  banner and can still be given `--audit-log`.

### Added

- **A device attached to a relay now prints the same `Try:` command a tunnel
  does.** The relay path announced a public URL and stopped there, so the one
  path that reaches a machine behind NAT was the one that never showed what to
  do with the result. A reconnect does not reprint the block — the URL has not
  changed — and is logged instead, on the stream that reported the drop.

### Changed

- **`relay::client::RelayClientConfig` gains an `enrolled` field** (breaking for
  code that constructs it as a struct literal; `None` restores the previous
  behaviour minus the stdout write). The client used to `println!` the device's
  public URL from inside the library: an embedding consumer got a write to
  stdout it never asked for, and one line of the binary's banner lived where no
  banner test looks — which is why the `Try:` block above could not be added
  until now. The client reports enrolment; the caller decides the wording, and
  whether a reconnect deserves any.

## 0.15.1 — 2026-08-03

### Fixed

- **A `denied` audit entry now names the path that was refused.** A request to a
  path the router does not match carries no route template, and the entry
  recorded the method alone — `{"route": "GET "}`. Scanning the API surface
  unauthenticated therefore left a run of byte-identical lines, and the trail
  that exists to answer "what was probed?" could not. An unmatched path is now
  recorded as the caller sent it; a matched route is still recorded as its
  template (`/api/v1/sessions/{id}`), so entries keep grouping instead of
  splitting one bucket per id.

  Because the raw path is caller-controlled, it is truncated past 256 bytes with
  ` (truncated)` appended. The marker starts with a space, which a request path
  cannot contain, so it cannot be forged.

- **A quote in `command` now reaches the shell as a quote (Windows).** The
  command line was passed with an API that applies the C runtime's
  argument-encoding rules, and `cmd.exe` does not parse its command line that
  way — so `"` arrived as a literal `\"`. Every command that needed quoting
  failed: `dir /b "C:\Program Files"` was a syntax error, `powershell -c "a | b"`
  ran only `a`, and a path containing a space had no working form at all. A
  caller who applied ordinary shell quoting was worse off than one who did not,
  which is the opposite of what an API taking a command line should do.

  Nothing new is granted by this. `/execute` hands its string to a shell by
  definition, so a token holding `exec` could already run anything the account
  can; what changed is that quoting means what it says. Unquoted commands are
  byte-identical, shell operators (`&`, `|`, `&&`) behave as before, and Unix
  was never affected.

- **A startup that could not take its port no longer announces success first.**
  The relay logged and printed `listening on <addr>` — plus a ready-to-paste
  join command — *before* attempting the bind. Against a port already in use,
  those lines were false by the time the failure appeared, and the operator was
  left with a join command for a relay that does not exist; pasting it into a
  device produced a dial timeout with nothing pointing back at the cause. The
  same shape existed on the tunnelled path, where the server was spawned as a
  task and the banner published a public URL, a generated API key, and a `curl`
  example without ever learning whether the port was taken.

  Both now bind first. The gateway already had this split (`api::bind`); the
  relay gained the matching `bind_relay` / `serve_relay_on` pair, and
  `serve_relay` is unchanged for callers with nothing to print in between.

- **A port already in use is reported in words.** Both the gateway and the relay
  ended a failed startup with the `Debug` form of an `io::Error` — `Error:
  Io(Os { code: 10048, kind: AddrInUse, ... })` — the one place in this binary a
  Rust internal reached an operator. The message now names the address, keeps
  the OS text, and gives the platform's command for finding what holds the port.

- **A device that cannot reach its relay now says what happened.** The only
  advice this path carried was for two certificate problems; every network
  failure fell through to a raw OS error, repeated forever with backoff. It did
  not even name the host and port being dialled — the relay URL appears in the
  startup banner and nowhere else.

  A timed-out dial and a refused one now read differently, because they mean
  different things: refused says the relay is not serving there, timed out says
  something between the two machines is dropping the connection. The timeout
  advice states outright that no flag of this program changes it — an operator
  looking at a failure suspects their own arguments first, because those are the
  only variable on screen, and in the incident behind this the host could not
  open *any* outbound connection. If a proxy environment variable is set, that is
  reported too, along with the fact that this client dials directly and does not
  use it.

  Classification comes from `io::ErrorKind`, never from the message text: an OS
  error is written in the machine's own language, and the incident's console was
  in Korean. A unit test pins that, so a regression to string matching fails.

- **A gateway refused a TLS flag by naming flags the caller had not passed.**
  `--tls-self-signed` fills in `--tls-cert`/`--tls-key` while arguments are
  parsed, and the refusal reported those instead — sending the operator looking
  for two flags they never wrote. It now names what was given.

### Documentation

- **A session was described as running a different shell than `/execute`. It
  does not.** Both run `cmd /c` on Windows and `sh -c` on Unix, and a session
  runs each command in a fresh one — `set FOO=bar` is not visible to the next
  call and a `cd` does not persist. The `shell` field on `POST /sessions` is
  accepted and has no effect. USAGE §3 and §3.2 and the OpenAPI schema now say
  all three, and a test pins them so the sentence cannot go stale unnoticed.
  What a session actually offers — an id the audit trail records against,
  per-session `working_dir` and `env`, a place for streaming to attach — is
  stated in its place.

- **`--help` said a gateway serves HTTPS with no reverse proxy needed. Both
  halves were false.** A gateway refuses the TLS flags at startup, and its own
  refusal says to put a reverse proxy in front. The section is now scoped
  ``TLS OPTIONS (with `relay`)`` — matching the scope the relay's other section
  already carried — and states that a gateway's socket is plaintext. The two
  dial-trust flags that were filed under it, `--relay-fingerprint` and
  `--relay-ca`, moved next to `--relay`, which is what they belong to.
  `USAGE.md` §6 listed the same two TLS rows in the gateway table, directly
  above a line introducing the relay's flags as what it "additionally accepts";
  they have moved to the relay table. The prose section on TLS was already
  correct — only the reference tables were wrong.

- **`--help` filed five mode-independent flags under the relay's section.**
  `--check-update`, `--update`, `--no-update-check`, `-h` and `-V` trailed the
  end of ``RELAY OPTIONS (with `relay`)``, having simply been left where the
  list ran out. None of them concerns the relay — one flat parser reads every
  flag, and the update trio exits before a server of either kind starts — and
  the help contradicted itself further down, where the examples show
  `shell-tunnel --check-update` with no subcommand. They now sit under their own
  unscoped `OTHER OPTIONS`. Scoping the TLS header above (previous entry) is
  what sharpened this: once every named section carries a mode, whatever trails
  the last one inherits a scope nobody wrote.

- `USAGE.md` §4 named one gap in the audit trail — requests refused for carrying
  an unrecognised field. Four more refusals reach the same place and were left
  unnamed: a malformed JSON body, a query string that fails to parse, a path
  parameter that fails to parse, and a body over the size limit. The section now
  lists them, and separately states that successful reads (`list`, `stat`,
  `download`) are not recorded at all — previously discoverable only by noticing
  no such kind in the event table.

- **A server that generates its own API key now prints it on stdout, at every
  log level.** `--require-auth` (and `--preset`/`--capabilities`, which also
  switch authentication on) generate a key when none was supplied. On a
  loopback bind that key was created inside the server and reported only as an
  `INFO` log line, so `-l warn` or quieter started a server that enforced
  authentication and told nobody the key — no copy of it existed anywhere, and
  the only symptom was every request answering `401`. The key is now issued
  before the banner and printed there, which is not something a log level can
  silence.

  A reachable server (tunnel, relay, or non-loopback bind) already printed its
  key on the banner and is unchanged.

  Because the key now exists before the server starts, it is no longer written
  to the application log at all. That closes a smaller gap in the same place:
  the audit trail deliberately records no tokens, while the log was carrying
  one in plaintext.

## 0.15.0 — 2026-08-01

### Fixed

- **A request field this server does not recognise is now refused instead of
  dropped.** Every request type accepted unknown fields silently, which is
  serde's default. That is ordinarily harmless, but not here: the optional
  fields on this API either ask for something *safer* or say *where* to act, so
  dropping one leaves the less safe default in place — and the response still
  reports success.

  What that cost, all confirmed against a running server:

  - `DELETE .../fs/file?dryRun=true` **deleted the file it was asked to
    preview**, and answered `204`. The correct spelling, `dry_run=true`,
    answers `200` with the preview and removes nothing. The two differ by one
    letter's case and both are success statuses.
  - `timeoutSecs` ran the command with no timeout at all — five seconds against
    a requested one — and reported `timed_out: false`, which reads as having
    finished within the limit.
  - `workingDir` ran the command in the server's default directory rather than
    the requested one, and reported `success: true`.
  - `{"command": "cmd", "args": [...]}` — the shape `spawn`-style APIs use —
    started a bare shell that exited at EOF and reported `success: true,
    exit_code: 0`, byte-identical to sending no arguments at all. The command
    the caller asked for never ran. (`command` is the whole command line here;
    there is no `args` array.)

  Not every field failed this way, and the exception is the useful one:
  `recursive` already refused a typo, because omitting it is a `400`. It is an
  opt-in to the *destructive* behaviour, so a slip fails safe. `dry_run` is the
  opposite shape, and that is what made the same slip destructive.

  Refusals name the offending field and list the accepted ones, so a caller can
  correct the request from the response alone.

### Changed

- **Breaking: a request carrying an unknown field now fails.** Callers sending
  extra fields will see a refusal where they previously saw success. Those
  fields were already being ignored, so the refusal exposes an existing
  misbehaviour rather than introducing one — a client that relied on a field
  being honoured was not getting that, and a client that sent one harmlessly
  need only stop sending it.

  The refusal is **`422`** for a JSON body and **`400`** for a query string,
  both as `text/plain` rather than the JSON error envelope. The two codes come
  from different layers of request parsing and are documented rather than
  normalised; normalising them would mean a custom extractor on every route
  whose only job is to relabel a status. A request the authentication layer
  turns away first still answers `401`, unchanged.

  Neither refusal reaches the audit trail — both happen before any handler
  runs. `USAGE.md` §4 names the gap alongside the one it already had.

- **Breaking: `WsMessage` is split into `WsClientMessage` and
  `WsServerMessage`.** The two directions want opposite strictness and one
  shared type could only have one. Client input is strict, for the reason
  above. Server output is deliberately *not*, so a consumer built against this
  version keeps parsing a later server that adds a field — locking that down
  would trade one silent failure for another. A client that sent a
  server-shaped message (`output`, `result`, `error`) now gets a parse error
  where it was previously ignored.

### Documentation

- `openapi.json` declares `additionalProperties: false` on request schemas, and
  §8 gains the unknown-field refusal. The `/execute` description now states
  that `command` is a whole command line with no `args` array — the mismatch
  with `spawn`-style APIs is what produced the silent no-op above.

## 0.14.1 — 2026-08-01

### Fixed

- **A relayed request refused for its size now reports the refusal, not a
  connection failure.** A request body over a route's own limit but under the
  relay's 8 MiB ceiling is forwarded to the device, whose server answers `413`
  before the body has finished arriving and then closes. Writing on into a
  closed peer draws a RST, and a RST discards whatever is still unread in the
  receive buffer — so the device's relay client, which wrote the body to
  completion and only then read, lost the answer already sent and reported
  `502 device could not reach its local server` in its place.

  The two point in opposite directions: `413` means split the request, `502`
  sends someone to check whether the device is still alive. It reproduced as a
  race rather than a constant — on loopback the write usually wins, so roughly
  one attempt in ten lost the `413`, while across a relay the first attempt
  lost it.

  The client now reads concurrently with the write and stops writing as soon as
  an answer starts arriving. Neither half suffices alone: reading in parallel
  gets the bytes somewhere a later RST cannot reach, and stopping the write is
  what keeps the RST from being provoked at all.

### Documentation

- **The server's own 2 MiB request body limit is documented.** `USAGE.md`
  counted two ceilings — the relay's 8 MiB request and 16 MiB response — and
  never mentioned the limit that applies to every route setting none of its
  own. It is the lowest of the three and therefore the first one an oversized
  request meets, with or without a relay. §10 gains it, the §8 `413` row names
  all three causes, and `openapi.json` declares `413` on the four routes that
  take a body and do not raise it (`POST /api/v1/execute`, `POST
  /api/v1/sessions`, `POST /api/v1/sessions/{sessionId}/execute`, `POST
  /api/v1/fs/uploads`) — as `text/plain`, since that refusal comes from the
  request layer rather than a handler and so does not carry the JSON error
  envelope.

## 0.14.0 — 2026-08-01

### Added

- **Two audit kinds for a delete that removed nothing.** `fs.delete.refused`
  records a removal the server turned away before touching the disk, with
  `reason` carrying the same code the HTTP body does — `recursive-required`,
  `staging-in-tree`, or `reserved-path`. `fs.delete.failed` records one that
  was attempted and the filesystem turned down, with the underlying error as
  its `reason`. Both carry `status`, the shape the authentication layer's
  `denied` events already use.

  Every other refusal in the file API already left a trail: the authentication
  layer writes `denied`, and an upload that does not complete writes
  `upload.rejected` or `upload.failed`. Delete recorded only its successes, so
  "why did that cleanup not go through" had no answer after the fact — and the
  refusal worth asking that about, a tree held back by an upload in flight, was
  the one leaving no evidence beyond the `409` the caller saw.

  Not split per reason, unlike the four kinds on the success side: those differ
  in how exact their counts are, which is what an operator greps for. Neither
  of these carries counts, so `reason` distinguishes them and the grep surface
  stays where it is.

- **`/execute` output is capped, and says when it was cut.** The response now
  carries `total_bytes` (what the command produced) and `truncated` (whether
  `output` is only a prefix), and `output` stops at `max_output_bytes` — 1 MiB
  unless the request names a smaller figure, or a larger one up to an 8 MiB
  ceiling. `truncated` is always present, including when false, so a complete
  answer is never inferred from a missing field.

  Nothing bounded this before: the only effective limit was the timeout, which
  bounds time rather than size, so a single `cat` of a large file was held whole
  in memory and then serialised into one JSON response — and behind a relay that
  response could not be delivered at all. The filesystem API already worked the
  other way, reporting `truncated` on a listing for exactly this reason;
  `/execute` was the one route outside that rule.

  The cap cannot be disabled, only moved within its ceiling: an uncapped
  response is the failure this exists to prevent. To read more than it allows,
  redirect the output to a file and fetch it with `GET /api/v1/fs/file`, which
  supports `Range`. Streaming is unaffected — a WebSocket consumer receives
  every chunk as it arrives, and its `result` message now carries `total_bytes`
  so it can confirm the whole stream arrived.

- **An `execute` audit entry says when output was capped.** A capped execution
  now records `output_bytes` — what the command produced, not what the response
  returned. The field appears *only* when output was discarded, so its presence
  is the signal and an entry without it describes a response that carried
  everything.

  The response is not kept anywhere, so once a caller holds a short `output`
  the trail was the only place left to learn whether the command had said more
  — and it did not say. A truncated result was indistinguishable after the fact
  from a command that simply printed little. Streaming executions never carry
  it: a WebSocket consumer receives every chunk regardless of the cap, so there
  is nothing about that delivery to flag.

### Fixed

- **`--help` says that `--api-key` adds to a config file's keys.** It described
  what the flag is for but not how it combines, while `--capabilities` and
  `--preset` — right below it, and *replacing* a file's scope since this
  release — read the same way at a glance. An operator passing `-k` to rotate a
  key would leave the file's key valid and have no indication of it. The
  operating guide already said so; the two surfaces drift independently, which
  is why this one went unnoticed.

- **A device no longer treats a failed body read as an empty body.** Reading
  the forwarded request body matched only the success case and fell through to
  an empty `Vec` for everything else, so a read error would have replayed the
  request locally without what it was carrying — a chunk `PATCH` appending
  nothing and answering as though it had. The relay's own receive loop had the
  mirror image of this on the response side. The relay caps a request body
  before forwarding, which is what kept this unreachable; correctness resting
  on an upstream limit is not a contract.

- **A response too large for the relay no longer arrives as an empty `200`.**
  A device returns a response body as a single frame, so a body over the
  WebSocket message limit — 16 MiB — fails the relay's read of it. That failure was
  indistinguishable from a clean close: the receive loop stopped, and the
  status — already taken from the header frame that arrives before the body —
  went out as the device's own. A caller downloading a 20 MiB file got
  `200 OK`, `content-type: application/json`, `content-length: 0`, and no
  indication the file had not been delivered. The same threshold truncated
  large `execute` output.

  The relay now answers `502`, which is what a failed read of an upstream
  response means. Use `Range` to fetch a file larger than one response can
  carry; the ceiling is on a single response, not on the file. Documented
  under Limits alongside the request-body ceiling, which is a separate and
  smaller number — the two were easy to conflate while only one of them was
  written down.

- **A recursive-delete preview is no longer refused by an upload in flight.**
  `dry_run=true` was turned away with the same `409 staging-in-tree` as the
  removal, which left a caller holding a refusal and no way to learn how large
  the tree was or what was holding it — the question a preview exists to answer.
  A preview touches nothing, so there is no upload to protect it from. It now
  answers `200` with a new `staging_in_tree` field, present on every tree
  answer including when `false`, so a successful preview cannot be mistaken for
  permission to proceed. The removal itself is still refused.

- **A generated relay enrolment token says that it is not saved.** Starting
  `shell-tunnel relay` without `--enroll-token` generates one and keeps it
  nowhere, so a restart invalidates every attached device's join line at once —
  and the devices do not report it, they retry in backoff against a token the
  relay no longer knows. The self-signed certificate beside it *is* written to
  disk and reused, which gave an operator every reason to assume the token was
  too. The banner now says otherwise at the one moment they are looking at it.

- **`--allow-host` no longer fails silently on a published server.** Host
  checking is off wherever the server is deliberately reachable under a name it
  may not know — a tunnel assigns one, a relay routes by path — and the flag was
  not merely ignored there but never read, with no warning and no refusal. An
  operator who passed it believed the server answered to one name while it
  answered to every name. The startup banner now says the flag was not applied.

  Turning the check off is unchanged and is not the defect: host checking
  answers DNS rebinding, which does not apply once the server is published, and
  enforcing it would refuse legitimate traffic. It is also not access control —
  a caller holding the token reaches the server under whatever name the tunnel
  or relay publishes. Narrow what a token can do instead.

- **An upload no longer leaves its staging directory behind.**
  `.shell-tunnel-uploads` was created for a transfer and never removed: `.part`
  files were swept but the directory holding them stayed, and since `list`
  hides it and `stat` and `delete` refuse it by name, the file API could not
  clear an artifact the file API had made. Reaching the whole machine that was
  one per directory anyone had ever uploaded to, and a token holding
  `fs.read`/`fs.write` without `exec` — the case `--fs-root` exists for — had
  no way to remove it at all.

  It is now reclaimed when the last transfer staging through it ends, whether
  that transfer completed, was abandoned, or was swept as idle. A directory
  another session is still staging through is left alone, and the reservation
  guard on `stat` and `delete` is unchanged: whoever made the directory clears
  it, rather than the guard being relaxed to let callers do it.

- **`--audit-log` no longer claims to record every refusal.** It records
  executions, requests the authentication layer denies, and the file operations
  the event-kind table lists. The promise was wider than the trail — the two
  delete refusals it missed are recorded as of the `Added` section above, but a
  request whose *path* does not resolve still writes nothing on any file route,
  and the documentation now says so instead of implying otherwise.

### Changed

- **The defaults now follow reachability.** A tunnel, a relay, or a non-loopback
  bind puts the server in a reachable posture: authentication is required, the
  issued token is scoped rather than wildcard, and an audit trail is written. A
  loopback bind with no public path is unchanged — no file is created and
  nothing is narrowed. There is no flag to select this; the reachability you
  asked for decides it.

- **A non-loopback bind counts as reachable on its own.** Previously only a
  tunnel or a relay did, and `-H 0.0.0.0` merely produced a warning when
  combined with one. A LAN is other people's machines.

- **The startup banner names the one combination that is a hazard.** A token
  holding `fs.read`/`fs.write` without `exec` — what `--preset file-read` and
  `--preset file-write` grant — has no route to a file except the file API, so
  `--fs-root` is the only thing that confines it. Run without one, the banner
  now says so on its own line instead of leaving the operator to draw the
  conclusion from three separately true lines. The test is the resolved
  capability set, not the preset name, so `--capabilities fs.read` reaches it
  too; a token holding `exec` never does, since there the file API grants
  nothing `exec` did not already reach. It also requires authentication to be
  on: with `--no-auth` no token is ever demanded and every route is open, so
  there is no scope in force to describe.

### Breaking

- **`/execute` no longer returns unlimited output.** `output` stops at
  `max_output_bytes` (1 MiB by default, 8 MiB ceiling). A caller that relied on
  one response carrying a command's entire output must either lower what the
  command produces, raise the cap within its ceiling, or write the output to a
  file and fetch it with `GET /api/v1/fs/file`. `truncated` and `total_bytes`
  on every response say which case applies. Described under Added above.

- **A configured bind address and port now take effect.** `server.host`,
  `server.port`, `SHELL_TUNNEL_HOST`, and `SHELL_TUNNEL_PORT` were read and
  then overwritten: both fields were assigned from `-H` and `-p` on every
  start, and those flags carry their own defaults, so a configured value never
  survived even when no flag was passed. They now apply unless a flag names
  one.

  **This can change how an existing configuration starts.** A file saying
  `"host": "0.0.0.0"` previously produced a quiet loopback server; it now binds
  `0.0.0.0`, which is a reachable posture — so that server requires
  authentication, scopes its issued token, and writes an audit trail. If a
  loopback bind is what you want, remove the setting or pass `-H 127.0.0.1`.

- **Naming a scope on the command line replaces the file's scope.**
  `--capabilities` did not clear a `preset` the file named; the two were
  unioned, so a file saying `"preset": "operator"` plus a command line saying
  `--capabilities fs.read` issued a token holding operator's whole set *and*
  `fs.read` — `exec` still among them, though the command line was narrowing.
  Either flag now clears both of the file's scope settings before applying what
  was named. Within one command line the union stays: `--preset operator
  --capabilities fs.read` is still a request to add.

  A configuration that relied on adding a capability to a file's preset from
  the command line must now name the whole set it wants, on one side or the
  other. `--api-key` is unchanged and still adds.

- **`--preset read-only` is removed.** It granted only `session.read`, so it
  could not read a file despite its name. `file-read` (`fs.read`) and
  `file-write` (`fs.read`, `fs.write`) replace it with sets that name what they
  grant; `--capabilities session.read` reproduces the old set exactly. An
  unknown preset already refused startup, so this cannot pass silently.

- **A token issued on a reachable server carries `operator`, not the wildcard.**
  Its reach today is the same — `operator` holds `exec`, which reaches every
  file the process can. What changes is that it no longer inherits capabilities
  added in later versions. Pass `--preset full-control` to keep the wildcard.

- **`--no-auth` is refused with a non-loopback bind**, as it already was with a
  tunnel or a relay.

- **A reachable server writes `shell-tunnel-audit.jsonl`** in the working
  directory unless `--audit-log` names another path. This is the second
  exception to "no file is created that nobody asked for" — the first is the
  self-signed certificate, and the shape is the same.

## 0.13.0 — 2026-07-31

### Added

- **Recursive delete, opt-in.** `DELETE /api/v1/fs/file?path=<dir>&recursive=true` removes
  a directory and everything under it. Without the flag a directory is refused with `400
  recursive-required`, so a call meaning to remove one file cannot take a tree with it by
  mistake. A file, symlink, or other non-directory node still needs no flags at all —
  `204`, no body, exactly as before this release.
- **`dry_run=true`** reports what a removal would take — `removed`, `bytes`, and up to
  `limit` `entries` (`truncated` marks a longer list) — through the same walk the removal
  itself uses, without touching the disk.
- A tree holding an upload in flight is refused whole (`409 staging-in-tree`) rather than
  partly removed. A removal that only partly succeeds answers `500 partial-delete` with
  the counts and a `failures` list; a `dry_run` that could not enumerate everything
  answers `500 preview-incomplete` instead, since nothing was removed there and the counts
  are a lower bound rather than exact.
- The audit trail records a directory removal as `fs.delete`, `fs.delete.dry_run`,
  `fs.delete.preview_incomplete`, or `fs.delete.partial`, matching the convention the
  upload events already use — the split is what makes a partial failure greppable on its
  own rather than folded into a generic success kind. `fs.delete.preview_incomplete` is a
  `dry_run` that hit an enumeration failure: the disk is untouched, same as
  `fs.delete.dry_run`, but the entry count is only a lower bound rather than exact.

  These guard against a caller's mistake, not against a caller. A token holding
  `fs.write` can already remove anything the server can reach.

## 0.12.3 — 2026-07-31

### Fixed

- **Relay: a request carrying `Expect: 100-continue` came back `500` even though the
  device handled it.** The relay replayed the header onto the device's own local HTTP
  call; that server answered with an interim `100 Continue`, the device reported the
  interim response as the response, and the relay tried to return `100` as a final
  status — which cannot be written as one, so an empty `500` was substituted.

  The request always succeeded. Only the status the caller saw was wrong, which is the
  worst way for this to fail: a non-idempotent `execute` reported as failed *after it
  had already run*, and an upload chunk written but reported lost. `curl` adds the
  header automatically for bodies over roughly a kilobyte, so this affected every
  sizeable upload while small `execute` payloads did not. Present since 0.10.0.

  If you saw `500` from a relay and retried, check whether the first attempt had
  already taken effect.

### Changed

- CI now runs tests and clippy with `relay-client` enabled, and lints test targets.
  Both relay end-to-end files are gated behind that feature, so the previous
  configuration compiled them to zero tests and reported green without running them —
  which is how the defect above survived three minor versions.

## 0.12.2 — 2026-07-31

### Fixed

- **The upload staging directory was reachable through the file API when no `--fs-root`
  was set.** The guard matched `.shell-tunnel-uploads` as a path prefix, which is where
  it sits inside a jail; without one, staging follows the destination and the name lands
  mid-path, so the test stopped matching. `stat` and `list` reported the directory,
  `download` served in-flight `.part` contents belonging to another upload, and `delete`
  removed another session's staging file. Affects 0.12.0 and 0.12.1. Matched per path
  segment now, at any depth.

  A directory of your own named `.shell-tunnel-uploads` is refused as well. The name is
  reserved.

## 0.12.1 — 2026-07-31

### Fixed

- **Data loss: a second upload into the same directory destroyed the first.** Without
  `--fs-root`, staging follows the destination, so uploads heading for one directory
  share a staging directory — and opening a session swept that directory
  unconditionally, removing an in-flight session's staging file. The session kept its
  open handle, so nothing looked wrong until the end: every chunk answered 200 with an
  advancing offset and the session reported the full size received, then `complete`
  failed with a "file not found" error after the whole file had been uploaded. Affects
  0.12.0 only. The sweep now leaves any staging file younger than the session TTL, and
  leaves any whose age cannot be read.

  If you ran 0.12.0 with concurrent uploads into one directory, transfers that reported
  every chunk accepted but failed at `complete` were lost and need re-sending.

## 0.12.0 — 2026-07-31

### Changed

- **The file API no longer needs `--fs-root`, and no longer confines itself to one
  directory by default.** It now reaches whatever the account running the server
  reaches — the same places a command it runs would. `path` is an absolute path when
  no root is set (`C:/data/x.bin`, `/srv/deploy/x.bin`), and stays root-relative when
  one is. The startup banner names the effective scope on every run.

  The previous default confined the file API while `exec` — which every preset carrying
  file capabilities also carries — could already read and write anything the server
  could. That combination withheld no access; it only forced large transfers onto a
  slower route for any destination outside the chosen directory, which is the opposite
  of what these endpoints exist for. `--fs-root` still confines, for the case where
  confinement is a real boundary: a token granted `fs.read`/`fs.write` and **not**
  `exec`.

  On Windows the old shape could not express the common case at all: there is no path
  above `C:\` and `D:\`, so `--fs-root C:\` could never reach a second drive.

- **`operator` now carries `fs.read` and `fs.write`.** Same reasoning: the preset
  already grants `exec`. `read-only` still carries neither, and there the exclusion is
  a genuine boundary — that preset has no `exec` and so no other route to a file's
  contents.

- **`fs-not-enabled` (403) is no longer reachable from the binary.** There is no longer
  a configuration in which the file API is absent; a token either holds `fs.read`/
  `fs.write` or is refused for the capability it lacks. Deliberate: with `exec` present,
  a switch that turned off the file API would have suggested a protection it could not
  provide. Library callers building an `AppState` without a root still get it.

- `--audit-log` is only checked against `--fs-root` when that flag narrows the scope.
  Machine-wide there is nowhere outside to point the log at; the banner says so rather
  than implying a containment that is not there.

### Fixed

- `--help` aligned the two file-API flags with the rest of the option list.

## 0.11.0 — 2026-07-30

### Added

- **Filesystem API** — list, stat, download, upload, and delete inside a directory named
  by `--fs-root`. Off entirely unless that flag is given at startup.
- Downloads use HTTP `Range`, so resuming needs no client-side protocol beyond what any
  HTTP client already speaks; `If-Range` refuses to stitch a stale prefix onto a file
  that changed mid-transfer, falling back to the whole file instead of serving
  mismatched bytes.
- Uploads run as sessions: declare a size and a whole-file SHA-256, send chunks at
  per-chunk offsets, and the file is verified end to end and renamed into place
  atomically — a partial file never appears at the destination. `--fs-chunk-size` sets
  the advertised chunk size (default 4 MiB); refused at startup at or above the relay's
  8 MiB request-body ceiling, since a chunk that size could never cross a relay anyway.
- `list` is paginated by an opaque path cursor rather than an offset, so a file added or
  removed mid-walk cannot invalidate a page already handed out. An unpaginated listing
  would also exceed the relay's body ceiling on exactly the directory sizes this
  endpoint exists to serve.
- New capabilities `fs.read` and `fs.write`, deliberately absent from the `operator` and
  `read-only` presets: adding them there would hand file access to tokens already issued
  for a server that had none. Request them explicitly — `--capabilities fs.read,fs.write`.
  `full-control`'s wildcard already covers both, as it does every capability.
- Transfers are audited at session granularity — start, completion, checksum rejection,
  and cancellation all leave an entry — including sessions abandoned and later swept for
  being idle too long, so the trail never shows a session starting with no matching end.
- `--audit-log` may not resolve inside `--fs-root`; startup is refused rather than allowed,
  naming both paths. An `fs.write` token could otherwise delete or overwrite the trail
  recording its own actions. The check runs before the log file is opened, so a refused
  startup never leaves a stray file inside the root it declined to trust.
- New default dependency: `sha2`, for the upload integrity check.

## 0.10.0 — 2026-07-24

### Breaking

- **A port-less `--public-base` now inherits the relay's listen port.** Previously
  `--public-base https://relay.example.com` advertised port 443 (the URL scheme
  default) regardless of `-p`, so a relay on `-p 8443` printed URLs nobody was
  serving unless a proxy forwarded 443 here. Now the advertised URL — in the
  startup banner, the enrolment reply, and `/relay/v1/devices` — uses the listen
  port, so a direct-exposed relay works without naming the port twice.

  **Migration — reverse proxy on 443 → 8443:** the old behaviour relied on the
  port-less form meaning 443. Name the port devices actually dial:

  ```
  # before (0.9.x): advertised https://relay.example.com  (port 443)
  shell-tunnel relay -p 8443 --public-base https://relay.example.com
  # after (0.10.0): name the proxy's port explicitly
  shell-tunnel relay -p 8443 --public-base https://relay.example.com:443
  ```

  An explicit port is always honoured verbatim, so `:443` restores the previous
  advertised URL. Relays with no proxy (direct HTTPS on 8443) need no change and
  now advertise `:8443` automatically. The startup banner prints a note whenever a
  port was inherited.

### Changed

- Startup banner: the five-line "restart with `--public-base …:8443`" warning is
  replaced by a two-line note stating which port was inherited and pointing the
  proxy case at the explicit override.
- Docs/help: direct-exposure examples drop the now-redundant `:8443`; the proxy
  example names `:443` explicitly.
