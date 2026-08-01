# Changelog

Notable changes per release. Dates are UTC. This project is pre-1.0, so a minor
bump may carry a behaviour change; breaking items are called out explicitly.

## 0.14.0 — 2026-07-31

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

### Fixed

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
