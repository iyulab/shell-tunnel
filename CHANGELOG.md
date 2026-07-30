# Changelog

Notable changes per release. Dates are UTC. This project is pre-1.0, so a minor
bump may carry a behaviour change; breaking items are called out explicitly.

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
