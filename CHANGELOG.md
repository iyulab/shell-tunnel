# Changelog

Notable changes per release. Dates are UTC. This project is pre-1.0, so a minor
bump may carry a behaviour change; breaking items are called out explicitly.

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
- New capabilities `fs.read` and `fs.write`, deliberately absent from every preset
  (`operator`, `read-only`, `full-control`): adding them to an existing preset would
  hand file access to tokens already issued for a server that had none. Request them
  explicitly — `--capabilities fs.read,fs.write`.
- Transfers are audited at session granularity — start, completion, checksum rejection,
  and cancellation all leave an entry — including sessions abandoned and later swept for
  being idle too long, so the trail never shows a session starting with no matching end.
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
