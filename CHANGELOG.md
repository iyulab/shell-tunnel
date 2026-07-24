# Changelog

Notable changes per release. Dates are UTC. This project is pre-1.0, so a minor
bump may carry a behaviour change; breaking items are called out explicitly.

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
