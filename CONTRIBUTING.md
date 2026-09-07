# Contributing

## Before you push

Three commands. CI runs all three, and the first is the one that gets forgotten,
because the other two have aliases and it cannot have one — a cargo alias invokes
a single subcommand.

```bash
cargo fmt --all -- --check   # CI's Lint job fails on this
cargo test-all               # the whole suite (alias, see below)
cargo clippy-all             # lints the way CI does (alias)
```

## Why `test-all` rather than `cargo test --all`

`default = []`, so the suites gated behind the `relay-client` and `tls` features
compile to **zero tests** under a plain `cargo test --all`. They do not fail —
they stop existing, and the run still reports `ok`. Measured 2026-09-07:
721 tests passing under `cargo test --all` against 808 under `cargo test-all` —
22 test binaries run either way, and four of them contain no tests at all
without the features. Both numbers only grow; read them for the gap.

The `test-all` and `clippy-all` aliases in `.cargo/config.toml` carry the
complete feature list, and `tests/ci_feature_gates.rs` holds those aliases and
CI's own command lines to the same rule — so a new gate cannot appear without
turning up in both.

Run plain `cargo test --all` too when you touch dependencies. That build is the
reason `default` stays empty, and CI now runs its tests as well.

## Tests

- **No `#[ignore]`.** There are none, and re-introducing one needs a reason that
  something re-checks. A skip label states a reason, nothing here notices when
  the reason stops being true, and an ignored test looks covered while never
  running. Three of them were removed after being found to pass on the first
  `--ignored` run — their stated reason had not applied for several releases.
- **A new guard should be shown to fail.** Break the thing it guards, watch it go
  red, put it back. A test that passes whether or not the defect is present is
  worse than no test, because it reads as coverage.
- **Wall-clock bounds measure the host.** Several tests here bound "the deadline
  ended the wait" with elapsed time. If you need margin, buy it in the command —
  make the command run for minutes — rather than by widening the bound until a
  real hang would fit through it.

## Documentation

`docs/openapi.json` is the authoritative API reference and `docs/USAGE.md` is the
operating guide. USAGE is prose, so nothing fails when it drifts: a stale
sentence there ships silently and is read as the contract. If you change a flag,
an endpoint, a status code, or a default, change what says so — and prefer
verifying against a running binary, since `--help` output and response bodies are
quoted in those files verbatim.

Two more that a release pass keeps forgetting:

- **`CHANGELOG.md`** is the one public artifact that says what changed *for a
  consumer*. Anything observable from outside belongs in it.
- **Grep for anything that names a release, not only for version numbers.** A
  performance note here once pointed at "this crate's next release" for an
  improvement the next release then shipped — false from the day it went out,
  and matching no search for a version number. `next release`, `unreleased`,
  `upcoming` are the phrases that hide.
