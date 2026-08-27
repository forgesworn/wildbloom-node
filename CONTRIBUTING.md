# Contributing

Open an issue before undertaking a large protocol or storage change.  Small,
well-tested fixes can go straight to a pull request.

All changes must preserve the boundaries in [AGENTS.md](AGENTS.md) and pass:

```sh
cargo fmt --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
cargo audit
```

Use synthetic keys, domains and blob contents in tests.  A passing unit test is
not evidence of cross-device durability, Tor reachability or repair after loss;
state exactly which boundary was exercised.

By contributing, you agree that your contribution is licensed under MIT.

