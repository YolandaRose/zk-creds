# Copilot instructions for zk-creds

- This repository is a Rust cryptographic library for anonymous credentials backed by zkSNARKs.
- The main crate entry is `src/lib.rs`; `src/python_exports.rs` is an optional PyO3 wrapper enabled via `--features python`.

- Core design boundaries:
  - `src/attrs.rs` defines the credential attribute model: `Attrs`, `AttrsVar`, `AccountableAttrs`, and `AccountableAttrsVar`.
  - `src/pred.rs` defines the generic `PredicateChecker` trait and the `prove_pred` / `verify_pred` workflow.
  - `src/pseudonymous_show.rs`, `src/revealing_multishow.rs`, and `src/multishow.rs` are where concrete show/predicate semantics are implemented.
  - `src/com_tree.rs`, `src/com_forest.rs`, and `src/compressed_pedersen/` manage Merkle/commitment infrastructure.

- Build and development workflow:
  - Standard Rust build: `cargo build`
  - Run unit tests: `cargo test`
  - Run benchmarks: `cargo bench` (criterion outputs in `target/criterion/`; this also updates `proof_sizes.csv`)
  - Python wrapper flow:
    - `python3 -m venv .env`
    - `source .env/bin/activate`
    - `pip install maturin`
    - `maturin develop`
    - `python3 python-examples/web-demo.py`
  - `src/python_exports.rs` currently contains stub bindings; do not assume a complete Python API.

- Project-specific conventions:
  - `Attrs::commit()` derives randomness deterministically from `get_com_nonce()` via `ChaCha12Rng`.
  - `Attrs` implementations should expose commitment parameters through `get_com_param()` rather than embedding them directly.
  - Predicate public inputs come from `PredicateChecker::public_inputs()` and are intentionally separated from the attribute commitment.
  - `Com`, `ComVar`, `ComNonce`, and `ComNonceVar` are crate-level aliases used throughout the proof stack.
  - The repository pins `ark-crypto-primitives` to a specific git revision in `Cargo.toml`; do not upgrade that dependency without checking compatibility with `arkworks-gadgets`.
  - Default Cargo features are `std`, `parallel`, and `asm`.

- Important patterns to preserve:
  - The library is research-oriented; avoid changing the core ZK trait structure unless necessary.
  - Application-level flows live in `benches/credentials/` and show the intended credential use cases (`passport`, `student_id`, `employee_id`, `common`).
  - `link.rs` is where proof linking / multi-credential show logic is implemented.
  - `src/poseidon_utils.rs` is the canonical place for Poseidon parameter setup and reuse.

- Notes for code changes:
  - Keep the Rust/Python boundary minimal and consistent with the existing crate feature gate.
  - When modifying proofs, follow the existing `PredicateChecker` pattern and preserve the separation between witness attributes and public inputs.
  - Use `benches/credentials/*` examples as the reference for real-world data flows and parameter initialization.

If any section is unclear or missing specific project details, please point me to the area you want expanded.