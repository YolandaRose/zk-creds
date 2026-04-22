<h1 align="center">zkcreds-rs</h1>
<p align="center">
    <a href="https://github.com/rozbb/zkcreds-rs/blob/main/LICENSE-APACHE"><img src="https://img.shields.io/badge/license-APACHE-blue.svg"></a>
    <a href="https://github.com/rozbb/zkcreds-rs/blob/main/LICENSE-MIT"><img src="https://img.shields.io/badge/license-MIT-blue.svg"></a>
    <!--<a href="https://deps.rs/repo/github/rozbb/zkcreds-rs"><img src="https://deps.rs/repo/github/rozbb/zkcreds-rs/status.svg"></a>-->
</p>

A cryptographic library for designing anonymous credential systems in a flexible, issuer-agnostic, and efficient manner using general-purpose zero-knowledge proofs. This code accompanies the zk-creds paper [here](https://eprint.iacr.org/2022/878).

While the core library is written in Rust, this repository also includes an associated Python wrapper module for some of the higher-level interfaces. See [`src/lib.rs`](src/lib.rs), [`python-examples`](python-examples), and Web Demo below for more details.

## Development and Examples

For an overview of this library and usage snippets, see the wiki [here](https://github.com/rozbb/zkcreds-rs/wiki).

## Web Demo

With Rust v1.48+ and Python v3.7+ installed:

```bash
$ cd zkcreds
$ python3 -m venv .env
$ source .env/bin/activate
$ python server.rs

Interact with the demo to get an idea for how arbitrary attribute fields can be formulated into a credential, and how this credential can be issued and subsequently shown without revealing any more than the fact that it satisfies the given criteria.


## Benchmarks

You can run benchmarks using `cargo bench`. This will produce `criterion` benchmarks in `target/criterion/`. It will also create `proof_sizes.csv`, which records proof sizes across various benchmarks.

The passport benchmarks will error if you do not provide a valid passport dump. The student-ID benchmark expects `benches/credentials/student_id/student_card.json` (copy from `student_card.example.json`, then run `sign_student_record.ps1` with the same demo issuer key as the passport bench).

## License

 This library is distributed under either of the following licenses:
 
 * Apache License v2.0 ([LICENSE-APACHE](LICENSE-APACHE))
 * MIT License ([LICENSE-MIT](LICENSE-MIT))
 
Unless explicitly stated otherwise, any contribution made to this library shall be dual-licensed as above (as defined in the Apache v2 License), without any additional terms or conditions.

## Authors

* Michael Rosenberg - micro@cs.umd.edu
* Jacob White - white570@purdue.edu
