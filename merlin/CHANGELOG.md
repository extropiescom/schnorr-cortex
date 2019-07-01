# Changelog

## 1.1.0

* Rename transcript functions to avoid any possible confusion between
  protocol-level "commitments" and transcript messages.
* Move design docs to [merlin.cool](https://merlin.cool) and reorient
  the Rust docs around the API.

## 1.0.3

* Remove `rand` dependency in favor of `rand_core`.
* Update README with example of transcript logs.

## 1.0.2

* Update doc comment on Merlin domain separator version string.
* Add an experimental `debug-transcript` feature which does
  pretty-printing.

## 1.0.1

* Update the `curve25519-dalek` dev-dependency used for tests to version `1.0`.

## 1.0.0

* Initial stable version.

## 0.3

* Forces labels to be `&'static`
* Merlin-specific domain separator
* Use a pointer cast instead of a transmute
* Clarify example documentation

## 0.2

* Adds a TranscriptRng for use by the prover.

## 0.1

* Initial prototype version.

