# Changes

## 0.1.0

- Initial standalone OPAM package. Extracted from four independent, byte-identical
  copies of the same TLS wrapper code: aws-eio's `Aws_tls`, obs-loki-eio's
  `Obs_loki_tls`, obs-prometheus-eio's `Obs_prometheus_tls`, and Sun's in-tree
  `Kafka_service_tls`. All four are now deleted from their respective packages in
  favor of depending on `Https_eio` directly.
- Replaces each copy's hand-rolled, Linux/macOS-only CA-bundle path list with
  `ca-certs`, which detects the system trust store (including `SSL_CERT_FILE`/
  `NIX_SSL_CERT_FILE`) across more platforms than the four hand-rolled lists covered.
- Carries forward two fixes an independent review found in aws-eio's copy before this
  extraction: `Mirage_crypto_rng` is seeded (`Mirage_crypto_rng_unix.use_default`)
  before the first real TLS handshake — without it, every handshake raised "The
  default generator is not yet initialized" — and the built wrapper is cached with
  double-checked locking over an `Atomic.t`, not a bare `Stdlib.Lazy.t` (documented
  unsafe, and reproducibly broken, across concurrent OCaml 5 domains).
