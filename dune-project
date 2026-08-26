(lang dune 3.0)
(name https-eio)
(version 0.1.0)
(generate_opam_files true)

(package
 (name https-eio)
 (synopsis "Authenticated HTTPS client wrapper for Eio (cohttp-eio's ~https hook)")
 (description "\
Builds the `Uri.t -> flow -> Tls_eio.t` wrapper that cohttp-eio's client expects
for its ~https hook: system CA bundle detection (via ca-certs), a Tls.Config.client,
and the one-time Mirage_crypto_rng seed that TLS handshake needs before it can
generate any key/nonce material. Extracted from four independent, byte-identical
copies of this code (aws-eio's Aws_tls, obs-loki-eio's Obs_loki_tls,
obs-prometheus-eio's Obs_prometheus_tls, and Sun's in-tree Kafka_service_tls) after
an unseeded-RNG bug had to be hand-ported across all four. Not a general-purpose TLS
or HTTP library — only the narrow wrapper cohttp-eio's ~https parameter needs.")
 (maintainers "lbendtlynielsen@gmail.com")
 (authors "lbendtly")
 (license "MIT")
 (homepage "https://github.com/loganbnielsen/https-eio")
 (bug_reports "https://github.com/loganbnielsen/https-eio/issues")
 (source (github loganbnielsen/https-eio))
 (depends
  (ocaml (>= 5.4.0))
  (eio (>= 1.3))
  (uri (>= 4.4.0))
  (tls-eio (>= 2.1.0))
  (mirage-crypto-rng (>= 2.1.0))
  (x509 (>= 1.0.0))
  (ca-certs (>= 1.0.1))
  (domain-name (>= 0.5.0))
  (eio_main (and (>= 1.3) :with-test))
  (alcotest :with-test)
  (odoc :with-doc)))
