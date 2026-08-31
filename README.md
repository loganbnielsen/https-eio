# https-eio

Authenticated HTTPS client wrapper for [Eio](https://github.com/ocaml-multicore/eio) —
the `Uri.t -> flow -> Tls_eio.t` function [cohttp-eio](https://github.com/mirage/ocaml-cohttp)'s
client expects for its `~https` hook — plus `request`, a shared timeout-bounded HTTP
request helper built on top of it.

`https_for_uri` does exactly three things:

- Detects the system CA trust store via [ca-certs](https://github.com/mirage/ca-certs)
  (no hand-rolled, platform-specific path list).
- Builds a `Tls.Config.client` from that trust store.
- Seeds `Mirage_crypto_rng` before the first real handshake and caches the built
  wrapper, domain-safely (double-checked locking over an `Atomic.t`, not a bare
  `Stdlib.Lazy.t` — see `lib/https_eio.ml` for why).

Extracted after the same ~90 lines were found duplicated, byte-for-byte, across four
packages (aws-eio, obs-loki-eio, obs-prometheus-eio, and Sun's in-tree
`kafka-eio-service`) — see `CHANGES.md`. There's no separate published opam library for
this; cohttp-eio's own repo ships the same pattern as example code
(`cohttp-eio/examples/client_tls.ml`) rather than a reusable package.

`request` was extracted later, for the same reason: obs-loki-eio, obs-prometheus-eio,
kafka-eio-service, and sun-svc's JWKS fetch had each independently rebuilt "validate a
URL, connect with `https_for_uri`'s wrapper, send one request, read a bounded response
body, classify timeout/network failures" on top of this package's own TLS layer. Not a
general-purpose HTTP client — no retries, no connection pooling (a fresh connection per
call), no redirect handling. `aws-eio` is the deliberate exception that still builds its
own transport, for SigV4 byte-fidelity reasons documented in its own README.

## Usage

```ocaml
Eio_main.run @@ fun env ->
match Https_eio.https_for_uri (Uri.of_string "https://example.com") with
| Error e -> failwith (Https_eio.error_to_string e)
| Ok https ->
  let client = Cohttp_eio.Client.make ~https env#net in
  ...
```

```ocaml
Eio_main.run @@ fun env ->
match Https_eio.request ~net:env#net ~clock:env#clock ~meth:`GET
        ~url:"https://example.com/status" () with
| Ok (status, body) -> Printf.printf "%d: %s\n" status body
| Error e -> failwith (Https_eio.request_error_to_string e)
```

## Build

```bash
eval $(opam env)
dune build
```

## Test

```bash
dune runtest
```

No external infrastructure required — the handshake test spins up a local self-signed
TLS server (fixtures in `test/tls_fixtures/`, not trusted by the system CA bundle) and
asserts the handshake fails on certificate trust, not on an unseeded RNG.
