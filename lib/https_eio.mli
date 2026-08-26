type error = [ `Msg of string ]
(** TLS/CA setup errors, matching ca-certs' and tls's own error shape. HTTPS
    connections fail closed if no system CA bundle can be found; certificate
    verification is never silently disabled. *)

type https_wrapper =
  Uri.t ->
  [ Eio.Flow.two_way_ty | Eio.Resource.close_ty ] Eio.Std.r ->
  Tls_eio.t
(** The exact shape cohttp-eio's client expects for its [~https] hook. *)

val make_https_wrapper : unit -> (https_wrapper, error) result
(** Build a fresh HTTPS wrapper: detect the system CA bundle (via ca-certs) and
    construct a {!Tls.Config.client}. Does not seed the RNG or cache its
    result — most callers want {!https_for_uri} instead. *)

val https_for_uri : Uri.t -> (https_wrapper option, error) result
(** Return [Some wrapper] for [https://] URIs, [None] otherwise. Seeds
    {!Mirage_crypto_rng} on first use (a real TLS handshake cannot generate
    key/nonce material before that) and caches the built wrapper across
    calls, domain-safely. *)

val error_to_string : error -> string
(** Human-readable error text suitable for logs. *)

val default_https_wrapper_cache : (https_wrapper, error) result option Atomic.t
(** Exposed only so tests can force a cold cache before exercising the
    first-use domain race. Not part of the module's intended API. *)
