type error = [ `Msg of string ]
(** TLS/CA setup errors, matching ca-certs' and tls's own error shape. HTTPS
    connections fail closed if no system CA bundle can be found; certificate
    verification is never silently disabled. *)

type https_wrapper =
  Uri.t ->
  [ Eio.Flow.two_way_ty | Eio.Resource.close_ty ] Eio.Std.r ->
  Tls_eio.t
(** The exact shape cohttp-eio's client expects for its [~https] hook. *)

val https_for_uri : Uri.t -> (https_wrapper option, error) result
(** Return [Some wrapper] for [https://] URIs, [None] otherwise. HTTPS URIs
    must include a DNS hostname accepted by [domain-name]; invalid hosts return
    [Error _] before any TLS handshake. The returned wrapper captures the
    validated host for SNI/certificate verification. *)

val error_to_string : error -> string
(** Human-readable error text suitable for logs. *)
