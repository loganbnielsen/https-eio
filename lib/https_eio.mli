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

type request_error =
  | Invalid_config of string
      (** Invalid [timeout], or [url] is not an absolute [http://]/[https://]
          URL with a host — rejected before any I/O. *)
  | Tls_setup of string  (** TLS setup failed for an [https://] URL. *)
  | Timeout of float  (** The request did not complete within this many seconds. *)
  | Network_error of string
      (** Connection failure, or any other transport-level exception. *)

val request_error_to_string : request_error -> string

val request
  :  net:_ Eio.Net.t
  -> clock:_ Eio.Time.clock
  -> ?timeout:float  (** Request timeout in seconds. Must be positive. Default: [5.0]. *)
  -> meth:Http.Method.t
  -> url:string
  -> ?headers:(string * string) list
  -> ?body:string
  -> ?max_response_bytes:int
      (** Response body is read up to this many bytes, then the connection is
          closed even if more data remains. Default: [1_048_576] (1 MiB). *)
  -> unit
  -> (int * string, request_error) result
(** A timeout-bounded HTTP request through [https_for_uri]'s TLS wrapper, on
    [cohttp-eio]. Returns [(status, body)] for {b any} response, 2xx or not —
    callers classify status codes themselves, the same way {!https_for_uri}
    leaves TLS/certificate policy to its caller. [Eio.Cancel.Cancelled] is
    always re-raised, never converted to [Error].

    Not a general-purpose HTTP client: no retries, no connection pooling
    (a fresh connection is made per call), no redirect handling. Built for
    the shape every non-AWS caller in this ecosystem already needed —
    metrics/log push, schema-registry and admin API calls, JWKS fetch — not
    as a replacement for [cohttp-eio] itself. Callers with different needs
    (SigV4 byte-fidelity, streaming bodies, connection reuse) should keep
    building their own transport. *)
