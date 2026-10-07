type error = [ `Msg of string ]

type https_wrapper =
  Uri.t ->
  [ Eio.Flow.two_way_ty | Eio.Resource.close_ty ] Eio.Std.r ->
  Tls_eio.t

let make_tls_config () =
  Mirage_crypto_rng_unix.use_default ();
  match Ca_certs.authenticator () with
  | Error _ as error -> error
  | Ok authenticator ->
    match Tls.Config.client ~authenticator () with
    | Error _ as error -> error
    | Ok tls_config -> Ok tls_config

(* Build a TLS client configuration whose trust anchors are exactly the
   certificates in the PEM bundle at [path]. This is the deployment's declared
   trust root: a Sol-managed HTTPS client talking to a Sol-managed endpoint
   behind a private CA supplies that CA here, and ordinary chain (RFC 5280) and
   hostname verification still run against it through
   [Tls_eio.client_of_flow ~host].

   A missing, empty or unparseable bundle is an error; verification is never
   silently disabled, and there is no fallback to the system store once a
   declared bundle is supplied. *)
let tls_config_of_ca_file path =
  Mirage_crypto_rng_unix.use_default ();
  match In_channel.with_open_bin path In_channel.input_all with
  | exception Sys_error msg ->
    Error (`Msg (Printf.sprintf "cannot read CA bundle %s: %s" path msg))
  | pem ->
    (match X509.Certificate.decode_pem_multiple pem with
     | Error e ->
       let detail = match e with `Msg m -> m | _ -> "unrecognized error" in
       Error (`Msg (Printf.sprintf "CA bundle %s is not a PEM bundle: %s" path detail))
     | Ok [] -> Error (`Msg (Printf.sprintf "CA bundle %s contains no certificate" path))
     | Ok anchors ->
       let time () = Some (Ptime_clock.now ()) in
       let authenticator = X509.Authenticator.chain_of_trust ~time anchors in
       (match Tls.Config.client ~authenticator () with
        | Error _ as error -> error
        | Ok tls_config -> Ok tls_config))

let host_of_uri uri =
  match Uri.host uri with
  | None | Some "" -> Error (`Msg "HTTPS URI must include a host")
  | Some host -> (
    match Domain_name.of_string host with
    | Error _ -> Error (`Msg ("invalid HTTPS host: " ^ host))
    | Ok domain -> (
      match Domain_name.host domain with
      | Ok host -> Ok host
      | Error _ -> Error (`Msg ("invalid HTTPS host: " ^ host))))

(* Mirage_crypto_rng must be seeded before the first TLS handshake or it
   raises "not yet initialized"; nothing in tls-eio's dependency graph does
   this, so it's seeded lazily here via the synchronous getentropy-based
   Mirage_crypto_rng_unix.use_default (needs no env/sw, unlike the
   continuously-reseeding Eio-native RNG).

   Not a bare `lazy`: Stdlib.Lazy.force is documented unsafe across domains
   (Lazy.mli). Atomic.get gives a lock-free fast path; the mutex is only
   taken on the cold-cache race. *)
let default_tls_config_cache = Atomic.make None
let default_tls_config_mutex = Mutex.create ()

let default_tls_config () =
  match Atomic.get default_tls_config_cache with
  | Some result -> result
  | None ->
    Mutex.lock default_tls_config_mutex;
    Fun.protect
      ~finally:(fun () -> Mutex.unlock default_tls_config_mutex)
      (fun () ->
        match Atomic.get default_tls_config_cache with
        | Some result -> result (* another domain won the race while we waited for the lock *)
        | None ->
          let result = make_tls_config () in
          (match result with
           | Ok _ -> Atomic.set default_tls_config_cache (Some result)
           | Error _ -> ());
          result)

(* The deployment's declared trust root, when one is supplied, replaces the
   system store; callers that do not name one keep the system behaviour. *)
let tls_config ?ca_file () =
  match ca_file with
  | None -> default_tls_config ()
  | Some path -> tls_config_of_ca_file path

let https_for_uri ?ca_file uri =
  match Uri.scheme uri with
  | Some scheme when String.lowercase_ascii scheme = "https" ->
    Result.bind (host_of_uri uri) (fun host ->
        Result.map
          (fun tls_config -> Some (fun _uri raw -> Tls_eio.client_of_flow ~host tls_config raw))
          (tls_config ?ca_file ()))
  | _ -> Ok None

let error_to_string (`Msg msg) = "TLS setup error: " ^ msg

type request_error =
  | Invalid_config of string
  | Tls_setup of string
  | Timeout of float
  | Response_too_large of int
  | Network_error of string

let request_error_to_string = function
  | Invalid_config msg -> msg
  | Tls_setup msg -> msg
  | Timeout t -> Printf.sprintf "request timed out after %gs" t
  | Response_too_large max_bytes ->
    Printf.sprintf "response exceeded the %d-byte limit" max_bytes
  | Network_error msg -> msg

let validate_request_url uri =
  let scheme = Uri.scheme uri |> Option.map String.lowercase_ascii in
  match scheme with
  | Some "http" | Some "https" -> (
    match Uri.host uri with
    | None -> Error (Invalid_config "url must include a host")
    | Some _ -> Ok ())
  | _ -> Error (Invalid_config "url must use http:// or https://")

let request
      ~net
      ~clock
      ?(timeout = 5.0)
      ~meth
      ~url
      ?(headers = [])
      ?body
      ?(max_response_bytes = 1_048_576)
      ?ca_file
      ()
  =
  if timeout <= 0. || classify_float timeout = FP_nan then
    Error (Invalid_config "timeout must be positive")
  else
    let uri = Uri.of_string url in
    match validate_request_url uri with
    | Error _ as e -> e
    | Ok () -> (
      try
        Eio.Time.with_timeout_exn clock timeout (fun () ->
            Eio.Switch.run (fun sw ->
                match https_for_uri ?ca_file uri with
                | Error e -> Error (Tls_setup (error_to_string e))
                | Ok https ->
                  let client = Cohttp_eio.Client.make ~https net in
                  let headers = Http.Header.of_list headers in
                  let body = Option.map Cohttp_eio.Body.of_string body in
                  let resp, resp_body = Cohttp_eio.Client.call client ~sw ~headers ?body meth uri in
                  let status = Http.Status.to_int (Http.Response.status resp) in
                  let body_str =
                    Eio.Buf_read.of_flow resp_body ~max_size:max_response_bytes
                    |> Eio.Buf_read.take_all
                  in
                  Ok (status, body_str)))
      with
      | Eio.Time.Timeout -> Error (Timeout timeout)
      | Eio.Cancel.Cancelled _ as exn -> raise exn
      | (Out_of_memory | Stack_overflow | Sys.Break) as exn -> raise exn
      | Eio.Buf_read.Buffer_limit_exceeded -> Error (Response_too_large max_response_bytes)
      | exn -> Error (Network_error (Printexc.to_string exn)))
