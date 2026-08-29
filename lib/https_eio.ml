type error = [ `Msg of string ]

type https_wrapper =
  Uri.t ->
  [ Eio.Flow.two_way_ty | Eio.Resource.close_ty ] Eio.Std.r ->
  Tls_eio.t

let make_https_wrapper () : (https_wrapper, error) result =
  Mirage_crypto_rng_unix.use_default ();
  match Ca_certs.authenticator () with
  | Error _ as error -> error
  | Ok authenticator ->
    match Tls.Config.client ~authenticator () with
    | Error _ as error -> error
    | Ok tls_config ->
      Ok
        (fun uri raw ->
          let host =
            Uri.host uri
            |> Option.map (fun h -> Domain_name.(host_exn (of_string_exn h)))
          in
          Tls_eio.client_of_flow ?host tls_config raw)

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
let default_https_wrapper_cache : (https_wrapper, error) result option Atomic.t = Atomic.make None
let default_https_wrapper_mutex = Mutex.create ()

let default_https_wrapper () =
  match Atomic.get default_https_wrapper_cache with
  | Some result -> result
  | None ->
    Mutex.lock default_https_wrapper_mutex;
    Fun.protect
      ~finally:(fun () -> Mutex.unlock default_https_wrapper_mutex)
      (fun () ->
        match Atomic.get default_https_wrapper_cache with
        | Some result -> result (* another domain won the race while we waited for the lock *)
        | None ->
          let result = make_https_wrapper () in
          Atomic.set default_https_wrapper_cache (Some result);
          result)

let https_for_uri uri =
  match Uri.scheme uri with
  | Some scheme when String.lowercase_ascii scheme = "https" ->
    Result.bind (host_of_uri uri) (fun _ ->
        Result.map (fun https -> Some https) (default_https_wrapper ()))
  | _ -> Ok None

let error_to_string (`Msg msg) = "TLS setup error: " ^ msg
