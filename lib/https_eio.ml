type error = [ `Msg of string ]

type https_wrapper =
  Uri.t ->
  [ Eio.Flow.two_way_ty | Eio.Resource.close_ty ] Eio.Std.r ->
  Tls_eio.t

let make_https_wrapper () : (https_wrapper, error) result =
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

(* tls-eio's handshake needs Mirage_crypto_rng.default_generator seeded before
   it generates any key/nonce material — without this, every TLS handshake
   raises "The default generator is not yet initialized" at the point of
   first use. Nothing in tls-eio or its opam dependency graph does this.
   Computed once, tied to whatever builds the TLS wrapper so pure-signing
   callers that never touch HTTPS don't pay for it. Using the synchronous
   getentropy-based seed (Mirage_crypto_rng_unix.use_default), not the
   Eio-native continuously-reseeding mirage-crypto-rng-eio, to avoid requiring
   env/sw here — getentropy has no accumulator state to go stale (it calls the
   raw getrandom()/getentropy() syscall on every generate, not once at
   startup), so a single blocking syscall at first-TLS-use, not per-handshake
   reseeding, is sufficient indefinitely.

   NOT a bare `lazy`: Stdlib.Lazy is explicitly documented as unsafe across
   domains — concurrent Lazy.force from different domains can raise
   CamlinternalLazy.Undefined, per Lazy.mli, for whichever domain loses the
   race. Fibers within one domain are fine (nothing here performs an Eio
   effect, so a fiber runs this to completion without the scheduler switching
   away), but callers don't get to assume every caller is single-domain.
   Double-checked locking below: the fast path is a lock-free Atomic.get
   (correct under OCaml 5's memory model, unlike a plain ref/mutable field,
   for cross-domain visibility); the mutex is only ever taken on the (at most
   once per domain-race) slow path. *)
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
          Mirage_crypto_rng_unix.use_default ();
          let result = make_https_wrapper () in
          Atomic.set default_https_wrapper_cache (Some result);
          result)

let https_for_uri uri =
  match Uri.scheme uri with
  | Some scheme when String.lowercase_ascii scheme = "https" ->
    Result.map (fun https -> Some https) (default_https_wrapper ())
  | _ -> Ok None

let error_to_string (`Msg msg) = "TLS setup error: " ^ msg
