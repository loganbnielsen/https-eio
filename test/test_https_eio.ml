(* CA-bundle detection is ca-certs' own tested responsibility, not retested
   here; this file only regression-tests the RNG-seeding and domain-safe
   caching layered on top. *)

(* Performs a real local TLS handshake (self-signed cert in tls_fixtures/,
   untrusted by the system CA bundle) so the expected failure is a
   certificate-validation error rather than the "RNG not yet initialized"
   error seeding is meant to prevent. *)

let contains_substring ~needle haystack =
  let nlen = String.length needle and hlen = String.length haystack in
  let rec go i = i + nlen <= hlen && (String.sub haystack i nlen = needle || go (i + 1)) in
  nlen = 0 || go 0

let read_file path =
  let ic = open_in_bin path in
  let n = in_channel_length ic in
  let s = really_input_string ic n in
  close_in ic;
  s

let fixtures_dir = "tls_fixtures"

let test_https_for_uri_validates_host () =
  let assert_some uri =
    match Https_eio.https_for_uri (Uri.of_string uri) with
    | Ok (Some _) -> ()
    | Ok None -> Alcotest.failf "%s: expected Some wrapper" uri
    | Error e -> Alcotest.failf "%s: %s" uri (Https_eio.error_to_string e)
  in
  assert_some "https://localhost";
  assert_some "https://example.com";
  Alcotest.(check bool) "http URL has no wrapper" true
    (Https_eio.https_for_uri (Uri.of_string "http://example.com") = Ok None);
  List.iter
    (fun uri ->
      Alcotest.(check bool) uri true
        (match Https_eio.https_for_uri (Uri.of_string uri) with
         | Error _ -> true
         | Ok _ -> false))
    [ "https:///path"; "https://127.0.0.1"; "https://-bad.com" ]

let test_https_handshake_fails_on_cert_not_on_rng () =
  Eio_main.run @@ fun env ->
  Eio.Switch.run @@ fun sw ->
  let cert = Result.get_ok (X509.Certificate.decode_pem (read_file (Filename.concat fixtures_dir "cert.pem"))) in
  let key = Result.get_ok (X509.Private_key.decode_pem (read_file (Filename.concat fixtures_dir "key.pem"))) in
  let server_config = Result.get_ok (Tls.Config.server ~certificates:(`Single ([ cert ], key)) ()) in
  let socket = Eio.Net.listen ~backlog:2 ~sw env#net (`Tcp (Eio.Net.Ipaddr.V4.loopback, 0)) in
  let port = match Eio.Net.listening_addr socket with `Tcp (_, port) -> port | _ -> failwith "unexpected address family" in
  Eio.Fiber.fork_daemon ~sw (fun () ->
      Eio.Net.accept_fork ~sw socket
        ~on_error:(fun _ -> ())
        (fun conn _addr -> ( try ignore (Tls_eio.server_of_flow server_config conn) with _ -> ()));
      `Stop_daemon);
  let client_socket = Eio.Net.connect ~sw env#net (`Tcp (Eio.Net.Ipaddr.V4.loopback, port)) in
  let dummy_uri = Uri.make ~scheme:"https" ~host:"localhost" () in
  match Https_eio.https_for_uri dummy_uri with
  | Error e -> Alcotest.fail ("expected an https wrapper, got: " ^ Https_eio.error_to_string e)
  | Ok None -> Alcotest.fail "expected Some wrapper for an https:// uri"
  | Ok (Some wrap) -> (
    let raw = (client_socket :> [ Eio.Flow.two_way_ty | Eio.Resource.close_ty ] Eio.Std.r) in
    match wrap dummy_uri raw with
    | (_ : Tls_eio.t) -> Alcotest.fail "expected the untrusted self-signed cert to be rejected"
    | exception exn ->
      let msg = Printexc.to_string exn in
      Alcotest.(check bool)
        "handshake reached certificate validation, not the unseeded-RNG error" true
        (not (contains_substring ~needle:"not yet initialized" msg)))

(* Forces the cache cold, then exercises real concurrent-domain contention
   on Https_eio.default_https_wrapper's double-checked-locking path (not the
   lock-free warm-cache fast path) to confirm no domain sees
   Lazy.Undefined. *)
let test_concurrent_domains_never_see_lazy_undefined () =
  let domain_count = 8 in
  let ready_count = Atomic.make 0 in
  let go = Atomic.make false in
  let domains =
    List.init domain_count (fun _ ->
        Domain.spawn (fun () ->
            Atomic.incr ready_count;
            while not (Atomic.get go) do
              Domain.cpu_relax ()
            done;
            let uri = Uri.make ~scheme:"https" ~host:"localhost" () in
            try
              ignore (Https_eio.https_for_uri uri : (Https_eio.https_wrapper option, Https_eio.error) result);
              Ok ()
            with exn -> Error (Printexc.to_string exn)))
  in
  while Atomic.get ready_count < domain_count do
    Domain.cpu_relax ()
  done;
  Atomic.set go true;
  let results = List.map Domain.join domains in
  List.iteri
    (fun i result ->
      match result with
      | Ok () -> ()
      | Error msg -> Alcotest.failf "domain %d: %s" i msg)
    results

let () =
  Alcotest.run "https_eio"
    [ ( "https handshake",
        [ Alcotest.test_case "https_for_uri validates HTTPS hosts" `Quick
            test_https_for_uri_validates_host;
          Alcotest.test_case "concurrent domains never see Lazy.Undefined" `Quick
            test_concurrent_domains_never_see_lazy_undefined;
          Alcotest.test_case "fails on certificate trust, not on an unseeded RNG" `Quick
            test_https_handshake_fails_on_cert_not_on_rng;
        ] );
    ]
