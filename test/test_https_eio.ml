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

(* Exercises real concurrent-domain contention on the TLS config cache's cold
   path to confirm no domain sees Lazy.Undefined. *)
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

(* ------------------------------------------------------------------ *)
(* request                                                             *)
(* ------------------------------------------------------------------ *)

let with_mock_server env ~status_code f =
  Eio.Switch.run @@ fun sw ->
  let last_method = ref "" in
  let last_body = ref "" in
  let stop, stop_r = Eio.Promise.create () in
  let callback _conn req body =
    last_method := Http.Method.to_string (Http.Request.meth req);
    last_body := Eio.Buf_read.(of_flow body ~max_size:(64 * 1024) |> take_all);
    Cohttp_eio.Server.respond ~status:(Http.Status.of_int status_code)
      ~body:(Cohttp_eio.Body.of_string "pong") ()
  in
  let server = Cohttp_eio.Server.make ~callback () in
  let addr = `Tcp (Eio.Net.Ipaddr.V4.loopback, 0) in
  let socket = Eio.Net.listen ~backlog:1 ~sw env#net addr in
  let port =
    match Eio.Net.listening_addr socket with
    | `Tcp (_, p) -> p
    | _ -> failwith "unexpected address family"
  in
  Eio.Fiber.fork_daemon ~sw (fun () ->
    Cohttp_eio.Server.run ~stop ~on_error:(fun _ -> ()) socket server;
    `Stop_daemon);
  let result = f ~port ~last_method ~last_body in
  Eio.Promise.resolve stop_r ();
  result

let test_request_get () =
  Eio_main.run @@ fun env ->
  with_mock_server env ~status_code:200 (fun ~port ~last_method ~last_body:_ ->
    let url = Printf.sprintf "http://127.0.0.1:%d/ping" port in
    match Https_eio.request ~net:env#net ~clock:env#clock ~meth:`GET ~url () with
    | Ok (200, "pong") -> Alcotest.(check string) "method" "GET" !last_method
    | Ok (status, body) -> Alcotest.failf "unexpected response: %d %S" status body
    | Error e -> Alcotest.fail (Https_eio.request_error_to_string e))

let test_request_post_sends_body () =
  Eio_main.run @@ fun env ->
  with_mock_server env ~status_code:200 (fun ~port ~last_method ~last_body ->
    let url = Printf.sprintf "http://127.0.0.1:%d/push" port in
    match Https_eio.request ~net:env#net ~clock:env#clock ~meth:`POST ~url ~body:"hello" () with
    | Ok (200, _) ->
      Alcotest.(check string) "method" "POST" !last_method;
      Alcotest.(check string) "body received" "hello" !last_body
    | Ok (status, body) -> Alcotest.failf "unexpected response: %d %S" status body
    | Error e -> Alcotest.fail (Https_eio.request_error_to_string e))

let test_request_does_not_classify_status () =
  Eio_main.run @@ fun env ->
  with_mock_server env ~status_code:500 (fun ~port ~last_method:_ ~last_body:_ ->
    let url = Printf.sprintf "http://127.0.0.1:%d/boom" port in
    match Https_eio.request ~net:env#net ~clock:env#clock ~meth:`GET ~url () with
    | Ok (500, "pong") -> ()
    | Ok (status, body) -> Alcotest.failf "unexpected response: %d %S" status body
    | Error e -> Alcotest.failf "expected Ok (500, _), got Error: %s" (Https_eio.request_error_to_string e))

let test_request_rejects_invalid_url () =
  Eio_main.run @@ fun env ->
  match Https_eio.request ~net:env#net ~clock:env#clock ~meth:`GET ~url:"ftp://example.com" () with
  | Ok _ -> Alcotest.fail "expected Invalid_config for a non-http(s) URL"
  | Error (Https_eio.Invalid_config _) -> ()
  | Error e -> Alcotest.failf "expected Invalid_config, got: %s" (Https_eio.request_error_to_string e)

let test_request_rejects_invalid_timeout () =
  Eio_main.run @@ fun env ->
  match Https_eio.request ~net:env#net ~clock:env#clock ~timeout:0. ~meth:`GET ~url:"http://example.com" () with
  | Ok _ -> Alcotest.fail "expected Invalid_config for a non-positive timeout"
  | Error (Https_eio.Invalid_config _) -> ()
  | Error e -> Alcotest.failf "expected Invalid_config, got: %s" (Https_eio.request_error_to_string e)

let test_request_reports_response_too_large () =
  Eio_main.run @@ fun env ->
  with_mock_server env ~status_code:200 (fun ~port ~last_method:_ ~last_body:_ ->
    let url = Printf.sprintf "http://127.0.0.1:%d/big" port in
    (* The mock server's body ("pong", 4 bytes) exceeds this 1-byte cap. *)
    match Https_eio.request ~net:env#net ~clock:env#clock ~meth:`GET ~url ~max_response_bytes:1 () with
    | Ok (status, body) -> Alcotest.failf "expected Response_too_large, got: %d %S" status body
    | Error (Https_eio.Response_too_large 1) -> ()
    | Error e -> Alcotest.failf "expected Response_too_large 1, got: %s" (Https_eio.request_error_to_string e))

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
      ( "request",
        [ Alcotest.test_case "GET returns status and body" `Quick test_request_get;
          Alcotest.test_case "POST sends the body" `Quick test_request_post_sends_body;
          Alcotest.test_case "does not classify non-2xx status" `Quick
            test_request_does_not_classify_status;
          Alcotest.test_case "rejects a non-http(s) URL" `Quick test_request_rejects_invalid_url;
          Alcotest.test_case "rejects a non-positive timeout" `Quick
            test_request_rejects_invalid_timeout;
          Alcotest.test_case "reports Response_too_large distinctly" `Quick
            test_request_reports_response_too_large;
        ] );
    ]
