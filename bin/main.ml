let reporter ppf =
  let report src level ~over k msgf =
    let k _ =
      over () ;
      k () in
    let with_metadata header _tags k ppf fmt =
      Format.kfprintf k ppf
        ("[%a]%a[%a]: " ^^ fmt ^^ "\n%!")
        Fmt.(styled `Blue int)
        (Unix.getpid ()) Logs_fmt.pp_header (level, header)
        Fmt.(styled `Magenta string)
        (Logs.Src.name src) in
    msgf @@ fun ?header ?tags fmt -> with_metadata header tags k ppf fmt in
  { Logs.report }

let () = Fmt_tty.setup_std_outputs ~style_renderer:`Ansi_tty ~utf_8:true ()
let () = Logs.set_reporter (reporter Fmt.stderr)
let () = Logs.set_level ~all:true (Some Logs.Debug)

let run socket flow =
  let rec go = function
    | Flow.Done v -> Ok v
    | Flow.Fail err -> Error err
    | Flow.Rd { buf; off; len; k; } ->
      Logs.debug (fun m -> m "<~ Waiting for read.") ;
      ( match Unix.read socket buf off len with
      | 0 -> go (k `End)
      | len -> go (k (`Len len)) )
    | Flow.Wr { str; off; len; k; } ->
      let len = Unix.write_substring socket str off len in
      Logs.debug (fun m -> m "[o] ~> @[<hov>%a@]"
        (Hxd_string.pp Hxd.default) (String.sub str off len)) ;
      go (k len) in
  go flow

let connect_client sockaddr =
  let domain = Unix.domain_of_sockaddr sockaddr in
  let socket = Unix.socket domain Unix.SOCK_STREAM 0 in
  Unix.connect socket sockaddr ;
  socket

let connect_server sockaddr =
  let domain = Unix.domain_of_sockaddr sockaddr in
  let socket = Unix.socket domain Unix.SOCK_STREAM 0 in
  Unix.bind socket sockaddr ;
  Unix.listen socket 40 ;
  ( match sockaddr with
  | Unix.ADDR_UNIX path -> Stdlib.at_exit (fun () -> try Unix.unlink path with _ -> ())
  | _ -> () ) ;
  socket

let simulate sockaddr ~password ~identity cfg =
  let client () =
    let g = Random.State.make_self_init () in
    let ctx = Flow.ctx () in
    let flow = Flow.handshake0 ctx ~g ~identity password in
    let socket = connect_client sockaddr in
    let res = run socket flow in
    Unix.close socket ; res in
  let server main () =
    let g = Random.State.make_self_init () in
    let ctx = Flow.ctx () in
    let flow = Flow.handshake1 ctx ~g ~password ~identity cfg in
    let socket, _sockaddr = Unix.accept main in
    let res = run socket flow in
    Unix.close socket ; Unix.close main ; res in
  let open Fiber in
  let main = connect_server sockaddr in
  Fiber.fork_and_join
    (fun () -> run_process client)
    (fun () -> run_process (server main))
  >>= function
  | Ok res0, Ok res1 -> Fiber.return (res0, res1)
  | Error _, _ | _, Error _ ->
    Fmt.failwith "Error to parallelize processes."

let client_identity = "Bob"
let server_identity = "Alice"
let identities = client_identity, server_identity
let cfg = Flow.Cfg (Spoke.Pbkdf2, 16)

let run_with_fifo fifo ~password =
  let fiber = simulate fifo 
    ~password ~identity:identities cfg in
  match Fiber.run fiber with
  | Ok (k0, k1), Ok (k0', k1') ->
    if Eqaf.compare_be k0 k0' = 0 && Eqaf.compare_be k1 k1' = 0
    then ( Fmt.pr "K0: %s\n%!" (Base64.encode_exn k0)
         ; Fmt.pr "K1: %s\n%!" (Base64.encode_exn k1) )
    else Fmt.epr "No agreement!\n%!"
  | Error err, s ->
    Fmt.epr "%s[client]: %a (server: %s)\n%!"
      Sys.argv.(0) Flow.pp_error err
      (if Result.is_ok s then "ok" else "errored")
  | c, Error err ->
    Fmt.epr "%s[server]: %a (client: %s)\n%!"
      Sys.argv.(0) Flow.pp_error err
      (if Result.is_ok c then "ok" else "errored")

let run ~password =
  let ( let+ ) = Result.bind in

  let g = Random.State.make_self_init () in
  let Cfg (algorithm, arguments) = cfg in
  let secret, public = Spoke.generate ~g ~password
    ~algorithm arguments in
  let client, packet = Spoke.hello ~g ~public password in
  Fmt.pr "[o] C ~> S @[<hov>%a@]\n%!" (Hxd_string.pp Hxd.default) packet ;
  let+ server, packet = Spoke.server_compute ~secret ~identity:identities
    packet in
  Fmt.pr "[o] S ~> C @[<hov>%a@]\n%!" (Hxd_string.pp Hxd.default) packet ;
  let+ shared_keys0, packet = Spoke.client_compute
    ~client ~identity:identities packet in
  Fmt.pr "[o] C ~> S @[<hov>%a@]\n%!" (Hxd_string.pp Hxd.default) packet ;
  let+ shared_keys1 = Spoke.server_finalize ~server packet in
  if Eqaf.compare_be (fst shared_keys0) (fst shared_keys1) = 0
  && Eqaf.compare_be (snd shared_keys0) (snd shared_keys1) = 0
  then Ok () else Error (`Msg "Keys are not shared")

let run ~password = match run ~password with
  | Ok () -> ()
  | Error (#Spoke.error as err) -> Fmt.epr "%s: %a\n%!" Sys.argv.(0) Spoke.pp_error err
  | Error (`Msg err) -> Fmt.epr "%s: %s." Sys.argv.(0) err

let () = match Sys.argv with
  | [| _; password |] -> run ~password
  | [| _; unix_domain; password |] ->
    run_with_fifo (Unix.ADDR_UNIX unix_domain) ~password
  | _ ->
    Fmt.epr "%s <unix-socket> password\n%!" Sys.argv.(0)
