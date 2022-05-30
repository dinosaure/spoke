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

open Rresult
open Lwt.Infix

let ( >>? ) = Lwt_result.bind

let line_of_queue queue =
  let blit src src_off dst dst_off len =
    Bigstringaf.blit_to_bytes src ~src_off dst ~dst_off ~len in
  let exists ~p queue =
    let pos = ref 0 and res = ref (-1) in
    Ke.Rke.iter (fun chr -> if p chr && !res = -1 then res := !pos
                          ; incr pos) queue ;
    if !res = -1 then None else Some !res in
  match exists ~p:((=) '\n') queue with
  | None -> None
  | Some 0 -> Ke.Rke.N.shift_exn queue 1 ; Some ""
  | Some pos ->
    let tmp = Bytes.create pos in
    Ke.Rke.N.keep_exn queue ~blit ~length:Bytes.length ~off:0 ~len:pos tmp ;
    Ke.Rke.N.shift_exn queue (pos + 1) ;
    match Bytes.get tmp (pos - 1) with
    | '\r' -> Some (Bytes.sub_string tmp 0 (pos - 1))
    | _ -> Some (Bytes.unsafe_to_string tmp)

let rec getline flow queue =
  let blit src src_off dst dst_off len =
    let src = Cstruct.to_bigarray src in
    Bigstringaf.blit src ~src_off dst ~dst_off ~len in
  match line_of_queue queue with
  | Some line -> Lwt.return_ok (`Line line)
  | None ->
    Mimic.read flow >>= function
    | Ok `Eof -> Lwt.return_ok `Close
    | Ok (`Data v) ->
      Ke.Rke.N.push queue ~blit ~length:Cstruct.length ~off:0 v ;
      getline flow queue
    | Error err -> Lwt.return_error (R.msgf "%a" Mimic.pp_error err)

let sendline flow fmt =
  let send str = Mimic.write flow (Cstruct.of_string str) >>= function
    | Ok _ as v -> Lwt.return v
    | Error err -> Lwt.return_error (R.msgf "%a" Mimic.pp_write_error err) in
  Fmt.kstr send (fmt ^^ "\r\n")

let client ~ctx ic =
  let rec go flow queue = match input_line ic with
    | line ->
      if ic != stdin then Fmt.pr "> %s\n%!" line ;
      sendline flow "%s" line >>? fun () ->
      ( getline flow queue >>? function
      | `Close -> Lwt.return_ok ()
      | `Line v ->
        Fmt.pr "<~ %s\n%!" v ;
        if ic == stdin then Fmt.pr "> %!" ;
        go flow queue )
    | exception End_of_file -> Lwt.return_ok () in
  Mimic.resolve ctx >>? fun flow ->
  let queue = Ke.Rke.create ~capacity:0x1000 Bigarray.char in
  if ic == stdin then Fmt.pr "> %!" ;
  go flow queue >>= fun res ->
  Mimic.close flow >>= fun () -> Lwt.return res

let handler flow =
  let queue = Ke.Rke.create ~capacity:0x1000 Bigarray.char in
  let rec go flow queue =
    getline flow queue >>? function
    | `Close -> Lwt.return_ok ()
    | (`Line "ping") ->
      sendline flow "pong" >>? fun () -> go flow queue
    | (`Line "pong") ->
      sendline flow "ping" >>? fun () -> go flow queue
    | (`Line line) ->
      sendline flow "%s" line >>? fun () -> go flow queue in
  Logs.debug (fun m -> m "Start to handle our client.") ;
  go flow queue >>= fun res ->
  Mimic.close flow >>= fun () -> Lwt.return res

let handler flow = handler flow >>= function
  | Ok () -> Lwt.return_unit
  | Error err ->
    Fmt.epr "Got an error: %a.\n%!" Mimic.pp_error err ;
    Lwt.return_unit

module SPOKE = struct
  include Flow.Make (Tcpip_stack_socket.V4V6.TCP)

  type endpoint =
    { g : Random.State.t option
    ; identity : string * string
    ; password : string
    ; tcp : Tcpip_stack_socket.V4V6.TCP.t
    ; ipaddr : Ipaddr.t
    ; port : int }

  let connect { g; identity; password; tcp= stack; ipaddr; port; } =
    let open Tcpip_stack_socket.V4V6 in
    TCP.create_connection stack (ipaddr, port)
    >|= R.reword_error (fun err -> `Flow err)
    >>? fun flow -> client_of_flow ?g ~identity ~password flow
end

type ('v, 'flow, 'err) service =
  { accept : 'v -> ('flow, 'err) result Lwt.t
  ; close : 'v -> unit Lwt.t }
  constraint 'err = [> `Closed ]

let serve_when_ready ?stop ~handler { accept; close; } service =
  `Initialized
    (let switched_off =
       let t, u = Lwt.wait () in
       Lwt_switch.add_hook stop (fun () ->
           Lwt.wakeup_later u (Ok `Stopped) ;
           Lwt.return_unit) ;
       t in
     let rec loop () =
       let accept =
         accept service >>? fun flow -> Lwt.return_ok (`Flow flow) in
       accept >>? function
       | `Flow flow ->
         Lwt.async (fun () -> handler flow) ;
         Lwt.pause () >>= loop in
     let stop_result =
       Lwt.pick [ switched_off; loop () ] >>= function
       | Ok `Stopped -> close service >>= fun () -> Lwt.return_ok ()
       | Error _ as err -> close service >>= fun () -> Lwt.return err in
     stop_result >>= function Ok () | Error _ -> Lwt.return_unit)

module TCP = struct
  type flow = Lwt_unix.file_descr

  type error = [ `Error of Unix.error * string * string ]
  type write_error = [ `Closed | `Error of Unix.error * string * string ]

  let pp_error ppf = function
    | `Error (err, f, v) ->
      Fmt.pf ppf "%s(%s) : %s" f v (Unix.error_message err)

  let pp_write_error ppf = function
    | #error as err -> pp_error ppf err
    | `Closed -> Fmt.pf ppf "Connection closed by peer"

  let read fd =
    let tmp = Bytes.create 0x1000 in
    let process () =
      Lwt_unix.read fd tmp 0 (Bytes.length tmp) >>= function
      | 0 -> Lwt.return_ok `Eof
      | len -> Lwt.return_ok (`Data (Cstruct.of_bytes ~off:0 ~len tmp)) in
    Lwt.catch process @@ function
    | Unix.Unix_error (e, f, v) -> Lwt.return_error (`Error (e, f, v))
    | exn -> Lwt.fail exn

  let write fd ({ Cstruct.len; _ } as cs) =
    let rec process buf off max =
      Lwt_unix.write fd buf off max >>= fun len ->
      if max - len = 0 then Lwt.return_ok ()
      else process buf (off + len) (max - len) in
    let buf = Cstruct.to_bytes cs in
    Lwt.catch (fun () -> process buf 0 len) @@ function
    | Unix.Unix_error (e, f, v) -> Lwt.return_error (`Error (e, f, v))
    | exn -> Lwt.fail exn

  let rec writev fd = function
    | [] -> Lwt.return_ok ()
    | x :: r -> write fd x >>? fun () -> writev fd r

  let close = Lwt_unix.close
end

module SPOKEServer = struct 
  include Flow.Make (TCP)

  type endpoint = |
  let connect : endpoint -> (flow, write_error) result Lwt.t = function _ -> .
end

let _, spoke_protocol = Mimic.register ~name:"spoke" (module SPOKEServer)

let pp_sockaddr ppf = function
  | Unix.ADDR_UNIX unix_domain -> Fmt.string ppf unix_domain
  | Unix.ADDR_INET (inet_addr, port) ->
    let inet_addr = Unix.string_of_inet_addr inet_addr in
    Fmt.pf ppf "%s:%d" inet_addr port

let service ?g password =
  let module REPR = (val Mimic.repr spoke_protocol) in
  let identity = Unix.gethostname () in
  let accept t =
    Lwt_unix.accept t >>= fun (fd, sockaddr) ->
    Logs.debug (fun m -> m "Incoming connection from: %a."
      pp_sockaddr sockaddr) ;
    SPOKEServer.server_of_flow ?g
      ~cfg:Spoke.(Cfg (Pbkdf2, 16))
      ~identity:(identity, identity)
      ~password fd >>? fun fd ->
    Logs.debug (fun m -> m "Handshake done!") ;
    Lwt.return_ok (REPR.T fd) in
  let close t = Lwt_unix.close t in
  { accept; close; }

let spoke_edn, _ = Mimic.register ~name:"spoke" (module SPOKE)
let m_g = Mimic.make ~name:"g"
let m_server_identity = Mimic.make ~name:"server-identity"
let m_password = Mimic.make ~name:"password"
let m_tcp = Mimic.make ~name:"tcp"
let m_ipaddr = Mimic.make ~name:"ipaddr"
let m_port = Mimic.make ~name:"port"
let m_domain_name = Mimic.make ~name:"domain-name"

let ctx () =
  let k0 domain_name =
    match Unix.gethostbyname (Domain_name.to_string domain_name) with
    | { Unix.h_addr_list; _ } when Array.length h_addr_list > 0 ->
      Lwt.return_some (Ipaddr_unix.of_inet_addr h_addr_list.(0))
    | _ -> Lwt.return_none
    | exception _ -> Lwt.return_none in
  let k1 g server_identity password tcp ipaddr port =
    let client_identity = Unix.gethostname () in
    Lwt.return_some { SPOKE.g
                    ; identity= (client_identity, server_identity)
                    ; password
                    ; tcp
                    ; ipaddr
                    ; port } in
  let open Tcpip_stack_socket.V4V6 in
  TCP.connect ~ipv4_only:false ~ipv6_only:false
    Ipaddr.V4.Prefix.global None >>= fun tcp ->
  let ctx = Mimic.empty in
  let ctx = Mimic.add m_tcp tcp ctx in
  let ctx = Mimic.fold m_ipaddr
    Mimic.Fun.[ req m_domain_name ] ~k:k0 ctx in
  let ctx = Mimic.fold spoke_edn
    Mimic.Fun.[ opt m_g; req m_server_identity; req m_password; req m_tcp;
                req m_ipaddr; dft m_port 9009 ] ~k:k1 ctx in
  Lwt.return ctx

let run ipaddr password =
  let client () =
    let g = Random.State.make_self_init () in
    ctx () >>= fun ctx ->
    let ctx = Mimic.add m_ipaddr ipaddr ctx in
    let ctx = Mimic.add m_g g ctx in
    let identity = Unix.gethostname () in
    let ctx = Mimic.add m_server_identity identity ctx in
    let ctx = Mimic.add m_password password ctx in
    client ~ctx stdin >>= function
    | Ok () -> Lwt.return_unit
    | Error err ->
      Fmt.epr "%a.\n%!" Mimic.pp_error err ;
      Lwt.return_unit in
  let server () =
    let g = Random.State.make_self_init () in
    let sockaddr = Unix.ADDR_INET (Ipaddr_unix.to_inet_addr ipaddr, 9009) in
    let domain = Unix.domain_of_sockaddr sockaddr in
    let socket = Lwt_unix.socket domain Unix.SOCK_STREAM 0 in
    Lwt_unix.bind socket sockaddr >>= fun () ->
    Lwt_unix.listen socket 40 ;
    let `Initialized th = serve_when_ready ~handler
      (service ~g password) socket in
    th in
  Lwt.both (client ()) (server ()) >>= fun ((), ()) ->
  Lwt.return_unit

let () = match Sys.argv with
  | [| _; ipaddr; password; |] ->
    ( match Ipaddr.of_string ipaddr with
    | Ok ipaddr -> Lwt_main.run (run ipaddr password)
    | Error _ -> Fmt.epr "%s <ipaddr> <password>\n%!" Sys.argv.(0) )
  | _ -> Fmt.epr "%s <ipaddr> <password>\n%!" Sys.argv.(0)
