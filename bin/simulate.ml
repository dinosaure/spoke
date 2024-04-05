open Rresult
open Lwt.Infix

let ( >>? ) = Lwt_result.bind

let client ~ctx fd fd_length =
  let queue, _ = Ke.Rke.Weighted.create ~capacity:0x1000 Bigarray.char in
  let buf = Bytes.create 0x1000 in
  let close = ref false in
  let mutex = Lwt_mutex.create () in
  let condition = Lwt_condition.create () in

  let rec producer flow =
    Lwt_unix.read fd buf 0 (Bytes.length buf) >>= function
    | 0 ->
        ( Lwt_mutex.with_lock mutex @@ fun () ->
          close := true;
          Lwt_condition.broadcast condition `Closed;
          Lwt.return_unit )
        >>= fun () -> Lwt.return_ok ()
    | len ->
        let rec fill (buf, off, max) =
          ( Lwt_mutex.with_lock mutex @@ fun () ->
            let blit src src_off dst dst_off len =
              Bigstringaf.blit_from_bytes src ~src_off dst ~dst_off ~len
            in
            match min len (Ke.Rke.Weighted.available queue) with
            | 0 ->
                Lwt_condition.signal condition `Full;
                Lwt.return (`Redo (buf, off, max))
            | len ->
                let _ =
                  Ke.Rke.Weighted.N.push_exn queue ~blit ~length:Bytes.length
                    ~off ~len buf
                in
                Logs.debug (fun m -> m "Signal `Filled.");
                Lwt_condition.signal condition `Filled;
                if max - len = 0 then Lwt.return `Next
                else Lwt.return (`Redo (buf, off, max - len)) )
          >>= function
          | `Redo v -> Lwt.pause () >>= fun () -> fill v
          | `Next -> Lwt.return_unit
        in
        Mimic.write flow (Cstruct.of_string (Bytes.sub_string buf 0 len))
        >>? fun () ->
        fill (buf, 0, len) >>= fun () -> producer flow
  in

  let rec consumer flow checked =
    ( Lwt_mutex.with_lock mutex @@ fun () ->
      let rec wait res =
        if Ke.Rke.Weighted.is_empty queue && not !close then
          Lwt_condition.wait ~mutex condition >>= wait
        else Lwt.return res
      in
      Logs.debug (fun m -> m "Waiting for more data.");
      wait `Filled >>= function
      | (`Filled | `Full | `Closed) as state -> (
          Mimic.read flow >>? function
          | `Eof ->
              if state = `Closed && Ke.Rke.Weighted.is_empty queue then
                Lwt.return_ok `Closed
              else Lwt.return_error (R.msgf "Remaining untrusted contents!")
          | `Data cs ->
              let str0 = Cstruct.to_string cs in
              let blit src src_off dst dst_off len =
                Bigstringaf.blit_to_bytes src ~src_off dst ~dst_off ~len
              in
              let len = String.length str0 in
              let buf = Bytes.create len in
              Ke.Rke.Weighted.N.keep_exn queue ~blit ~length:Bytes.length buf
                ~len;
              Ke.Rke.Weighted.N.shift_exn queue len;
              if Eqaf.compare_be str0 (Bytes.unsafe_to_string buf) = 0 then (
                Logs.debug (fun m ->
                    m "Block received (%d byte(s)) is integre."
                      (Cstruct.length cs));
                if checked + len = fd_length then Lwt.return_ok `Closed
                else Lwt.return_ok (`Continue (checked + len)))
              else Lwt.return_error (R.msgf "Contents are corrupted!")) )
    >>? function
    | `Closed -> Lwt.return_ok ()
    | `Continue checked -> Lwt.pause () >>= fun () -> consumer flow checked
  in

  Mimic.resolve ctx >>? fun flow ->
  Lwt.both (producer flow) (consumer flow 0) >>= fun res ->
  Logs.debug (fun m -> m "Close the connection with the server.");
  Mimic.close flow >>= fun () ->
  match res with
  | Ok (), Ok () -> Lwt.return_ok ()
  | Error err, _ -> Lwt.return_error (R.msgf "%a" Mimic.pp_write_error err)
  | _, Error err -> Lwt.return_error (R.msgf "%a" Mimic.pp_error err)

let handler flow =
  let queue, _ = Ke.Rke.Weighted.create ~capacity:0x1000 Bigarray.char in
  let block = Cstruct.create 0x1000 in
  let close = ref false in
  let mutex = Lwt_mutex.create () in
  let condition = Lwt_condition.create () in

  let rec producer flow =
    Mimic.read flow >>? function
    | `Eof ->
        ( Lwt_mutex.with_lock mutex @@ fun () ->
          close := true;
          Lwt_condition.broadcast condition `Closed;
          Lwt.return_unit )
        >>= fun () -> Lwt.return_ok ()
    | `Data cs ->
        Logs.debug (fun m ->
            m "Recv @[<hov>%a@]"
              (Hxd_string.pp Hxd.default)
              (Cstruct.to_string cs));
        let rec fill cs =
          ( Lwt_mutex.with_lock mutex @@ fun () ->
            let blit src src_off dst dst_off len =
              let dst = Cstruct.of_bigarray dst ~off:dst_off ~len in
              Cstruct.blit src src_off dst 0 len
            in
            match min (Cstruct.length cs) (Ke.Rke.Weighted.available queue) with
            | 0 ->
                Lwt_condition.signal condition `Full;
                Lwt.return (`Redo cs)
            | len ->
                let _ =
                  Ke.Rke.Weighted.N.push_exn queue ~blit ~length:Cstruct.length
                    ~len cs
                in
                Lwt_condition.signal condition `Filled;
                if Cstruct.length cs - len = 0 then Lwt.return `Next
                else Lwt.return (`Redo (Cstruct.shift cs len)) )
          >>= function
          | `Redo cs -> Lwt.pause () >>= fun () -> fill cs
          | `Next -> Lwt.return_unit
        in
        fill cs >>= fun () -> producer flow
  in

  let rec consumer flow =
    ( Lwt_mutex.with_lock mutex @@ fun () ->
      let rec wait res =
        if Ke.Rke.Weighted.is_empty queue && not !close then
          Lwt_condition.wait ~mutex condition >>= wait
        else Lwt.return res
      in
      wait `Filled >>= function
      | (`Full | `Filled | `Closed) as state -> (
          let blit src src_off dst dst_off len =
            let src = Cstruct.of_bigarray src ~off:src_off ~len in
            Cstruct.blit src 0 dst dst_off len
          in
          let len = min (Ke.Rke.Weighted.length queue) (Cstruct.length block) in
          Ke.Rke.Weighted.N.keep_exn queue ~blit ~length:Cstruct.length block
            ~len;
          Ke.Rke.Weighted.N.shift_exn queue len;
          let block = Cstruct.sub block 0 len in
          Logs.debug (fun m ->
              m "Send @[<hov>%a@]"
                (Hxd_string.pp Hxd.default)
                (Cstruct.to_string block));
          (if Cstruct.length block > 0 then Mimic.write flow block
           else Lwt.return_ok ())
          >>? fun () ->
          match state with
          | `Closed ->
              Logs.debug (fun m -> m "The connection was closed by the client.");
              Lwt.return_ok `Closed
          | `Full | `Filled -> Lwt.return_ok `Continue) )
    >>? function
    | `Closed -> Lwt.return_ok ()
    | `Continue -> Lwt.pause () >>= fun () -> consumer flow
  in

  Lwt.both (producer flow) (consumer flow) >>= fun (p, c) ->
  Mimic.close flow >>= fun () ->
  match (p, c) with
  | Ok (), Ok () -> Lwt.return_ok ()
  | Error err, _ -> Lwt.return_error (R.msgf "%a" Mimic.pp_error err)
  | _, Error err -> Lwt.return_error (R.msgf "%a" Mimic.pp_write_error err)

let handler stop flow =
  handler flow >>= fun res ->
  Lwt_switch.turn_off stop >>= fun () ->
  match res with
  | Ok () -> Lwt.return_unit
  | Error err ->
      Fmt.epr "Got an error: %a.\n%!" Mimic.pp_error err;
      Lwt.return_unit

module SPOKE = struct
  include Flow.Make (Tcpip_stack_socket.V4V6.TCP)

  type endpoint = {
    g : Random.State.t option;
    identity : string * string;
    password : string;
    tcp : Tcpip_stack_socket.V4V6.TCP.t;
    ipaddr : Ipaddr.t;
    port : int;
  }

  let connect { g; identity; password; tcp = stack; ipaddr; port } =
    let open Tcpip_stack_socket.V4V6 in
    TCP.create_connection stack (ipaddr, port)
    >|= R.reword_error (fun err -> `Flow err)
    >>? fun flow -> client_of_flow ?g ~identity ~password flow
end

type ('v, 'flow, 'err) service = {
  accept : 'v -> ('flow, 'err) result Lwt.t;
  close : 'v -> unit Lwt.t;
}
  constraint 'err = [> `Closed ]

let serve_when_ready ?stop ~handler { accept; close } service =
  `Initialized
    (let switched_off =
       let t, u = Lwt.wait () in
       Lwt_switch.add_hook stop (fun () ->
           Lwt.wakeup_later u (Ok `Stopped);
           Lwt.return_unit);
       t
     in
     let rec loop () =
       let accept = accept service >>? fun flow -> Lwt.return_ok (`Flow flow) in
       accept >>? function
       | `Flow flow ->
           Lwt.async (fun () -> handler flow);
           Lwt.pause () >>= loop
     in
     let stop_result =
       Lwt.pick [ switched_off; loop () ] >>= function
       | Ok `Stopped -> close service >>= fun () -> Lwt.return_ok ()
       | Error _ as err -> close service >>= fun () -> Lwt.return err
     in
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
      | len -> Lwt.return_ok (`Data (Cstruct.of_bytes ~off:0 ~len tmp))
    in
    Lwt.catch process @@ function
    | Unix.Unix_error (e, f, v) -> Lwt.return_error (`Error (e, f, v))
    | exn -> Lwt.fail exn

  let write fd ({ Cstruct.len; _ } as cs) =
    let rec process buf off max =
      Lwt_unix.write fd buf off max >>= fun len ->
      if max - len = 0 then Lwt.return_ok ()
      else process buf (off + len) (max - len)
    in
    let buf = Cstruct.to_bytes cs in
    Lwt.catch (fun () -> process buf 0 len) @@ function
    | Unix.Unix_error (e, f, v) -> Lwt.return_error (`Error (e, f, v))
    | exn -> Lwt.fail exn

  let rec writev fd = function
    | [] -> Lwt.return_ok ()
    | x :: r -> write fd x >>? fun () -> writev fd r

  let close = Lwt_unix.close

  let shutdown fd = function
    | `read ->
        Lwt_unix.shutdown fd Unix.SHUTDOWN_RECEIVE;
        Lwt.return_unit
    | `write ->
        Lwt_unix.shutdown fd Unix.SHUTDOWN_SEND;
        Lwt.return_unit
    | `read_write ->
        Lwt_unix.shutdown fd Unix.SHUTDOWN_ALL;
        Lwt.return_unit
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
    Logs.debug (fun m -> m "Incoming connection from: %a." pp_sockaddr sockaddr);
    SPOKEServer.server_of_flow ?g
      ~cfg:Spoke.(Cfg (Pbkdf2, 16))
      ~identity:(identity, identity) ~password fd
    >>? fun fd ->
    Logs.debug (fun m -> m "Handshake done!");
    Lwt.return_ok (REPR.T fd)
  in
  let close t = Lwt_unix.close t in
  { accept; close }

let spoke_edn, _ = Mimic.register ~name:"spoke" (module SPOKE)
let m_g = Mimic.make ~name:"g"
let m_server_identity = Mimic.make ~name:"server-identity"
let m_password = Mimic.make ~name:"password"
let m_tcp = Mimic.make ~name:"tcp"
let m_ipaddr = Mimic.make ~name:"ipaddr"
let m_port = Mimic.make ~name:"port"

let m_domain_name : [ `host ] Domain_name.t Mimic.value =
  Mimic.make ~name:"domain-name"

let ctx ~port =
  let k0 domain_name =
    match Unix.gethostbyname (Domain_name.to_string domain_name) with
    | { Unix.h_addr_list; _ } when Array.length h_addr_list > 0 ->
        Lwt.return_some (Ipaddr_unix.of_inet_addr h_addr_list.(0))
    | _ -> Lwt.return_none
    | exception _ -> Lwt.return_none
  in
  let k1 g server_identity password tcp ipaddr port =
    let client_identity = Unix.gethostname () in
    Lwt.return_some
      {
        SPOKE.g;
        identity = (client_identity, server_identity);
        password;
        tcp;
        ipaddr;
        port;
      }
  in
  let open Tcpip_stack_socket.V4V6 in
  TCP.connect ~ipv4_only:false ~ipv6_only:false Ipaddr.V4.Prefix.global None
  >>= fun tcp ->
  let ctx = Mimic.empty in
  let ctx = Mimic.add m_tcp tcp ctx in
  let ctx = Mimic.fold m_ipaddr Mimic.Fun.[ req m_domain_name ] ~k:k0 ctx in
  let ctx =
    Mimic.fold spoke_edn
      Mimic.Fun.
        [
          opt m_g;
          req m_server_identity;
          req m_password;
          req m_tcp;
          req m_ipaddr;
          dft m_port port;
        ]
      ~k:k1 ctx
  in
  Lwt.return ctx

let run filename (ipaddr, port) password =
  let client () =
    let g = Random.State.make_self_init () in
    ctx ~port >>= fun ctx ->
    let ctx = Mimic.add m_ipaddr ipaddr ctx in
    let ctx = Mimic.add m_g g ctx in
    let identity = Unix.gethostname () in
    let ctx = Mimic.add m_server_identity identity ctx in
    let ctx = Mimic.add m_password password ctx in
    Lwt_unix.openfile filename Unix.[ O_RDONLY ] 0o644 >>= fun fd ->
    Lwt_unix.stat filename >>= fun stat ->
    client ~ctx fd stat.Unix.st_size >>= function
    | Ok () -> Lwt.return_unit
    | Error err ->
        Fmt.epr "%a.\n%!" Mimic.pp_error err;
        Lwt.return_unit
  in
  let server () =
    let stop = Lwt_switch.create () in
    let g = Random.State.make_self_init () in
    let sockaddr = Unix.ADDR_INET (Ipaddr_unix.to_inet_addr ipaddr, port) in
    let domain = Unix.domain_of_sockaddr sockaddr in
    let socket = Lwt_unix.socket domain Unix.SOCK_STREAM 0 in
    Lwt_unix.bind socket sockaddr >>= fun () ->
    Lwt_unix.listen socket 40;
    let (`Initialized th) =
      serve_when_ready ~stop ~handler:(handler stop) (service ~g password)
        socket
    in
    th
  in
  Lwt.both (client ()) (server ()) >>= fun ((), ()) -> Lwt.return_unit

let () =
  match Sys.argv with
  | [| _; filename; ipaddr; password |] when Sys.file_exists filename -> (
      match Ipaddr.with_port_of_string ~default:9000 ipaddr with
      | Ok addr -> Lwt_main.run (run filename addr password)
      | Error _ ->
          Fmt.epr "%s <filename> <addr>[:<port>] <password>\n%!" Sys.argv.(0))
  | _ -> Fmt.epr "%s <filename> <addr>[:<port>] <password>\n%!" Sys.argv.(0)
