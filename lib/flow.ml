type ctx =
  { a_buffer : bytes
  ; mutable a_pos : int
  ; mutable a_max : int
  ; b_buffer : bytes
  ; mutable b_pos : int }

let ctx () =
  { a_buffer= Bytes.create 128
  ; a_pos= 0
  ; a_max= 0
  ; b_buffer= Bytes.create 128
  ; b_pos= 0 }

type error =
  [ `Not_enough_space
  | `End_of_input
  | `Spoke of Spoke.error ]

let pp_error ppf = function
  | `Not_enough_space -> Fmt.pf ppf "Not enough space"
  | `End_of_input -> Fmt.pf ppf "End of input"
  | `Spoke err -> Spoke.pp_error ppf err

type 'a t =
  | Rd of { buf : bytes; off : int; len : int; k : 'a krd }
  | Wr of { str : string; off : int; len : int; k : 'a kwr }
  | Done of 'a
  | Fail of error
and 'a krd = [ `End | `Len of int ] -> 'a t
and 'a kwr = int -> 'a t

exception Leave of error

let leave_with _ctx error =
  raise (Leave error)

let safe k ctx =
  try k ctx
  with Leave err -> Fail err

let always x = fun _ -> x

module Send = struct
  let flush k0 ctx =
    if ctx.b_pos > 0
    then
      let rec k1 n =
        if n < ctx.b_pos
        then Wr { str= Bytes.unsafe_to_string ctx.b_buffer
                ; off= n
                ; len= ctx.b_pos - n
                ; k= (fun m -> k1 (n + m)) }
        else ( ctx.b_pos <- 0
             ; k0 ctx ) in
      k1 0
    else k0 ctx

  let write str ctx =
    let max = Bytes.length ctx.b_buffer in
    let go j l ctx =
      let rem = max - ctx.b_pos in
      let len = if l > rem then rem else l in
      Bytes.blit_string str j ctx.b_buffer ctx.b_pos len ;
      ctx.b_pos <- ctx.b_pos + len ;
      if len < l
      then leave_with ctx `Not_enough_space in
    go 0 (String.length str) ctx

  let send ctx str =
    safe begin fun ctx ->
    write str ctx ;
    flush (always (Done ())) ctx end ctx
end

module Recv = struct
  let prompt ~required k ctx =
    if ctx.a_pos > 0
    then
      ( let rest = ctx.a_max - ctx.a_pos in
        Bytes.blit ctx.a_buffer ctx.a_pos ctx.a_buffer 0 rest ;
        ctx.a_max <- rest ;
        ctx.a_pos <- 0 ) ;
    let rec go off =
      if off = Bytes.length ctx.a_buffer
      then Fail `Not_enough_space
      else if off - ctx.a_pos < required
      then let k = function
             | `Len len -> go (off + len)
             | `End -> Fail `End_of_input in
           Rd { buf= ctx.a_buffer
              ; off= off
              ; len= Bytes.length ctx.a_buffer - off
              ; k= k }
      else ( ctx.a_max <- off
           ; safe k ctx ) in
    go ctx.a_max

  let recv ctx ~len =
    let k ctx =
      let str = Bytes.sub_string ctx.a_buffer ctx.a_pos len in
      ctx.a_pos <- ctx.a_pos + len ;
      Done str in
    prompt ~required:len k ctx
end

let ( let* ) =
  let rec go f m len = match m len with
    | Done v -> f v
    | Fail err -> Fail err
    | Rd { buf; off; len; k } ->
      Rd { buf; off; len; k= go f k }
    | Wr { str; off; len; k } ->
      let k0 = function `End -> k 0 | `Len len -> k len in
      let k1 = function
        | 0 -> go f k0 `End | len -> go f k0 (`Len len) in
      Wr { str; off; len; k= k1; } in
  fun m f -> match m with
  | Done v -> f v
  | Fail err -> Fail err
  | Rd { buf; off; len; k; } ->
    Rd { buf; off; len; k= go f k }
  | Wr { str; off; len; k; } ->
    let k0 = function `End -> k 0 | `Len len -> k len in
    let k1 = function 0 -> go f k0 `End | len -> go f k0 (`Len len) in
    Wr { str; off; len; k= k1; }

let ( let+ ) x f = match x with
  | Ok v -> f v
  | Error err -> Fail (`Spoke err)

let send = Send.send
let recv = Recv.recv
let return v = Done v

type cfg =
  | Cfg : 'a Spoke.algorithm * 'a -> cfg

let handshake_client ctx
  ?g ~identity password =
  let* public = recv ctx ~len:34 in
  let+ public = Spoke.public_of_string public in
  let+ ciphers = Spoke.ciphers_of_public public in
  let+ client, packet = Spoke.hello ?g ~public password in
  let* () = send ctx packet in
  let* packet = recv ctx ~len:96 in
  Logs.debug (fun m -> m "[o] <~ @[<hov>%a@]" (Hxd_string.pp Hxd.default) packet) ;
  let+ shared_keys, packet = Spoke.client_compute
    ~client ~identity packet in
  let* () = send ctx packet in
  Logs.debug (fun m -> m "Client terminates.") ;
  return (ciphers, shared_keys)

let handshake_server ctx
  ?g ~password ~identity (Cfg (algorithm, arguments)) =
  let secret, public = Spoke.generate ?g ~password
    ~algorithm arguments in
  let+ ciphers = Spoke.ciphers_of_public public in
  let* () = send ctx (Spoke.public_to_string public) in
  let* packet = recv ctx ~len:32 in
  Logs.debug (fun m -> m "[o] <~ @[<hov>%a@]" (Hxd_string.pp Hxd.default) packet) ;
  let+ server, packet = Spoke.server_compute ~secret ~identity
    packet in
  let* () = send ctx packet in
  let* packet = recv ctx ~len:64 in
  Logs.debug (fun m -> m "[o] <~ @[<hov>%a@]" (Hxd_string.pp Hxd.default) packet) ;
  let+ shared_keys = Spoke.server_finalize ~server packet in
  Logs.debug (fun m -> m "Server terminates.") ;
  return (ciphers, shared_keys)

module type CIPHER_BLOCK = sig
  type key

  val authenticate_encrypt : key:key -> nonce:Cstruct.t -> ?adata:Cstruct.t -> Cstruct.t -> Cstruct.t
  val authenticate_decrypt : key:key -> nonce:Cstruct.t -> ?adata:Cstruct.t -> Cstruct.t -> Cstruct.t option
  val of_secret : Cstruct.t -> key
end

type 'k cipher_block = (module CIPHER_BLOCK with type key = 'k)

let module_of : type k. k Spoke.aead -> k cipher_block = function
  | Spoke.GCM -> (module Mirage_crypto.Cipher_block.AES.GCM)
  | Spoke.CCM ->
    let module M = struct
      include Mirage_crypto.Cipher_block.AES.CCM
      let of_secret = of_secret ~maclen:16 end in
    (module M)
  | Spoke.ChaCha20_Poly1305 -> (module Mirage_crypto.Chacha20)

module Make (Flow : Mirage_flow.S) = struct
  open Lwt.Infix

  let ( >>? ) = Lwt_result.bind
  let reword_error f = function
    | Ok v -> Ok v
    | Error err -> Error (f err)

  type symmetric = Symmetric : { key : 'k; nonce : Cstruct.t ref; block_len : int; impl : 'k cipher_block } -> symmetric

  let symmetric_of_key_nonce_and_cipher key_nonce (Spoke.AEAD aead) =
    let key_len = match aead with
      | Spoke.GCM -> 32
      | Spoke.CCM -> 32
      | Spoke.ChaCha20_Poly1305 -> 32 in
    let module Cipher_block = (val module_of aead) in
    let key = Cstruct.of_string ~off:0 ~len:key_len key_nonce in
    Logs.debug (fun m -> m "Private key: %s"
      (Base64.encode_exn (String.sub key_nonce 0 key_len))) ;
    let key = Cipher_block.of_secret key in
    let nonce = Cstruct.of_string ~off:key_len ~len:(String.length key_nonce - key_len) key_nonce in
    let block_len = 16 in
    Symmetric { key; nonce= { contents= nonce }
              ; block_len; impl= (module Cipher_block) }

  type flow =
    { flow : Flow.flow
    ; recv : symmetric
    ; send : symmetric
    ; recv_queue : (char, Bigarray.int8_unsigned_elt) Ke.Rke.t
    ; send_queue : (char, Bigarray.int8_unsigned_elt) Ke.Rke.t }

  let blit0 src src_off dst dst_off len =
    let dst = Cstruct.of_bigarray dst ~off:dst_off ~len in
    Cstruct.blit src src_off dst 0 len

  let blit1 src src_off dst dst_off len =
    let src = Cstruct.of_bigarray src ~off:src_off ~len in
    Cstruct.blit_to_bytes src 0 dst dst_off len

  let run queue flow fiber =
    let cs_wr = Cstruct.create 128 in
    let allocator len = Cstruct.sub cs_wr 0 len in
    let rec go = function
      | Done v -> Lwt.return_ok v
      | Fail (#error as err) -> Lwt.return_error err
      | Rd { buf; off; len; k; } as fiber ->
        if Ke.Rke.is_empty queue
        then Flow.read flow >|= reword_error (fun err -> `Flow err) >>? function
          | `Eof -> go (k `End)
          | `Data cs ->
            Ke.Rke.N.push queue ~blit:blit0 ~length:Cstruct.length cs ;
            go fiber
        else ( let len = min len (Ke.Rke.length queue) in
               Ke.Rke.N.keep_exn queue ~blit:blit1 ~length:Bytes.length ~off ~len buf ;
               Ke.Rke.N.shift_exn queue len ;
               go (k (`Len len)) )
      | Wr { str; off; len; k; } ->
        let cs = Cstruct.of_string ~allocator ~off ~len str in
        Flow.write flow cs >|= reword_error (fun err -> `Flow_write err) >>? fun () -> go (k len) in
    go fiber

  let client_of_flow ?g ~identity ~password flow =
    let ctx = ctx () in
    let queue = Ke.Rke.create ~capacity:128 Bigarray.char in
    run queue flow (handshake_client ctx ?g ~identity password) >>? fun ((cipher0, cipher1), (k0, k1)) ->
    Ke.Rke.clear queue ;
    let recv = symmetric_of_key_nonce_and_cipher k0 cipher0 in
    let send = symmetric_of_key_nonce_and_cipher k1 cipher1 in
    let recv_queue = Ke.Rke.create ~capacity:0x1000 Bigarray.char in
    let send_queue = Ke.Rke.create ~capacity:0x1000 Bigarray.char in
    Lwt.return_ok { flow; recv; send; recv_queue; send_queue; }

  let server_of_flow ?g ~cfg ~identity ~password flow =
    let ctx = ctx () in
    let queue = Ke.Rke.create ~capacity:128 Bigarray.char in
    run queue flow (handshake_server ctx ?g ~identity ~password cfg) >>? fun ((cipher0, cipher1), (k0, k1)) ->
    Ke.Rke.clear queue ;
    let recv = symmetric_of_key_nonce_and_cipher k0 cipher0 in
    let send = symmetric_of_key_nonce_and_cipher k1 cipher1 in
    let recv_queue = Ke.Rke.create ~capacity:0x1000 Bigarray.char in
    let send_queue = Ke.Rke.create ~capacity:0x1000 Bigarray.char in
    Lwt.return_ok { flow; recv; send; recv_queue; send_queue; }

  type write_error =
    [ `Closed
    | `Flow of Flow.error
    | `Flow_write of Flow.write_error
    | error ]

  let pp_write_error ppf = function
    | `Closed -> Flow.pp_write_error ppf `Closed
    | `Flow err -> Flow.pp_error ppf err
    | `Flow_write err -> Flow.pp_write_error ppf err
    | #error as err -> pp_error ppf err

  type error =
    [ `Flow of Flow.error
    | `Corrupted ]

  let pp_error ppf = function
    | `Flow err -> Flow.pp_error ppf err
    | `Corrupted -> Fmt.pf ppf "Communication corrupted"

  let blit1 src src_off dst dst_off len =
    let src = Cstruct.of_bigarray ~off:src_off ~len src in
    Cstruct.blit src 0 dst dst_off len

  let fill_block block queue =
    assert (Ke.Rke.length queue >= Cstruct.length block) ;
    Ke.Rke.N.keep_exn queue ~blit:blit1 ~length:Cstruct.length block ;
    Ke.Rke.N.shift_exn queue (Cstruct.length block)

  external xor_into
    : Bigstringaf.t -> src_off:int -> Bigstringaf.t -> dst_off:int -> len:int -> unit
    = "spoke_xor_into_generic_bigarray"

  let xor nonce =
    let len = Cstruct.length nonce in
    let res = Cstruct.create len in
    xor_into (Cstruct.to_bigarray nonce) ~src_off:0
      (Cstruct.to_bigarray res) ~dst_off:0 ~len ; res

  let rec read flow queue (Symmetric { key; nonce; block_len; impl= (module Cipher_block) } as symmetric) =
    if Ke.Rke.length queue < block_len
    then Flow.read flow >>= function
      | Ok `Eof -> Lwt.return_ok `Eof
      | Ok (`Data cs) ->
        Ke.Rke.N.push queue ~blit:blit0 ~length:Cstruct.length cs ;
        read flow queue symmetric
      | Error err -> Lwt.return_error (`Flow err)
    else
      let block = Cstruct.create block_len in
      let rec go blocks =
        fill_block block queue ;
        Logs.debug (fun m -> m "Decrypt @[<hov>%a@]"
          (Hxd_string.pp Hxd.default) (Cstruct.to_string block)) ;
        match Cipher_block.authenticate_decrypt ~key ~nonce:!nonce block with
        | Some decrypted ->
          nonce := xor !nonce ;
          if Ke.Rke.length queue >= block_len then go (decrypted :: blocks)
          else Lwt.return_ok (List.rev blocks)
        | None -> Lwt.return_error `Corrupted in
      go [] >>? fun blocks ->
      let data = List.fold_left Cstruct.append Cstruct.empty blocks in
      Lwt.return_ok (`Data data)

  let write flow queue (Symmetric { key; nonce; block_len; impl= (module Cipher_block) }) data =
    Ke.Rke.N.push queue ~blit:blit0 ~length:Cstruct.length data ;
    let block = Cstruct.create block_len in
    let rec go blocks =
      Logs.debug (fun m -> m "Remaining %d byte(s)" (Ke.Rke.length queue)) ;
      if Ke.Rke.length queue >= block_len
      then ( fill_block block queue
           ; Logs.debug (fun m -> m "Encrypt key nonce:%s @[<hov>%a@]"
               (Base64.encode_exn (Cstruct.to_string !nonce))
               (Hxd_string.pp Hxd.default) (Cstruct.to_string block))
           ; let encrypted = Cipher_block.authenticate_encrypt ~key ~nonce:!nonce block in
             Logs.debug (fun m -> m "Data encrypted\n%!")
           ; nonce := xor !nonce
           ; go (encrypted :: blocks) )
      else List.rev blocks in
    let blocks = go [] in
    let blocks = List.fold_left Cstruct.append Cstruct.empty blocks in
    Logs.debug (fun m -> m "send @[<hov>%a@]"
      (Hxd_string.pp Hxd.default) (Cstruct.to_string blocks)) ;
    Flow.write flow blocks >>= function
    | Ok () -> Lwt.return_ok ()
    | Error err -> Lwt.return_error (`Flow_write err)

  let read { flow; recv; recv_queue; _ } = read flow recv_queue recv
  let write { flow; send; send_queue; _ } = write flow send_queue send
  let writev _flow _ccs = assert false
  let close { flow; _ } = Flow.close flow
end
