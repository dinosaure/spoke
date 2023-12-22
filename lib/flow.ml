let src = Logs.Src.create "spoke.flow"

module Log = (val Logs.src_log src : Logs.LOG)

type ctx = {
  a_buffer : bytes;
  mutable a_pos : int;
  mutable a_max : int;
  b_buffer : bytes;
  mutable b_pos : int;
}

let ctx () =
  {
    a_buffer = Bytes.create 128;
    a_pos = 0;
    a_max = 0;
    b_buffer = Bytes.create 128;
    b_pos = 0;
  }

let remaining_bytes_of_ctx { a_pos; a_max; a_buffer; _ } =
  if a_pos >= a_max then None
  else Some (Bytes.sub_string a_buffer a_pos (a_max - a_pos))

type error = [ `Not_enough_space | `End_of_input | `Spoke of Spoke.error ]

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

let leave_with _ctx error = raise (Leave error)
let safe k ctx = try k ctx with Leave err -> Fail err
let always x _ = x

module Send = struct
  let flush k0 ctx =
    if ctx.b_pos > 0 then
      let rec k1 n =
        if n < ctx.b_pos then
          Wr
            {
              str = Bytes.unsafe_to_string ctx.b_buffer;
              off = n;
              len = ctx.b_pos - n;
              k = (fun m -> k1 (n + m));
            }
        else (
          ctx.b_pos <- 0;
          k0 ctx)
      in
      k1 0
    else k0 ctx

  let write str ctx =
    let max = Bytes.length ctx.b_buffer in
    let go j l ctx =
      let rem = max - ctx.b_pos in
      let len = if l > rem then rem else l in
      Bytes.blit_string str j ctx.b_buffer ctx.b_pos len;
      ctx.b_pos <- ctx.b_pos + len;
      if len < l then leave_with ctx `Not_enough_space
    in
    go 0 (String.length str) ctx

  let send ctx str =
    safe
      (fun ctx ->
        write str ctx;
        flush (always (Done ())) ctx)
      ctx
end

module Recv = struct
  let prompt ~required k ctx =
    if ctx.a_pos > 0 then (
      let rest = ctx.a_max - ctx.a_pos in
      Bytes.blit ctx.a_buffer ctx.a_pos ctx.a_buffer 0 rest;
      ctx.a_max <- rest;
      ctx.a_pos <- 0);
    let rec go off =
      if off = Bytes.length ctx.a_buffer then Fail `Not_enough_space
      else if off - ctx.a_pos < required then
        let k = function
          | `Len len -> go (off + len)
          | `End -> Fail `End_of_input
        in
        Rd { buf = ctx.a_buffer; off; len = Bytes.length ctx.a_buffer - off; k }
      else (
        ctx.a_max <- off;
        safe k ctx)
    in
    go ctx.a_max

  let recv ctx ~len =
    let k ctx =
      let str = Bytes.sub_string ctx.a_buffer ctx.a_pos len in
      ctx.a_pos <- ctx.a_pos + len;
      Done str
    in
    prompt ~required:len k ctx
end

let ( let* ) =
  let rec go f m len =
    match m len with
    | Done v -> f v
    | Fail err -> Fail err
    | Rd { buf; off; len; k } -> Rd { buf; off; len; k = go f k }
    | Wr { str; off; len; k } ->
        let k0 = function `End -> k 0 | `Len len -> k len in
        let k1 = function 0 -> go f k0 `End | len -> go f k0 (`Len len) in
        Wr { str; off; len; k = k1 }
  in
  fun m f ->
    match m with
    | Done v -> f v
    | Fail err -> Fail err
    | Rd { buf; off; len; k } -> Rd { buf; off; len; k = go f k }
    | Wr { str; off; len; k } ->
        let k0 = function `End -> k 0 | `Len len -> k len in
        let k1 = function 0 -> go f k0 `End | len -> go f k0 (`Len len) in
        Wr { str; off; len; k = k1 }

let ( let+ ) x f = match x with Ok v -> f v | Error err -> Fail (`Spoke err)
let send = Send.send
let recv = Recv.recv
let return v = Done v

type cfg = Cfg : 'a Spoke.algorithm * 'a -> cfg

let handshake_client ctx ?g ~identity password =
  let* public = recv ctx ~len:34 in
  let+ ciphers = Spoke.ciphers_of_public public in
  let+ client, packet = Spoke.hello ?g ~public password in
  let* () = send ctx packet in
  let* packet = recv ctx ~len:96 in
  let+ shared_keys, packet =
    Spoke.client_compute ~client ~identity (String.sub packet 0 32)
      (String.sub packet 32 64)
  in
  let* () = send ctx packet in
  return (ciphers, shared_keys)

let handshake_server ctx ?g ~password ~identity (Cfg (algorithm, arguments)) =
  let ciphers = Spoke.(AEAD GCM, AEAD ChaCha20_Poly1305) in
  let secret, public =
    Spoke.generate ?g ~password ~ciphers ~algorithm arguments
  in
  let* () = send ctx (Spoke.public_to_string public) in
  let* packet = recv ctx ~len:32 in
  let+ server, (_Y, validator) =
    Spoke.server_compute ~secret ~identity packet
  in
  let* () = send ctx (_Y ^ validator) in
  let* packet = recv ctx ~len:64 in
  let+ shared_keys = Spoke.server_finalize ~server packet in
  return (ciphers, shared_keys)

type 'k cipher_block = (module Mirage_crypto.AEAD with type key = 'k)

let module_of : type k. k Spoke.aead -> k cipher_block = function
  | Spoke.GCM -> (module Mirage_crypto.Cipher_block.AES.GCM)
  | Spoke.CCM16 -> (module Mirage_crypto.Cipher_block.AES.CCM16)
  | Spoke.ChaCha20_Poly1305 -> (module Mirage_crypto.Chacha20)

module Make (Flow : Mirage_flow.S) = struct
  open Lwt.Infix

  let ( >>? ) = Lwt_result.bind
  let reword_error f = function Ok v -> Ok v | Error err -> Error (f err)

  type symmetric =
    | Symmetric : {
        key : 'k;
        nonce : Cstruct.t;
        impl : 'k cipher_block;
      }
        -> symmetric

  external xor_into :
    Bigstringaf.t ->
    src_off:int ->
    Bigstringaf.t ->
    dst_off:int ->
    len:int ->
    unit = "spoke_xor_into_generic_bigarray"

  let xor src dst =
    let len = min (Cstruct.length src) (Cstruct.length dst) in
    xor_into (Cstruct.to_bigarray src) ~src_off:0 (Cstruct.to_bigarray dst)
      ~dst_off:0 ~len

  let xor a b =
    let len = min (Cstruct.length a) (Cstruct.length b) in
    let res = Cstruct.of_string (Cstruct.to_string b ~off:0 ~len) in
    xor a res;
    res

  let make_nonce nonce seq =
    let seq =
      let len = Cstruct.length nonce in
      let seq =
        let buf = Cstruct.create 8 in
        Cstruct.BE.set_uint64 buf 0 seq;
        buf
      in
      let pad = Cstruct.create (len - 8) in
      Cstruct.append pad seq
    in
    xor nonce seq

  let make_adata len =
    let buf = Cstruct.create 4 in
    Cstruct.BE.set_uint16 buf 0 Spoke.version;
    Cstruct.BE.set_uint16 buf 2 len;
    buf

  let encrypt (Symmetric { key; nonce; impl = (module Cipher_block) }) sequence
      buf =
    let nonce = make_nonce nonce sequence in
    let adata = make_adata (Cstruct.length buf) in
    Cipher_block.authenticate_encrypt ~key ~adata ~nonce buf

  let decrypt (Symmetric { key; nonce; impl = (module Cipher_block) }) sequence
      buf =
    let nonce = make_nonce nonce sequence in
    let adata = make_adata (Cstruct.length buf - Cipher_block.tag_size) in
    Cipher_block.authenticate_decrypt ~key ~adata ~nonce buf

  let symmetric_of_key_nonce_and_cipher key_nonce (Spoke.AEAD aead) =
    let key_len =
      match aead with
      | Spoke.GCM -> 32
      | Spoke.CCM16 -> 32
      | Spoke.ChaCha20_Poly1305 -> 32
    in
    let nonce_len =
      match aead with
      | Spoke.GCM -> 12
      | Spoke.CCM16 -> 12
      | Spoke.ChaCha20_Poly1305 -> 12
    in
    let module Cipher_block = (val module_of aead) in
    let key = Cstruct.of_string ~off:0 ~len:key_len key_nonce in
    Log.debug (fun m ->
        m "Private key: %s" (Base64.encode_exn (String.sub key_nonce 0 key_len)));
    let key = Cipher_block.of_secret key in
    let nonce = Cstruct.of_string ~off:key_len ~len:nonce_len key_nonce in
    Symmetric { key; nonce; impl = (module Cipher_block) }

  type flow = {
    flow : Flow.flow;
    recv : symmetric;
    send : symmetric;
    recv_record : Cstruct.t;
    send_record : Cstruct.t;
    mutable recv_seq : int64;
    mutable send_seq : int64;
    recv_queue : (char, Bigarray.int8_unsigned_elt) Ke.Rke.t;
    send_queue : (char, Bigarray.int8_unsigned_elt) Ke.Rke.t;
  }

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
      | Rd { buf; off; len; k } as fiber ->
          if Ke.Rke.is_empty queue then (
            Flow.read flow >|= reword_error (fun err -> `Flow err) >>? function
            | `Eof -> go (k `End)
            | `Data cs ->
                Ke.Rke.N.push queue ~blit:blit0 ~length:Cstruct.length cs;
                go fiber)
          else
            let len = min len (Ke.Rke.length queue) in
            Ke.Rke.N.keep_exn queue ~blit:blit1 ~length:Bytes.length ~off ~len
              buf;
            Ke.Rke.N.shift_exn queue len;
            go (k (`Len len))
      | Wr { str; off; len; k } ->
          let cs = Cstruct.of_string ~allocator ~off ~len str in
          Flow.write flow cs >|= reword_error (fun err -> `Flow_write err)
          >>? fun () -> go (k len)
    in
    go fiber

  let max_record = 0xFFFF

  let client_of_flow ?g ~identity ~password flow =
    let ctx = ctx () in
    let queue = Ke.Rke.create ~capacity:128 Bigarray.char in
    run queue flow (handshake_client ctx ?g ~identity password)
    >>? fun ((cipher0, cipher1), (k0, k1)) ->
    let rem = remaining_bytes_of_ctx ctx in
    let rem = Option.value ~default:"" rem in
    let recv = symmetric_of_key_nonce_and_cipher k0 cipher0 in
    let send = symmetric_of_key_nonce_and_cipher k1 cipher1 in
    let recv_queue = Ke.Rke.create ~capacity:0x10000 Bigarray.char in
    let blit src src_off dst dst_off len =
      Bigstringaf.blit_from_string src ~src_off dst ~dst_off ~len
    in
    Ke.Rke.N.push recv_queue ~blit ~length:String.length rem;
    let send_queue = Ke.Rke.create ~capacity:0x10000 Bigarray.char in
    let recv_record =
      let (Symmetric { impl = (module Cipher_block); _ }) = recv in
      Cstruct.create (2 + max_record + Cipher_block.tag_size)
    in
    let send_record =
      let (Symmetric { impl = (module Cipher_block); _ }) = send in
      Cstruct.create (2 + max_record + Cipher_block.tag_size)
    in
    Lwt.return_ok
      {
        flow;
        recv;
        send;
        recv_record;
        send_record;
        recv_seq = 0L;
        send_seq = 0L;
        recv_queue;
        send_queue;
      }

  let server_of_flow ?g ~cfg ~identity ~password flow =
    let ctx = ctx () in
    let queue = Ke.Rke.create ~capacity:128 Bigarray.char in
    run queue flow (handshake_server ctx ?g ~identity ~password cfg)
    >>? fun ((cipher0, cipher1), (k0, k1)) ->
    let rem = remaining_bytes_of_ctx ctx in
    let rem = Option.value ~default:"" rem in
    Log.debug (fun m ->
        m "Remains %d byte(s) from the client." (String.length rem));
    let recv = symmetric_of_key_nonce_and_cipher k1 cipher1 in
    let send = symmetric_of_key_nonce_and_cipher k0 cipher0 in
    let recv_queue = Ke.Rke.create ~capacity:0x10000 Bigarray.char in
    let blit src src_off dst dst_off len =
      Bigstringaf.blit_from_string src ~src_off dst ~dst_off ~len
    in
    Ke.Rke.N.push recv_queue ~blit ~length:String.length rem;
    let send_queue = Ke.Rke.create ~capacity:0x10000 Bigarray.char in
    let recv_record =
      let (Symmetric { impl = (module Cipher_block); _ }) = recv in
      Cstruct.create (2 + max_record + Cipher_block.tag_size)
    in
    let send_record =
      let (Symmetric { impl = (module Cipher_block); _ }) = send in
      Cstruct.create (2 + max_record + Cipher_block.tag_size)
    in
    Lwt.return_ok
      {
        flow;
        recv;
        send;
        recv_record;
        send_record;
        recv_seq = 0L;
        send_seq = 0L;
        recv_queue;
        send_queue;
      }

  type write_error =
    [ `Closed | `Flow of Flow.error | `Flow_write of Flow.write_error | error ]

  let pp_write_error ppf = function
    | `Closed -> Flow.pp_write_error ppf `Closed
    | `Flow err -> Flow.pp_error ppf err
    | `Flow_write err -> Flow.pp_write_error ppf err
    | #error as err -> pp_error ppf err

  type error = [ `Flow of Flow.error | `Corrupted ]

  let pp_error ppf = function
    | `Flow err -> Flow.pp_error ppf err
    | `Corrupted -> Fmt.pf ppf "Communication corrupted"

  let get_record record queue symmetric =
    let (Symmetric { impl = (module Cipher_block); _ }) = symmetric in
    match Ke.Rke.length queue with
    | 0 -> `Await_hdr
    | 1 -> `Await_rec 1
    | 2 | _ ->
        let blit src src_off dst dst_off len =
          let src = Cstruct.of_bigarray src ~off:src_off ~len in
          Cstruct.blit src 0 dst dst_off len
        in
        Ke.Rke.N.keep_exn queue ~blit ~length:Cstruct.length record ~len:2;
        let len = Cstruct.BE.get_uint16 record 0 in
        if Ke.Rke.length queue >= len then (
          Ke.Rke.N.keep_exn queue ~blit ~length:Cstruct.length record ~len;
          Ke.Rke.N.shift_exn queue len;
          `Record (Cstruct.sub record 2 (len - 2)))
        else `Await_rec (len - Ke.Rke.length queue)

  let rec read flow =
    match get_record flow.recv_record flow.recv_queue flow.recv with
    | `Record buf -> (
        match decrypt flow.recv flow.recv_seq buf with
        | Some buf (* copy *) ->
            flow.recv_seq <- Int64.succ flow.recv_seq;
            Lwt.return_ok (`Data buf)
        | None -> Lwt.return_error `Corrupted)
    | (`Await_hdr | `Await_rec _) as await -> (
        Flow.read flow.flow >>= function
        | Error err -> Lwt.return_error (`Flow err)
        | Ok `Eof ->
            if await = `Await_hdr then Lwt.return_ok `Eof
            else Lwt.return_error `Corrupted
        | Ok (`Data buf) ->
            let blit src src_off dst dst_off len =
              let dst = Cstruct.of_bigarray dst ~off:dst_off ~len in
              Cstruct.blit src src_off dst 0 len
            in
            Ke.Rke.N.push flow.recv_queue ~blit ~length:Cstruct.length buf;
            read flow)

  let record ~dst ~sequence queue symmetric =
    let len = min max_record (Ke.Rke.length queue) in
    let blit src src_off dst dst_off len =
      let src = Cstruct.of_bigarray src ~off:src_off ~len in
      Cstruct.blit src 0 dst dst_off len
    in
    Ke.Rke.N.keep_exn queue ~length:Cstruct.length ~blit ~off:2 ~len dst;
    let buf (* copy *) = encrypt symmetric sequence (Cstruct.sub dst 2 len) in
    Ke.Rke.N.shift_exn queue len;
    let len = 2 + Cstruct.length buf in
    Cstruct.BE.set_uint16 dst 0 len;
    Cstruct.blit buf 0 dst 2 (Cstruct.length buf);
    Cstruct.sub dst 0 len

  let rec flush flow =
    if not (Ke.Rke.is_empty flow.send_queue) then (
      let record =
        record ~dst:flow.send_record ~sequence:flow.send_seq flow.send_queue
          flow.send
      in
      flow.send_seq <- Int64.succ flow.send_seq;
      Flow.write flow.flow record >>? fun () ->
      (* XXX(dinosaure): reset [send_record]? *)
      flush flow)
    else Lwt.return_ok ()

  let write flow data =
    Ke.Rke.N.push flow.send_queue ~blit:blit0 ~length:Cstruct.length data;
    flush flow >>= function
    | Ok () -> Lwt.return_ok ()
    | Error err -> Lwt.return_error (`Flow_write err)

  let read flow = read flow
  let write flow data = write flow data

  let writev flow css =
    let rec go = function
      | [] -> Lwt.return_ok ()
      | cs :: css ->
          write flow cs >>= function
          | Ok () -> go css | Error err -> Lwt.return_error err in
    go css

  let close { flow; _ } = Flow.close flow
  let shutdown { flow; _ } value = Flow.shutdown flow value
end
