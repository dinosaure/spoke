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

let handshake0 ctx
  ?g ~identity password =
  let* public = recv ctx ~len:36 in
  let+ public = Spoke.public_of_string public in
  let client, packet = Spoke.hello ?g ~public password in
  let* () = send ctx packet in
  let* packet = recv ctx ~len:96 in
  Logs.debug (fun m -> m "[o] <~ @[<hov>%a@]" (Hxd_string.pp Hxd.default) packet) ;
  let+ shared_keys, packet = Spoke.client_compute
    ~client ~identity packet in
  let* () = send ctx packet in
  Logs.debug (fun m -> m "Client terminates.") ;
  return shared_keys

let handshake1 ctx
  ?g ~password ~identity (Cfg (algorithm, arguments)) =
  let secret, public = Spoke.generate ?g ~password
    ~algorithm arguments in
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
  return shared_keys
