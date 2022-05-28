external xor_into
  : string -> src_off:int -> bytes -> dst_off:int -> len:int -> unit
  = "spoke_xor_into_generic" [@@noalloc]

external bytes_set_int32 : bytes -> int -> int32 -> unit = "%caml_bytes_set32"

external lessequal : 'a -> 'a -> bool = "%lessequal"

let imin (a : int) b =
  let ( <= ) (x : int) y = lessequal x y in
  if a <= b then a else b [@@inline]

let xor_into src ~src_off dst ~dst_off ~len =
  if len > imin (String.length src) (Bytes.length dst)
  then Fmt.invalid_arg "xor: buffers to small (need %d)" len
  else xor_into src ~src_off dst ~dst_off ~len

let xor str0 str1 =
  let len = imin (String.length str0) (String.length str1) in
  let buf = Bytes.of_string (String.sub str1 0 len) in
  ( xor_into str0 ~src_off:0 buf ~dst_off:0 ~len ; Bytes.unsafe_to_string buf )

let ( // ) x y =
  if y < 1 then raise Division_by_zero ;
  if x > 0 then 1 + ((x - 1) / y) else 0 [@@inline]

(* XXX(dinosaure): implementation of PBKDF 2 from ocaml-pbkdf without the
 * mirage-crypto dependency. ocaml-pbkdf is under the BSD-2-Clause license.
 *
 * Copyright (c) 2016, Alfredo Beaumont, Sonia Meruelo
 * All rights reserved. *)
let generate : type hash.
  hash Digestif.hash ->
  password:string ->
  salt:string ->
  count:int ->
  int32 -> string
  = fun hash ~password ~salt ~count len ->
  let module Hash = (val (Digestif.module_of hash)) in
  if count <= 0
  then Fmt.invalid_arg "pbkdf2: count must be a positive integer" ;
  if len <= 0l
  then Fmt.invalid_arg "pbkdf2: derived key length must be a positive integer" ;
  let hash_len = Hash.digest_size in
  let derived_key_len = Int32.to_int len in
  let len = derived_key_len // hash_len in
  let r = derived_key_len - (len - 1) * hash_len in
  let block idx : string =
    let rec go u v = function
      | 0 -> v
      | j ->
        let u = Hash.hmac_string ~key:password u in
        let u = Hash.to_raw_string u in
        go u (xor v u) (pred j) in
    let trailer =
      let buf = Bytes.make 4 '\000' in
      bytes_set_int32 buf 0 (Int32.of_int idx) ; Bytes.unsafe_to_string buf in
    let u = Hash.hmac_string ~key:password (salt ^ trailer) in
    let u = Hash.to_raw_string u in
    go u u (pred count) in
  let rec go blocks = function
    | 0 -> blocks
    | n -> go ((block n) :: blocks) (pred n) in
  String.concat "" (go [ String.sub (block len) 0 r ] (pred len))
