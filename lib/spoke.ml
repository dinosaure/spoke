type shared_keys = string * string
type public = string
type secret = string

type scalar = Scalar of string

let scalar (Scalar v) = v

type keys =
  { _M : scalar
  ; _N : scalar
  ; _L : scalar
  ; h_K : string
  ; h_L : string }

external spoke_ed25519_from_uniform
  : bytes -> dst_off:int -> string -> src_off:int -> unit
  = "spoke_ed25519_from_uniform"

let ed25519_from_uniform src ~off =
  let buf = Bytes.create 32 in
  spoke_ed25519_from_uniform buf ~dst_off:0 src ~src_off:off ;
  Scalar (Bytes.unsafe_to_string buf)

external spoke_ed25519_scalarmult_base
  : bytes -> dst_off:int -> string -> src_off:int -> unit
  = "spoke_ed25519_scalarmult_base"

let ed25519_scalarmult_base hash ~off =
  let buf = Bytes.create 32 in
  spoke_ed25519_scalarmult_base buf ~dst_off:0 hash ~src_off:off ;
  Scalar (Bytes.unsafe_to_string buf)

external bytes_get_uint8  : bytes -> int -> int = "%bytes_safe_get"

external bytes_set_uint8  : bytes -> int -> int -> unit   = "%bytes_safe_set"
external bytes_set_uint16 : bytes -> int -> int -> unit   = "%caml_bytes_set16"
external bytes_set_uint32 : bytes -> int -> int32 -> unit = "%caml_bytes_set32"
external bytes_set_uint64 : bytes -> int -> int64 -> unit = "%caml_bytes_set64"

external string_get_uint16 : string -> int -> int   = "%caml_string_get16"
external string_get_uint64 : string -> int -> int64 = "%caml_string_get64"

let random_buffer ?g buf =
  let g = match g with
    | Some g -> g
    | None -> Random.State.make_self_init () in
  let len  = Bytes.length buf in
  let len0 = len land 3 in
  let len1 = len asr 2 in
  for i = 0 to len1 - 1 do
    let i = i * 4 in
    bytes_set_uint32 buf i (Random.State.bits32 g)
  done ;
  for i = 0 to len0 - 1 do
    let i = (len1 * 4) + i in
    bytes_set_uint8 buf i (Random.State.bits g land 0xff)
  done

let random_bytes ?g len =
  let buf = Bytes.create len in
  random_buffer ?g buf ; Bytes.unsafe_to_string buf

let version = 1
let version_string =
  let buf = Bytes.create 2 in
  bytes_set_uint16 buf 0 1 ; Bytes.unsafe_to_string buf

type _ algorithm = Pbkdf2 : int algorithm
type hash = Hash : 'k Digestif.hash -> hash

let algorithm_to_uint16 : type a. a algorithm -> int = function
  | Pbkdf2 -> 2

let hash_to_uint64 : type k. k Digestif.hash -> int64 = function
  | Digestif.SHA256 -> 4L
  | _ -> assert false (* TODO *)

let keys
  : type a. salt:string -> hash:hash -> string -> algorithm:a algorithm -> a -> keys * int64
  = fun ~salt ~hash password ~algorithm arguments ->
  let Hash hash = hash in
  let mnkl = match algorithm with
    | Pbkdf2 ->
      let count = arguments in
      Pbkdf2.generate hash ~password
        ~salt ~count (Int32.of_int (32 * 4)) in
  let h_K = String.sub mnkl 64 32 in
  let h_L = String.sub mnkl 96 32 in
  let _M = ed25519_from_uniform mnkl ~off:0 in
  let _N = ed25519_from_uniform mnkl ~off:32 in
  let _L = ed25519_scalarmult_base mnkl ~off:96 in
  let arguments = match algorithm with
    | Pbkdf2 -> Int64.of_int arguments in
  { _M; _N; _L; h_K; h_L; }, arguments

let generate : type a.
  ?hash:hash -> ?g:Random.State.t -> password:string -> algorithm:a algorithm -> a -> string * string 
  = fun ?(hash= Hash Digestif.SHA256) ?g ~password ~algorithm arguments ->
  let salt = random_bytes ?g 16 in
  let keys, arguments = keys ~salt ~hash password ~algorithm arguments in
  let Hash hash = hash in
  let secret = Bytes.create (2 + 2 + 8 + 8 + 16 + 32 + 32 + 32 + 32) in
  bytes_set_uint16 secret 0 version ;
  bytes_set_uint16 secret 2 (algorithm_to_uint16 Pbkdf2) ;
  bytes_set_uint64 secret 4 arguments ; (* count *)
  bytes_set_uint64 secret 12 (hash_to_uint64 hash) ;
  Bytes.blit_string salt 0 secret 20 16 ;
  Bytes.blit_string (scalar keys._M) 0 secret 36 32 ;
  Bytes.blit_string (scalar keys._N) 0 secret 68 32 ;
  Bytes.blit_string keys.h_K 0 secret 100 32 ;
  Bytes.blit_string (scalar keys._L) 0 secret 132 32 ;
  let public = Bytes.create (2 + 2 + 8 + 8 + 16) in
  bytes_set_uint16 public 0 version ;
  bytes_set_uint16 public 2 (algorithm_to_uint16 Pbkdf2) ;
  bytes_set_uint64 public 4 arguments ;
  bytes_set_uint64 public 12 (hash_to_uint64 hash) ;
  Bytes.blit_string salt 0 public 20 16 ;
  Bytes.unsafe_to_string secret, Bytes.unsafe_to_string public

let public_to_string str = str
let public_of_string str = Ok str

type a = Algorithm : 'a algorithm -> a

let zero = String.make 32 '\000'

let random_scalar ?g () =
  let buf = Bytes.create 32 in
  let rec go () =
    random_buffer ?g buf ;
    Bytes.set buf 0  (Char.chr (bytes_get_uint8 buf 0  land 248)) ;
    Bytes.set buf 31 (Char.chr (bytes_get_uint8 buf 31 land 127)) ;
    if Eqaf.compare_be (Bytes.unsafe_to_string buf) zero = 0
    then go () in
  go () ; Bytes.unsafe_to_string buf

external spoke_ed25519_scalarmult_base_noclamp
  : bytes -> dst_off:int -> string -> src_off:int -> unit
  = "spoke_ed25519_scalarmult_base_noclamp"

let ed25519_scalarmult_base_noclamp hash ~off =
  let buf = Bytes.create 32 in
  spoke_ed25519_scalarmult_base_noclamp buf ~src_off:0 hash ~dst_off:off ;
  Scalar (Bytes.unsafe_to_string buf)

external spoke_ed25519_add
  : bytes -> dst_off:int -> string -> string -> unit
  = "spoke_ed25519_add"

let ed25519_add (Scalar f) (Scalar g) =
  let buf = Bytes.create 32 in
  spoke_ed25519_add buf ~dst_off:0 f g ;
  Scalar (Bytes.unsafe_to_string buf)

exception Invalid_version
exception Invalid_algorithm
exception Invalid_hash

type client =
  { h_K : string
  ; h_L : string
  ; _N  : scalar
  ; x   : string
  ; _X  : scalar }

let hello ?g ~public password =
  let version' = string_get_uint16 public 0 in
  if version' <> version
  then raise Invalid_version ;
  let Algorithm algorithm = match string_get_uint16 public 2 with
    | 2 -> Algorithm Pbkdf2
    | _ -> raise Invalid_algorithm in
  let Hash hash = match string_get_uint64 public 12 with
    | 4L -> Hash Digestif.SHA256
    | _  -> raise Invalid_hash in
  let salt = String.sub public 20 16 in
  let keys, _arguments = match algorithm, string_get_uint64 public 4 with
    | Pbkdf2, count ->
      let count = Int64.to_int count in
      keys ~salt ~hash:(Hash hash) password ~algorithm count in
  let x = random_scalar ?g () in
  let gx = ed25519_scalarmult_base_noclamp x ~off:0 in
  let _X = ed25519_add gx keys._M in
  { h_K= keys.h_K; h_L= keys.h_L; _N= keys._N; x; _X }, scalar _X

type error =
  [ `Point_is_not_on_prime_order_subgroup
  | `Invalid_client_validator
  | `Invalid_server_validator ]

let pp_error ppf = function
  | `Point_is_not_on_prime_order_subgroup -> Fmt.pf ppf "Point is not on prime-order subgroup"
  | `Invalid_client_validator -> Fmt.pf ppf "Invalid client validator"
  | `Invalid_server_validator -> Fmt.pf ppf "Invalid server validator"

external spoke_ed25519_scalarmult_noclamp
  : bytes -> string -> src_off:int -> point:string -> bool
  = "spoke_ed25519_scalarmult_noclamp"

let ed25519_scalarmult_noclamp hash ~off ~point:(Scalar point) =
  let buf = Bytes.create 32 in
  let res = spoke_ed25519_scalarmult_noclamp buf hash ~src_off:off ~point in
  if res then Ok (Scalar (Bytes.unsafe_to_string buf))
  else Error `Point_is_not_on_prime_order_subgroup

external spoke_ed25519_scalarmult
  : bytes -> string -> src_off:int -> point:string -> bool
  = "spoke_ed25519_scalarmult"

let ed25519_scalarmult hash ~off ~point:(Scalar point) =
  let buf = Bytes.create 32 in
  let res = spoke_ed25519_scalarmult buf hash ~src_off:off ~point in
  if res then Ok (Scalar (Bytes.unsafe_to_string buf))
  else Error `Point_is_not_on_prime_order_subgroup

let subkey_from_key ~identity context main_key =
  if String.length context > 8
  then Fmt.invalid_arg "Invalid context for key derivation" ;
  let ctx =
    let buf = Bytes.make 16 '\000' in
    Bytes.blit_string context 0 buf 0 (String.length context) ;
    Bytes.unsafe_to_string buf in
  let salt =
    let buf = Bytes.make 16 '\000' in
    bytes_set_uint64 buf 0 identity ; Bytes.unsafe_to_string buf in
  let module Hash = Digestif.BLAKE2B in
  Hash.Keyed.mac_string ~key:main_key (ctx ^ salt) |> Hash.to_raw_string
  (* XXX(dinosaure): [salt] and [ctx] can be a part of the BLAKE2B initialization.
   * However, [digestif] does not provide such API. *)

let context = "SPOKE"

let shared_keys_and_validators ~identity:(client, server) (Scalar _X) (Scalar _Y) (Scalar _Z) h_K (Scalar _V) =
  let module Hash = Digestif.BLAKE2B in
  let ctx = Hash.empty in
  let ctx = Hash.feed_string ctx version_string in
  let ctx = Hash.feed_string ctx client in
  let ctx = Hash.feed_string ctx server in
  let ctx = Hash.feed_string ctx _X in
  let ctx = Hash.feed_string ctx _Y in
  let ctx = Hash.feed_string ctx _Z in
  let ctx = Hash.feed_string ctx h_K in
  let ctx = Hash.feed_string ctx _V in
  let main_key = Hash.to_raw_string (Hash.get ctx) in
  let client_sk = subkey_from_key ~identity:0L context main_key in
  let server_sk = subkey_from_key ~identity:1L context main_key in
  let client_validator = subkey_from_key ~identity:2L context main_key in
  let server_validator = subkey_from_key ~identity:3L context main_key in
  (client_sk, server_sk), (client_validator, server_validator)

external spoke_ed25519_sub
  : bytes -> dst_off:int -> string -> string -> unit
  = "spoke_ed25519_sub"

let ed25519_sub (Scalar f) (Scalar g) =
  let buf = Bytes.create 32 in
  spoke_ed25519_sub buf ~dst_off:0 f g ;
  Scalar (Bytes.unsafe_to_string buf)

let ( let* ) = Result.bind

type server =
  { validator : string
  ; shared_keys : string * string }

let server_compute ?g ~secret ~identity packet =
  let _version' = string_get_uint16 secret 0 in
  let Algorithm _algorithm = match string_get_uint16 secret 2 with
    | 2 -> Algorithm Pbkdf2
    | _ -> raise Invalid_algorithm in
  let Hash _hash = match string_get_uint64 secret 12 with
    | 4L -> Hash Digestif.SHA256
    | _  -> raise Invalid_hash in
  let _salt = String.sub secret 20 16 in
  let _M = Scalar (String.sub secret 36 32) in
  let _N = Scalar (String.sub secret 68 32) in
  let h_K = String.sub secret 100 32 in
  let _L = Scalar (String.sub secret 132 32) in
  let y = random_scalar ?g () in
  let gy = ed25519_scalarmult_base_noclamp y ~off:0 in
  let _Y = ed25519_add gy _N in
  let _X = Scalar packet in
  let gx = ed25519_sub _X _M in
  let* _Z = ed25519_scalarmult_noclamp y ~off:0 ~point:gx in
  let* _V = ed25519_scalarmult_noclamp y ~off:0 ~point:_L in
  let shared_keys, validators = shared_keys_and_validators ~identity _X _Y _Z h_K _V in
  Ok ({ shared_keys; validator= snd validators; }, ((scalar _Y) ^ (fst validators)))

let client_compute ~client ~identity packet =
  let client_validator = String.sub packet 32 (String.length packet - 32) in
  let _Y = Scalar (String.sub packet 0 32) in
  let gy = ed25519_sub _Y client._N in
  let* _Z = ed25519_scalarmult_noclamp client.x ~off:0 ~point:gy in
  let* _V = ed25519_scalarmult client.h_L ~off:0 ~point:gy in
  let shared_keys, validators = shared_keys_and_validators ~identity client._X _Y _Z client.h_K _V in
  if Eqaf.compare_le (fst validators) client_validator = 0
  then Ok (shared_keys, snd validators)
  else Error `Invalid_client_validator

let server_finalize ~server packet =
  if Eqaf.compare_le server.validator packet = 0
  then Ok server.shared_keys
  else Error `Invalid_server_validator
