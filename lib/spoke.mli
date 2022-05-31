type client
type server

type hash = Hash : 'k Digestif.hash -> hash

type 'a algorithm =
  | Pbkdf2 : int algorithm

type _ aead =
  | GCM : Mirage_crypto.Cipher_block.AES.GCM.key aead
  | CCM : Mirage_crypto.Cipher_block.AES.CCM.key aead
  | ChaCha20_Poly1305 : Mirage_crypto.Chacha20.key aead

type cipher =
  | AEAD : 'k aead -> cipher

type public
type secret

type shared_keys = string * string

type error =
  [ `Point_is_not_on_prime_order_subgroup
  | `Invalid_client_validator
  | `Invalid_server_validator
  | `Invalid_public_packet
  | `Invalid_secret_packet ]

val pp_error : error Fmt.t

val version : int

val generate :
  ?hash:hash ->
  ?ciphers:cipher * cipher ->
  ?g:Random.State.t ->
  password:string ->
  algorithm:'a algorithm -> 'a ->
  secret * public

val public_to_string : public -> string
val public_of_string : string -> (public, [> error ]) result
val ciphers_of_public : public -> (cipher * cipher, [> error ]) result

val hello :
  ?g:Random.State.t ->
  public:public ->
  string ->
  (client * string, [> error ]) result

val server_compute :
  ?g:Random.State.t ->
  secret:secret ->
  identity:string * string ->
  string ->
  (server * string, [> error ]) result

val client_compute :
  client:client ->
  identity:(string * string) ->
  string ->
  (shared_keys * string, [> error ]) result

val server_finalize :
  server:server ->
  string ->
  (shared_keys, [> error ]) result
