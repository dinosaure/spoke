(** {1: Spoke, an implementation of SPAKE2+EE in OCaml.}

    Spoke is an implementation of SPAKE2+EE, a Password-Authenticated Key
    Agreement. It permits to find an agreement between two people with a strong
    key via an exchange of few information. From the shared strong
    key, 2 people can initiate a communication via, for example, a symmetric
    cryptographic method such as GCM or ChaCha20 Poly1305.

    This module wants to implement the necessary cryptographic primitives for
    this agreement.

    {2: The Handshake.}

    We identify 2 persons, a [server] and a [client]. The server will generate
    some values and a {i salt} and send it to the client with {!val:generate}.
    2 values are then generated, {type:secret} and {type:public}. The first
    must be strictly known only to the server. The second must be transferred
    to the client.

    The client can manipulate [public] with {!val:hello} and generate a value
    to be passed to the server.

    The server can then manipulate this received value with
    {!val:server_compute} to produce 2 values (which can be concatenated) to
    send to the client.

    The client can finalise the agreement with {val:client_compute} by finally
    calculating the {type:shared_keys}. It will then send a final value to
    ensure that the server can correctly produce the said shared key.

    Finally, the server can notify the agreement by checking the value
    transmitted by the client and in turn generating the shared key.

    {2: Parameters.}

    The user is able to choose:
    - the [KDF] function used to generate values (see {!type:algorithm}
    - an argument which will be used by the chosen algorithm
    - ciphers which will be used by the client and the server
*)

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
val public_of_secret : secret -> public

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
  (server * (string * string), [> error ]) result

val client_compute :
  client:client ->
  identity:(string * string) ->
  string -> string ->
  (shared_keys * string, [> error ]) result

val server_finalize :
  server:server ->
  string ->
  (shared_keys, [> error ]) result
