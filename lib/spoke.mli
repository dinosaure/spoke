(** {1: Spoke, an implementation of SPAKE2+EE in OCaml.}

    Spoke is an implementation of SPAKE2+EE, a Password-Authenticated Key
    Agreement. It permits to find an agreement between two people who share a
    weak password with a strong key via an exchange of few information. From
    the shared strong key, 2 people can initiate a communication via, for
    example, a symmetric cryptographic method such as GCM or ChaCha20 Poly1305.

    This module wants to implement the necessary cryptographic primitives for
    this agreement.

    {2: The Handshake.}

    We identify 2 persons, a [server] and a [client]. The server will generate
    some values and a {i salt} and send it to the client with {!val:generate}.
    2 values are then generated, {!type:secret} and {!type:public}. The first
    must be strictly known only by the server. The second must be transferred
    to the client.

    The client can manipulate [public] with {!val:hello} and generate a value
    to be passed to the server. The value is named [X]. {!val:hello} returns
    a {!type:client} value which must be kept by the client.

    The server can then manipulate this received value with
    {!val:server_compute} to produce 2 values (which can be concatenated) to
    send to the client. These values are: [Y] and [client_validator]. The first
    participates to the handshake, the second checks the shared key on the
    client side. {!val:server_compute} returns a {!type:server} which must be
    kept by the server and used later.

    The client can finalise the agreement with {!val:client_compute} by finally
    calculating the {type:shared_keys}. It requires the [Y] value and the
    [client_validator] value as well as the {!type:client} value returned
    previously. It will then send a final value to ensure that the server can
    correctly produce the said shared key. The name of this value is the
    [server_validator].

    Finally, the server can commit the agreement by checking the value
    transmitted by the client as well as the {!type:server} value generated
    previously and in turn generating the shared key.

    {2: Parameters.}

    The user is able to choose:
    - the [KDF] function used to generate values (see {!type:algorithm})
    - an argument which will be used by the chosen algorithm
    - {!type:cipher}s which will be used by the client and the server
    - tha {!type:hash} algorithm used to craft internal values

    {2: Order of primities.}

    Following the handshake explanation above, here is an example of the order
    in which the primitives should be executed:
    {[
      let run ~password =
        let secret, public = Spoke.generate ~password ~algorithm:Pbkdf2 16 in
        let+ client, _X = Spoke.hello ~public password in
        let+ server, (_Y, client_validator) = Spoke.server_compute ~secret
          ~identity:("Bob", "Alice") _X in
        let+ sk0, server_validator = Spoke.client_compute ~client
          ~identity:("Bob", "Alice") _Y client_validator in
        let+ sk1 = Spoke.server_finalize ~server server_validator in
        assert (sk0 = sk1)
    ]}
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
