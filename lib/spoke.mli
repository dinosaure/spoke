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
(** The type of a client. *)

type server
(** The type of a server. *)

type hash = Hash : 'k Digestif.hash -> hash
(** The hash algorithm. *)

(** The [KDF] (Key Derivation Function) used to generate common informations
    between client & server. *)
type 'a algorithm =
  | Pbkdf2 : int algorithm

(** The type of Authenticated Encryptions with Associated Data. *)
type _ aead =
  | GCM : Mirage_crypto.Cipher_block.AES.GCM.key aead
  | CCM : Mirage_crypto.Cipher_block.AES.CCM.key aead
  | ChaCha20_Poly1305 : Mirage_crypto.Chacha20.key aead

(** The type of ciphers. *)
type cipher =
  | AEAD : 'k aead -> cipher

type public
(** The type of the public part of the handshake. *)

type secret
(** The type of the secret part of the handshake. *)

type shared_keys = string * string
(** The type of shared keys. *)

type error =
  [ `Point_is_not_on_prime_order_subgroup
  | `Invalid_client_validator
  | `Invalid_server_validator
  | `Invalid_public_packet
  | `Invalid_secret_packet ]
(** The type of errors. *)

val pp_error : error Fmt.t
(** The pretty-printer of {!type:error}. *)

val version : int
(** The version of the handshake. *)

val generate :
  ?hash:hash ->
  ?ciphers:cipher * cipher ->
  ?g:Random.State.t ->
  password:string ->
  algorithm:'a algorithm -> 'a ->
  secret * public
(** [generate ?hash ?ciphers ?g ~password ~algorithm v] generates the
    {!type:public} and the {!type:secret} informations used to handle the
    handshake for a server. *)

val public_to_string : public -> string
(** [public_to_string public] serializes the {!type:public} information into
    bytes. Therefore, the public information can be transmitted to a client
    throught a (secured?) channel. *)

val public_of_string : string -> (public, [> error ]) result
(** [public_of_string str] tries to deserialize a serie of bytes to a public
    information. *)

val ciphers_of_public : string -> (cipher * cipher, [> error ]) result
(** [ciphers_of_public str] returns ciphers announced by the {!type:public}
    information serialized. *)

val ciphers_of_client : client -> cipher * cipher
(** [ciphers_of_client client] returns ciphers from a {!type:client} value. *)

val public_of_secret : secret -> public
(** [public_of_secret secret] regenerates {!type:public} from {!type:secret}. *)

val hello :
  ?g:Random.State.t ->
  public:string ->
  string ->
  (client * string, [> error ]) result
(** [hello ?g ~public password] tries to create a {!type:client} information
    from a serialized {!type:public} one and a [password]. It generates a
    curve point which should be transmitted to the server. *)

val server_compute :
  ?g:Random.State.t ->
  secret:secret ->
  identity:string * string ->
  string ->
  (server * (string * string), [> error ]) result
(** [server_compute ?g ~secret ~identity:(client, server) _X] tries to validate
    [_X] with the given {!type:secret} information and identities. It returns
    a {!type:server} information if it succeed as well as a curve point [_Y]
    and a {i client validator}. [_Y] and [client_validator] should be
    transmitted to the client.
    
    {b NOTE}: identities is something known to both parties. The client must
    recognise the server with a unique identifier (like ["Bob"]) and the
    server must recognise the client with a unique identifier (like ["Alice"]).
    But more concretely, the identifier can be the IP address as well as the
    port of each of the two peers. *)

val client_compute :
  client:client ->
  identity:(string * string) ->
  string -> string ->
  (shared_keys * string, [> error ]) result
(** [client_compute ~client ~identity:(client, server) _Y client_validator]
    tries to validate [_Y] and the [client_validator] with the given
    {!type:client} information and identities (for more details, about
    identities, you can look at the note for {!val:server_compute}). It
    returns {!type:shared_keys} and the server validator if it succeed. The
    [server_validator] should be transmitted to the server. *)

val server_finalize :
  server:server ->
  string ->
  (shared_keys, [> error ]) result
(** [server_finalize ~server server_validator] finalizes the handshake and
    tries to validate the given [server_validator] with the given
    {!type:server} information. If it succeed, it returns the
    {!type:shared_keys}. Then, the user is able to initiate a secure
    communication with the given client. *)
