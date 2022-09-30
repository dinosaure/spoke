(** {1: The {i Flow} implementation of SPAKE2+EE.}

    This module provides a concrete implementation of the {i handshake} on the
    client side and the server side which is agnostic to any protocols. These
    implementations emits a {!type:t} which supervises the user knows that
    when to read ([Rd]) and when to write ([Wr]).

    From these implementations, the module provides a [Mirage_flow.S]
    implementation which requires a [Mirage_flow.S] implementation as the
    underlying implementation to read/write through a {i network}.

    {2: The agnostic implementation of the {i handshake}.}

    As a server, for instance, you have 2 available {i syscalls}, one to
    read [read : fd -> bytes -> int -> int -> int] and one to write
    [write : fd -> string -> unit]. You receive a connection and you have an
    [fd]. You are able to compute the handshake:

    {[
      let cfg = Flow.Cfg (Spoke.Pbkdf2, 16)
      let identities = "Bob", "Alice"
      let password = "Your Password"

      let handle_client fd =
        let ctx = Flow.ctx () in
        let rec go = function
          | Rd { buf; off; len; k; } ->
            ( match read fd buf off len with
            | 0 -> go (k `End)
            | len -> go (k (`Len len)) )
          | Wr { str; off; len; k; } ->
            let str = String.sub str off len in
            write fd str ; go (k len)
          | Done (ciphers, sk) -> Ok (ciphers, sk)
          | Fail err -> Error err in
        go (Flow.handshake_server ctx ~password ~identity:identities cfg)
    ]}

    A {!type:ctx} is required to keep incoming/outcoming data along the
    computation of {!type:t}.

    {2: A [Mirage_flow.S] which handles ciphers.}

    Obviously, we can go further than just complete the handshake. We can
    finally start a communication with our peer through a symmetric cipher. The
    {i functor} {!module:Make} gives you the ability to upgrade a given flow
    implementation to a secured transmission protocol through a symmetric
    cipher from a shared weak password. The example below is about a server
    which handles client connections and it wants to upgrade them through
    symmetric ciphers to finally send a secured ["Hello World"].

    {[
      module SPOKEFlow = Flow.Make (Tcpip)

      let cfg = Flow.Cfg (Spoke.Pbkdf2, 16)
      let identities = "Bob", "Alice"
      let password = "Your Password"

      let handle_client_with_with_secured_connection
        : SPOKEFlow.flow -> unit Lwt.t
        = fun flow ->
          SPOKEFlow.write flow "Secured Hello World!" >>= fun () ->
          ...

      let handle_client (fd : Tcpip.flow) =
        SPOKEFlow.server_of_flow ~cfg ~password ~identity:identities
        >>= function
        | Ok flow -> handle_client_with_secured_connection flow
        | Error err -> ...
    ]}
*)

type ctx
(** Type of a context. *)

val ctx : unit -> ctx
(** [ctx ()] creates a fresh {!type:ctx}. *)

val remaining_bytes_of_ctx : ctx -> string option
(** [remaining_bytes_of_ctx ctx] returns bytes which are not consumed
    by the handshake but they are already consumed by the [read] {i syscall}.
    In other words, at the end of the handshake, you may read more than you
    needed to and this function allows you to recover the excess. *)

type error = [ `Not_enough_space | `End_of_input | `Spoke of Spoke.error ]
(** The type of errors. *)

val pp_error : error Fmt.t
(** The pretty-printer of {!type:error}. *)

(** The type of actions needed to compute the handshake. *)
type 'a t =
  | Rd of { buf : bytes; off : int; len : int; k : 'a krd }
  | Wr of { str : string; off : int; len : int; k : 'a kwr }
  | Done of 'a
  | Fail of error

and 'a krd = [ `End | `Len of int ] -> 'a t
and 'a kwr = int -> 'a t

(** The type of configurations. *)
type cfg = Cfg : 'a Spoke.algorithm * 'a -> cfg

val handshake_client :
  ctx ->
  ?g:Random.State.t ->
  identity:string * string ->
  string ->
  ((Spoke.cipher * Spoke.cipher) * Spoke.shared_keys) t
(** [handshake_client ctx ~identity password] returns a {!type:t} which leads
    users when they need to read or write. If the handshake succeed, we return
    {!type:Spoke.cipher}s and {!type:Spoke.shared_keys}. Otherwise, we return
    an error. *)

val handshake_server :
  ctx ->
  ?g:Random.State.t ->
  password:string ->
  identity:string * string ->
  cfg ->
  ((Spoke.cipher * Spoke.cipher) * Spoke.shared_keys) t
(** [handshake_server ctx ~password ~identity cfg] returns a {!type:t} which
    leads users when they need to read or write. If the handshake succeed, we
    return {!type:Spoke.cipher}s and {!type:Spoke.shared_keys}. Otherwise, we
    return an error. *)

module Make (Flow : Mirage_flow.S) : sig
  type write_error =
    [ `Closed | `Flow of Flow.error | `Flow_write of Flow.write_error | error ]

  type error = [ `Flow of Flow.error | `Corrupted ]

  include
    Mirage_flow.S with type error := error and type write_error := write_error

  val client_of_flow :
    ?g:Random.State.t ->
    identity:string * string ->
    password:string ->
    Flow.flow ->
    (flow, [> write_error ]) result Lwt.t

  val server_of_flow :
    ?g:Random.State.t ->
    cfg:cfg ->
    identity:string * string ->
    password:string ->
    Flow.flow ->
    (flow, [> write_error ]) result Lwt.t
end
