type ctx

val ctx : unit -> ctx

type error =
  [ `Not_enough_space
  | `End_of_input
  | `Spoke of Spoke.error ]

val pp_error : error Fmt.t

type 'a t =
  | Rd of { buf : bytes; off : int; len : int; k : 'a krd }
  | Wr of { str : string; off : int; len : int; k : 'a kwr }
  | Done of 'a
  | Fail of error
and 'a krd = [ `End | `Len of int ] -> 'a t
and 'a kwr = int -> 'a t

type cfg =
  | Cfg : 'a Spoke.algorithm * 'a -> cfg

val handshake_client : ctx -> ?g:Random.State.t -> identity:(string * string) -> string
  -> ((Spoke.cipher * Spoke.cipher) * Spoke.shared_keys) t
val handshake_server : ctx -> ?g:Random.State.t -> password:string -> identity:(string * string) -> cfg
  -> ((Spoke.cipher * Spoke.cipher) * Spoke.shared_keys) t

module Make (Flow : Mirage_flow.S) : sig
  type write_error =
    [ `Closed
    | `Flow of Flow.error
    | `Flow_write of Flow.write_error
    | error ]

  type error =
    [ `Flow of Flow.error
    | `Corrupted ]

  include Mirage_flow.S with type error := error
                         and type write_error := write_error

  val client_of_flow : ?g:Random.State.t -> identity:(string * string) -> password:string -> Flow.flow
    -> (flow, [> write_error ]) result Lwt.t
  val server_of_flow : ?g:Random.State.t -> cfg:cfg -> identity:(string * string) -> password:string -> Flow.flow
    -> (flow, [> write_error ]) result Lwt.t
end
