let () = match Sys.argv with
  | [| _; unix_domain |]
    when not (Sys.file_exists unix_domain) ->
    let socket = Unix.socket Unix.PF_UNIX Unix.SOCK_DGRAM 0 in
    Unix.bind socket (Unix.ADDR_UNIX unix_domain) ;
    Unix.close socket
  | _ -> Fmt.epr "%s <unix-domain>\n%!" Sys.argv.(0)
