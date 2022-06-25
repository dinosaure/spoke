# Spoke, a password-authenticated key agreement protocol in OCaml

The goal of Spoke is to establish an agreement on two strong keys from a shared
weak password. This implementation comes from a description of SPAKE2+EE
available [here][spake2+ee].

Let's start with Bob and Alice. They share a weak password and they want to
initiate a secure connection. Spoke is able to derive from this weak password 2
keys that can be used to establish a secure connection using symmetric
encryption (like AEAD).

Spoke implements a handshake between Alice and Bob and returns the 2 keys for
Alice and for Bob. It provides a [Mirage\_flow.S][mirage-flow] implementation
which uses GCM, CCM or ChaCha20\_Poly1305 as a symmetric encryption mechamism
between the client to the server and the server to the client (they can be
different).

You can simulate this handshake with the `bin/simulate.exe` program. It creates
a socket and simulates a communication between Alice and Bob and finds an
arrangement about 2 keys usable for symmetric encryption. Then, it sends a file
to the server which repeats contents to the client. The client check the
integrity of the received contents.

```
                         .---->----. (via GCM)
                 [ client ]       [ server ]
 (via ChaCha20_Poly1305) '----<----'
```

You can execute it with:

```sh
$ dune exec bin/simulate.exe -- filename 127.0.0.1:9000 hello-world
```

The goal of this tool is to ensure:
- that the handshake is done correctly if Bob & Alice share the same password
- the transmission throught a symmetric cipher from the shared keys works

A full explanation of the protocol and the handshake is available on my blog:
[Spoke, how to implement a little cryptographic protocol][spoke]. Finally, you
should take a look on [bob][bob] which has a real usage of Spoke.

[spake2+ee]: https://moderncrypto.org/mail-archive/curves/2015/000424.html
[mirage-flow]: https://github.com/mirage/mirage-flow/
[spoke]: https://blog.osau.re/articles/spoke.html
[bob]: https://github.com/dinosaure/bob
