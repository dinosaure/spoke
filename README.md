# Spoke, a password-authenticated key agreement protocol in OCaml

The goal of Spoke is to establish an agreement on two strong keys from a shared
weak password. 

Let's start with Bob and Alice. They share a weak password and they want to
initiate a secure connection. Spoke is able to derive from this weak password 2
keys that can be used to establish a secure connection using symmetric
encryption (like AES).

Spoke implements a handshake between Alice and Bob and returns the 2 keys for
Alice and for Bob.

You can simulate this handshake with the bin/simulate.exe program. It creates a
socket and simulates a communication between Alice and Bob and finds an
arrangement about 2 keys usable for symmetric encryption.

```sh
$ dune exec bin/simulate.exe -- 127.0.0.1 hello-world
[11159][DEBUG][application]: <~ Waiting for read.
[11160][DEBUG][application]: [o] ~> 00000000: 0100 0200 1000 0000 0000 0000 0400 0000  ................
                                    00000010: 0000 0000 0ac4 1e0f 4aab 2cec b9ae 210d  ........J.,...!.
                                    00000020: a25f 05f2                                ._..
                                    
[11160][DEBUG][application]: <~ Waiting for read.
[11159][DEBUG][application]: [o] ~> 00000000: b125 4263 ac5a ecb4 cea4 8113 61e1 73c3  .%Bc.Z......a.s.
                                    00000010: 063a 6a5c c6ae 6f00 f759 772f 95b7 69ac  .:j\..o..Yw/..i.
                                    
[11159][DEBUG][application]: <~ Waiting for read.
[11160][DEBUG][application]: [o] <~ 00000000: b125 4263 ac5a ecb4 cea4 8113 61e1 73c3  .%Bc.Z......a.s.
                                    00000010: 063a 6a5c c6ae 6f00 f759 772f 95b7 69ac  .:j\..o..Yw/..i.
                                    
[11160][DEBUG][application]: [o] ~> 00000000: b251 8547 7c88 8cd7 b4fc e7f9 e242 f46c  .Q.G|........B.l
                                    00000010: 454c a092 cff3 a81f 83f4 b8b3 7d4d eb91  EL..........}M..
                                    00000020: 108c 12e4 4e59 a2c8 587b 9e6b 1354 2800  ....NY..X{.k.T(.
                                    00000030: 301b 81e6 2e4b b56e 6b6a d9b6 66cc 15f4  0....K.nkj..f...
                                    00000040: 254d 0cbc f1b4 af23 f456 4631 a04e b143  %M.....#.VF1.N.C
                                    00000050: 7c08 8270 1467 067a cac4 4fb3 8274 c2cf  |..p.g.z..O..t..
                                    
[11160][DEBUG][application]: <~ Waiting for read.
[11159][DEBUG][application]: [o] <~ 00000000: b251 8547 7c88 8cd7 b4fc e7f9 e242 f46c  .Q.G|........B.l
                                    00000010: 454c a092 cff3 a81f 83f4 b8b3 7d4d eb91  EL..........}M..
                                    00000020: 108c 12e4 4e59 a2c8 587b 9e6b 1354 2800  ....NY..X{.k.T(.
                                    00000030: 301b 81e6 2e4b b56e 6b6a d9b6 66cc 15f4  0....K.nkj..f...
                                    00000040: 254d 0cbc f1b4 af23 f456 4631 a04e b143  %M.....#.VF1.N.C
                                    00000050: 7c08 8270 1467 067a cac4 4fb3 8274 c2cf  |..p.g.z..O..t..
                                    
[11159][DEBUG][application]: [o] ~> 00000000: ac13 e2c8 496f cccf 0b59 c39d 8b21 1be7  ....Io...Y...!..
                                    00000010: 0e48 6658 c43e 7fab 5164 e88b 2f23 b93b  .HfX.>..Qd../#.;
                                    00000020: eba9 4259 909e 7e3a 5418 a385 4ae9 1f80  ..BY..~:T...J...
                                    00000030: 836c 5d27 647d 1c6f dfee 16d5 856c c58b  .l]'d}.o.....l..
                                    
[11159][DEBUG][application]: Client terminates.
[11159][DEBUG][fiber]: End of the process 11159.
[11159][DEBUG][fiber]: Result of 11159 marshalled.
[11160][DEBUG][application]: [o] <~ 00000000: ac13 e2c8 496f cccf 0b59 c39d 8b21 1be7  ....Io...Y...!..
                                    00000010: 0e48 6658 c43e 7fab 5164 e88b 2f23 b93b  .HfX.>..Qd../#.;
                                    00000020: eba9 4259 909e 7e3a 5418 a385 4ae9 1f80  ..BY..~:T...J...
                                    00000030: 836c 5d27 647d 1c6f dfee 16d5 856c c58b  .l]'d}.o.....l..
                                    
[11160][DEBUG][application]: Server terminates.
[11160][DEBUG][fiber]: End of the process 11160.
[11160][DEBUG][fiber]: Result of 11160 marshalled.
K0: 55g088LTc6zTZswBkZeGFrF4T3N6hR9TquOutYAr3rhCrqfGdks2/A4eMp7mFc4iAQ4pWXXNwydWTC8VSEhSng==
K1: S4Y1JCMpywH54Oknj3V1Nymci7rWk1enxZlAK/fKWY/EstmKKKybvVyXzYG0sd0FMA0hQ2vLpgrhNoW00D3cHQ==
```
