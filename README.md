## PLUC - Pure LuaU Crypto

A small collection of crpytographic functions, and related utilities, implemented in LuaU, forked from PLC on [GitHub](https://github.com/philanc/plc/tree/master)

This `README` has been heavily watered down, I recommend you read the original PLC [`README`](https://github.com/philanc/plc/tree/master#readme) as it has a LOT more information. 

### Recent changes

November 2023
Initial Project Creation

### Objective

Collect in one place standalone implementation of well-known, and/or useful,  and/or interesting cryptographic algorithms.

Users should be able to pickup any file and just drop it in their project:

* Original file were written in pure Lua, verion 5.3 and above (since bit operators, string pack/unpack are extensively used)
* Rewritten to work with LuaU

* The files should not define any global. When required, they should just return a table with the algorithm's functions and constants.

Contributions, fixes, bug reports and suggestions are welcome.

What this collection is *not*:

* a complete, structured cryptographic library - no promise is made about consistent API structure and documentation. This is not a library - just a collection of hopefully useful snippets of crypto source code. 

*  memory-efficient implementations (see above)

*  memory-safe algorithms  -- Lua immutable strings are used and garbage-collected as needed. No guarantee is made that information, and in particular key material, is properly erased when no longer needed or do not leak.


### Functions

Encryption

* Morus, an *amazingly* fast (see performance below) authenticated encryption algorithm with associated data (AEAD). Morus is a finalist (round 4) in the [CAESAR](http://competitions.cr.yp.to/caesar-submissions.html) competition - see https://personal.ntu.edu.sg/wuhj/research/caesar/caesar.html

* NORX, a *very* fast authenticated encryption algorithm with associated data (AEAD). NORX is a 3rd-round candidate to [CAESAR](http://competitions.cr.yp.to/caesar.html). This Lua code implements the default NORX 64-4-1 variant (state is 16 64-bit words, four rounds, no parallel execution, key and nonce are 256 bits) - see https://github.com/norx/resources

* NORX32, a variant of NORX intended for smaller architectures (32-bit and less). Key and nonce are 128 bits. (Note that this NORX32 Lua implementation is half as fast as the default 64-bit NORX. It is included here only for compatibility with other implementations - In Lua, use the default NORX implementation!)

* Rabbit, a fast stream cipher, selected in the eSTREAM portfolio along with Salsa20, and defined in [RFC 4503](https://tools.ietf.org/html/rfc4503) (128-bit key, 64-bit IV - see more information and links in rabbit.lua)

* Chacha20, Poly1305 and authenticated stream encryption, as defined in [RFC 7539](https://tools.ietf.org/html/rfc7539), and XChacha20 stream encryption (Chacha20 with a 24-byte nonce)

* Salsa20, a fast encryption algorithm and the NaCl secretbox() API for authenticated encryption (with Salsa20 and Poly1305 - see box.lua)
Salsa20, Poly1305 and the NaCl library have been designed by Dan Bernstein, Tanja Lange et al.  http://nacl.cr.yp.to/.

* RC4 - for lightweight, low strength encryption. Can also be used as a simple pseudo-random number generator.

Public key

* Elliptic curve cryptography based on curve ec25519 by Dan Bernstein, Tanja Lange et al.,  http://nacl.cr.yp.to/.  File ec25519.lua includes the core scalar multiplication operation. File box.lua includes the NaCl box() API which combines ECDH key exchange and authenticated encryption.

Hash

* Blake2b - Blake was a final round candidate in the NIST SHA-3 selection process.  Blake2b is an improved version of Blake. See https://blake2.net/. It has been specified in [RFC 7693](https://tools.ietf.org/html/rfc7693)

* SHA2 cryptographic hash family (sha256 and sha512)

* SHA3 cryptographic hash family (formerly known as Keccak - 256-bit and 512-bit versions)

* SipHash, a keyed hash function family optimized for speed on short messages, by Jean-Philippe Aumasson and Dan Bernstein. The variant implemented here is the default SipHash-2-4.

* MD5, as specified in [RFC 1321](https://tools.ietf.org/html/rfc1321)

* Non-cryptographic checksums (CRC-32, Adler-32), ...

Some (un)related utilities: 

* Base64, Base58, Base85 (Z85, the ZeroMQ variant of Ascii85)  and Hex encoding/decoding.

### License and credits

All the files included here are distributed under the MIT License (see file LICENSE)

The salsa20 and box/secretbox implementations are contributed by Pierre Chapuis - https://github.com/catwell

The sha2-256 and sha2-512 core permutation has been borrowed from Egor Skriptunoff's pure_lua_SHA2 project - https://github.com/Egor-Skriptunoff/pure_lua_SHA2
