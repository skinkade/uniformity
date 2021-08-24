# Uniformity

`uniformity` is a Clojure(Script) library for easy-to-use cryptographic primitives
and utilities, aiming for uniform behavior between Clojure platform targets.
The library should function the same whether you're using it on the JVM
or with ClojureScript. CLR and BEAM support planned.

On the JVM, `uniformity` is backed by `java.Security.SecureRandom`.
Within ClojureScript, it's backed by either `window.crypto.getRandomValues` in-browser,
or `crypto.randomBytes` in Node.js.


## Modules

`uniformity.random` contains functions for generating crytographically random
booleans, bytes, 32-bit integers, base64/hex-encoded strings, UUIDs,
collection samples, and passwords/passphrases.
[See documentation](doc/random.md).

`uniformity.util`, at the moment, is largely for encoding/decoding base64/hex.
Input of encoding functions and output of decoding functions are byte arrays
(byte[] on JVM, Uint8Array in JS).
[See documentation](doc/util.md).