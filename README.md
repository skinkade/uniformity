# Uniformity

[![Clojars Project](https://img.shields.io/clojars/v/io.github.skinkade/uniformity.svg)](https://clojars.org/io.github.skinkade/uniformity)
[![CircleCI](https://circleci.com/gh/skinkade/uniformity/tree/main.svg?style=svg)](https://circleci.com/gh/skinkade/uniformity/?branch=main)

`uniformity` is a Clojure(Script) library for easy-to-use cryptographic primitives
and utilities, aiming for uniform behavior between Clojure platform targets.
The library should function the same whether you're using it on the JVM
or with ClojureScript. CLR and BEAM support planned.

On the JVM, `uniformity` is backed by `java.Security.SecureRandom`.
Within ClojureScript, it's backed by either `window.crypto.getRandomValues` in-browser,
or `crypto.randomBytes` in Node.js.



## Modules

### Crypto
`uniformity.crypto` provides a high-level, easy-to-use API for encrypting bytes
and strings with AES-GCM, using passwords and/or keys.
Passwords are treated as UTF-8 strings and processed with 100,000 rounds of
PBKDF2-HMAC-SHA256 by default.

Output can be chosen to be a Clojure map, JSON, or msgpack.
[See documentation](doc/crypto.md).

```clojure
;; password
(def password "Strong password")
(def encrypted (encrypt "Secret text" password))

;; key
(def secret-key (rand-bytes 16))
(def encrypted (encrypt "Secret text" secret-key))

;; or both...
(def encrypted (encrypt "Secret text" [password secret-key]))

;; ... and any key supplied works to decrypt
(decrypt encrypted password)
(decrypt encrypted secret-key)
```

### Random
`uniformity.random` contains functions for crytographically random:
- Booleans
- Bytes
- 32-bit integers
- Base64 / Hex strings
- UUIDs
- Collection sampling / shuffling
- Passwords / passphrases

[See documentation](doc/random.md).


### Util
`uniformity.util`, at the moment, is largely for:
- Encoding / decoding Base64 / Hex
- Encoding / decoding UTF-8 strings
- JSON (de)serialization
- msgpack (de)serialization

Input of encoding functions and output of decoding functions are byte arrays
(byte[] on JVM, Uint8Array in JS).
[See documentation](doc/util.md).