# Uniformity

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
`uniformity.random` contains functions for generating crytographically random
booleans, bytes, 32-bit integers, base64/hex-encoded strings, UUIDs,
collection samples, and passwords/passphrases.
[See documentation](doc/random.md).

`uniformity.util`, at the moment, is largely for encoding/decoding base64/hex,
JSON serialization, and UTF-8 string encoding/decoding.
Input of encoding functions and output of decoding functions are byte arrays
(byte[] on JVM, Uint8Array in JS).
[See documentation](doc/util.md).