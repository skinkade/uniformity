# Uniformity

[![Clojars Project](https://img.shields.io/clojars/v/io.github.skinkade/uniformity.svg)](https://clojars.org/io.github.skinkade/uniformity)
[![CircleCI](https://circleci.com/gh/skinkade/uniformity/tree/main.svg?style=svg)](https://circleci.com/gh/skinkade/uniformity/?branch=main)

**This library a work-in-progress.**

`uniformity` is a Clojure(Script) library for easy-to-use cryptographic primitives
and utilities, aiming for uniform behavior between Clojure platform targets.
The library should function the same whether you're using it on the JVM
or with ClojureScript. CLR support planned.

The library is effectively a wrapper for the following:
- JVM: `java.security.SecureRandom` and `javax.crypto`
- Node: built-in crypto module
- Browser: `window.crypto.getRandomValues` and the SubtleCrypto Web API
  * Note that SubtleCrypto, and therefore this library, are only usable in HTTPS contexts

## Examples

```clojure
(ns com.example
  (:require [uniformity.random :as r]
            [uniformity.crypto.core :as crypto]
            [uniformity.crypto.cryptopack :as pack]
            [clojure.core.async :refer [go <! <!!]]))
```

### Random value generation

```clojure
(r/rand-int32)
;; => 987787792

(r/rand-int32 100 1000)
;; => 646

(r/rand-web-token (/ 128 8))
;; => "FdZsrHmH7aJEvyC4L7HOcw"

(r/rand-uuid)
;; => #uuid "56ad902d-332a-41ec-9b34-13f3e048bfcc"

(def selections [:a :b :c :d :e :f :g :h :i :j :k :l :m :n :o :p])

(r/rand-selection selections)
;; => :j

(r/rand-selection selections 5)
;; => (:l :c :j :k :i)

(r/rand-shuffle selections)
;; => [:d :p :f :j :i :m :e :b :o :g :h :c :k :n :a :l]
```

### High-level async encryption with cryptopacks

```clojure
(def enc-key (r/rand-bytes 16))

(go
  (let [plaintext (byte-array [1 2 3 4])
        ciphertext (<! (pack/encrypt plaintext
                                     :aes-key enc-key))
        decrypted (<! (pack/decrypt ciphertext
                                    :aes-key enc-key))]
    (println (vec decrypted))))

;; Multiple keys of different types can be used
;; String plaintext will be decoded as UTF8 bytes,
;; When decrypting, specify :output :string for the result to be treated as UTF8
(go
  (let [plaintext "Hello world!"
        ciphertext (<! (pack/encrypt plaintext
                                     :password ["A strong password",
                                                "some-gibberish-string"]
                                     :aes-key enc-key))
        decrypted (<! (pack/decrypt ciphertext
                                    :password "A strong password"
                                    :output :string))]
  (println decrypted)))
```

## Modules

### Crypto

`uniformity.crypto.core` provides asynchronous AES-GCM, RSA, and PBKDF2 functionality.
[See documentation](doc/crypto/core.md).

`uniformity.crypto.cryptopack` provides a high-level API for encrypting bytes
and strings with AES-GCM; using passwords, symmetric keys, or RSA keys.
Passwords are treated as UTF-8 strings and processed with 100,000 rounds of
PBKDF2-HMAC-SHA256 by default.

Output can be chosen to be a Clojure map, JSON, or msgpack.
[See documentation](doc/crypto/cryptopack.md).


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


### Hash
`uniformity.hash` provides MD5 and SHA2 family hashing.
[See examples](doc/hash.md).


### Util
`uniformity.util`, at the moment, is largely for:
- Encoding / decoding Base64 / Hex
- Encoding / decoding UTF-8 strings
- JSON (de)serialization
- msgpack (de)serialization

Input of encoding functions and output of decoding functions are byte arrays
(byte[] on JVM, Uint8Array in JS).
[See documentation](doc/util.md).
