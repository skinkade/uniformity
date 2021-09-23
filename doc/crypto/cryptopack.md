# uniformity.crypto.cryptopack

The cryptopack module provides a high-level encryption function
that produces a self-describing 'pack' of ciphertext and
self-descriptive format metadata.

User-provided keys and passwords are never directly used to encrypt user-provided
plaintext. Rather, a unique data encryption key is generated for each piece of
data, and user-provided keys and passwords are used for key encryption keys.
Encrypted copies of the data encryption key are stored in key slots within the
metadata alongside the ciphertext.

Allowed length for AES-GCM keys are 128, 192, and 256 bits.
Nonces are 96 bits, and authentication tags are 128 bits.

Plaintext strings are treated as UTF-8 bytes.

RSA public keys are byte arrays in SPKI format.
RSA private keys are byte arrays in PKCS#8 format.

Note that the pretty-printed vectors of integers below are in reality byte arrays
(byte[] on JVM, Uint8Array in JS).


### Docstring

```
uniformity.crypto.cryptopack/encrypt
([plaintext
  & {:keys [aes-key password rsa-pubkey output padding enc-key-size]
     :or {output :map, padding nil, enc-key-size 128}}])
  Encrypts plaintext with a random data encryption key.
  DEK is protected with each of the provided key encryption keys
  and stored in slots in the output.

  `plaintext` parameter may be either a byte array, or a string,
  which will be treated as UTF-8 bytes.

  The following key types are supported, as either scalar values or vectors:
  - :aes-key takes one or more byte arrays of length 16, 24, or 32
  - :password takes one or more strings
  - :rsa-pubkey takes one or more byte arrays of SPKI format RSA public keys

  The following additional options are supported:
  - :output must be one of :json, :msgpack, or :map (default)
  - :padding may be a number between 1 and 255 for PKCS#7 padding of plaintext

  Basic example:

  (def password "A strong password")
  (encrypt "Attack at dawn" :password password)

  Advanced example:

  (def backup-key (rand-bytes 16))
  (encrypt "hello world"
           :password ["foo" "bar"]
           :aes-key backup-key
           :output :msgpack
           :padding 16)
```


## Examples

```clojure
(ns com.example
  (:require [uniformity.crypto.cryptopack :refer [encrypt
                                                  decrypt]]
            [uniformity.random :refer [rand-bytes]]
            [uniformity.util :refer [hex-decode]]
            [clojure.pprint :refer [pprint]]
            [clojure.core.async :refer [<! <!! go]]))
```

Keep in mind that all encryption operations in `uniformity` are async.

```clojure
(<!!
 (go
   (let [backup-key (rand-bytes 16)
         encrypted (<! (encrypt "hello world"
                                :password ["foo" "bar"]
                                :aes-key backup-key
                                :output :msgpack
                                :padding 16))]
     ;; either password or the backup key will work
     (<!
      (decrypt encrypted
               :password "bar"
               :output :string)))))
;; => "hello world"
```