# Low-level Symmetric Encryption Usage

```clojure
(ns com.example
  (:require [uniformity.crypto :refer [aes-gcm-encrypt
                                       aes-gcm-decrypt]]
            [uniformity.random :refer [rand-bytes]]
            [uniformity.util :refer [str->utf8
                                     utf8->str]]))

(def aes-key (rand-bytes (/ 128 8)))
(def gcm-nonce (rand-bytes (/ 96 8)))
(def plaintext (str->utf8 "Hello world"))

(def ciphertext
  (aes-gcm-encrypt plaintext aes-key gcm-nonce))

(def decrypted
  (utf8->str
   (aes-gcm-decrypt ciphertext aes-key gcm-nonce)))
```