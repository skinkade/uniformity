(ns uniformity.internals.crypto.algo-js
  (:require ["asmcrypto.js" :as asmcrypto]
            [uniformity.util :as util]))

(defn pbkdf2-hmac-sha256
  [password salt iterations key-length-bits]
  (let [password (if (string? password)
                   (util/str->utf8 password)
                   password)
        key-length (/ key-length-bits 8)]
    (asmcrypto/Pbkdf2HmacSha256 password salt iterations key-length)))

(defonce ^:private gcm-tag-length (/ 128 8))
(defonce ^:private gcm-nonce-length (/ 96 8))

(defn aes-gcm-encrypt
  [plaintext key nonce
   & {:keys [aad] :or {aad []}}]
  {:pre [(contains? #{16 24 32} (aget key "length"))
         (= gcm-nonce-length (aget nonce "length"))]}
  (.encrypt asmcrypto/AES_GCM
            plaintext
            key
            nonce
            aad
            gcm-tag-length))

(defn aes-gcm-decrypt
  [ciphertext key nonce
   & {:keys [aad] :or {aad []}}]
  {:pre [(contains? #{16 24 32} (aget key "length"))
         (= gcm-nonce-length (aget nonce "length"))]}
  (.decrypt asmcrypto/AES_GCM
            ciphertext
            key
            nonce
            aad
            gcm-tag-length))
