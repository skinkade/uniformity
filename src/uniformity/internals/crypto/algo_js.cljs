(ns uniformity.internals.crypto.algo-js
  (:require ["asmcrypto.js" :as asmcrypto]
            [uniformity.util :as util]))

(defn pbkdf2-hmac-sha256
  ^js/Uint8Array
  [password
   ^js/Uint8Array salt
   ^number iterations
   ^number key-length-bits]
  {:pre [(or
          (string? password)
          (instance? js/Uint8Array password))
         (>= (.-length salt) 16)
         (>= iterations 1000)
         (= 0 (mod key-length-bits 8))]
   :post [(= (.-length %)
             (/ key-length-bits 8))]}
  (let [password (if (string? password)
                   (util/str->utf8 password)
                   password)
        key-length (/ key-length-bits 8)]
    (asmcrypto/Pbkdf2HmacSha256 password salt iterations key-length)))

(defonce ^:private gcm-tag-length (/ 128 8))
(defonce ^:private gcm-nonce-length (/ 96 8))

(defn aes-gcm-encrypt
  ^js/Uint8Array
  [^js/Uint8Array plaintext
   ^js/Uint8Array key
   ^js/Uint8Array nonce
   & {:keys [aad] :or {aad []}}]
  {:pre [(contains? #{16 24 32} (.-length key))
         (= gcm-nonce-length (.-length nonce))]}
  (.encrypt asmcrypto/AES_GCM
            plaintext
            key
            nonce
            aad
            gcm-tag-length))

(defn aes-gcm-decrypt
  ^js/Uint8Array
  [^js/Uint8Array ciphertext
   ^js/Uint8Array key
   ^js/Uint8Array nonce
   & {:keys [aad] :or {aad []}}]
  {:pre [(contains? #{16 24 32} (.-length key))
         (= gcm-nonce-length (.-length nonce))]}
  (.decrypt asmcrypto/AES_GCM
            ciphertext
            key
            nonce
            aad
            gcm-tag-length))
