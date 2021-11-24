(ns uniformity.crypto.core
  (:require [uniformity.random :refer [rand-bytes]]
            [uniformity.util :as util]
            [uniformity.internals.validation :refer [compat-bytes?
                                                     compat-byte-array
                                                     compat-count]]
            #?(:clj  [async-error.core :refer [go-try <?]]
               :cljs [async-error.core :refer-macros [go-try <?]])
            #?(:clj  [clojure.core.async :refer [go <!]]
               :cljs [cljs.core.async] :refer-macros [go <!])
            #?(:clj  [uniformity.internals.java.aes :as aes]
               :cljs [uniformity.internals.js.aes :as aes])
            #?(:clj  [uniformity.internals.java.rsa :as rsa]
               :cljs [uniformity.internals.js.rsa :as rsa])
            #?(:clj  [uniformity.internals.java.pbkdf2 :as pbkdf2-internal]
               :cljs [uniformity.internals.js.pbkdf2 :as pbkdf2-internal])))

(defn aes-gcm-encrypt
  "Encrypts plaintext using AES in GCM with key + nonce.
  Key must be 128, 192, or 256 bits long.
  Nonce must be 96 bits long.

  If no nonce provided, a random one will be generated.
  
  Returns channel containing nonce and ciphertext (+ auth tag)."
  [plaintext
   key
   & {:keys [nonce]}]
  (go-try
   (let [nonce (if (some? nonce)
                 nonce
                 (rand-bytes 12))
         ciphertext (<? (aes/aes-gcm-encrypt plaintext key nonce))]
     {:nonce nonce
      :ciphertext ciphertext})))

(defn aes-gcm-decrypt
  "Decrypts ciphertext with key + nonce.
  
  Returns channel containing plaintext as byte array."
  [plaintext key nonce]
  (aes/aes-gcm-decrypt plaintext key nonce))

(defn pbkdf2
  "Derives a key using PBKDF2 on password with the following optional parameters:

  :salt
  - byte array
  - default: 128 random bits
  :iterations
  - number
  - default: 100,000
  :hash
  - keyword, one of :sha1, :sha256, :sha384, :sha512
  - default: :sha256
  :key-length 
  - number
  - one of: 128, 192, 256
  - should be less than or equal to hash length
  - default: 128
              
  Returns a channel containing key as byte array."
  [password
   & {:keys [salt iterations hash key-length]
      :or {iterations 100000
           hash :sha256
           key-length 128}}]
  (go-try
   (let [salt (if (some? salt)
                salt
                (rand-bytes 16))
         key (<? (pbkdf2-internal/pbkdf2 password
                                         salt
                                         iterations
                                         hash
                                         key-length))]
     {:key key
      :salt salt
      :iterations iterations
      :hash hash
      :key-length key-length})))

(defn rsa-generate-keypair
  "Generates an RSA keypair with a key size of the number of bits specified.
  Only allows 2048-, 3072-, and 4096-bit keys to be generated.
 
  Returns a map containing a channel each for the public and private keys,
  accessible via :public and :private"
  [key-length]
  {:pre [(or (= key-length 2048)
             (= key-length 3072)
             (= key-length 4096))]}
  (rsa/rsa-generate-keypair key-length))

(defn rsa-encrypt
  "Takes a byte array plaintext and an RSA public key
  as an SPKI-encoded byte array.
  
  Returns a channel containing ciphertext as a byte array."
  [plaintext public-key]
  (rsa/rsa-encrypt plaintext public-key))

(defn rsa-decrypt
  "Takes a byte array ciphertext and an RSA private key
  as a PKCS#8-encoded byte array.
  
  Returns a channel containing plaintext as a byte array."
  [ciphertext private-key]
  (rsa/rsa-decrypt ciphertext private-key))
