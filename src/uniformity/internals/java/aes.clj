(ns uniformity.internals.java.aes
  (:require [clojure.core.async :refer [go]]
            [async-error.core :refer [go-try <?]])
  (:import [javax.crypto Cipher]
           [javax.crypto.spec SecretKeySpec]
           [javax.crypto.spec GCMParameterSpec]))

(defn aes-gcm-encrypt
  [^bytes plaintext
   ^bytes key
   ^bytes nonce]
  (go-try
   (when-not (contains? #{16 24 32} (count key))
     (throw (Exception. "AES key must be 128, 192, or 256 bits")))
   (when-not (= 12 (count nonce))
     (throw (Exception. "AES-GCM nonce must be 96 bits")))
   (let [key-spec (SecretKeySpec. key "AES")
         gcm-spec (GCMParameterSpec. 128 nonce)
         cipher-instance (Cipher/getInstance "AES/GCM/NoPadding")]
     (.init cipher-instance Cipher/ENCRYPT_MODE key-spec gcm-spec)
     (.doFinal cipher-instance plaintext))))

(defn aes-gcm-decrypt
  [^bytes ciphertext
   ^bytes key
   ^bytes nonce]
  (go-try
   (when-not (contains? #{16 24 32} (count key))
     (throw (Exception. "AES key must be 128, 192, or 256 bits")))
   (when-not (= 12 (count nonce))
     (throw (Exception. "AES-GCM nonce must be 96 bits")))
   (let [key-spec (SecretKeySpec. key "AES")
         gcm-spec (GCMParameterSpec. 128 nonce)
         cipher-instance (Cipher/getInstance "AES/GCM/NoPadding")]
     (.init cipher-instance Cipher/DECRYPT_MODE key-spec gcm-spec)
     (.doFinal cipher-instance ciphertext))))
