(ns uniformity.internals.java.rsa
  (:require [clojure.core.async :refer [chan go put!]]
            [async-error.core :refer [go-try <?]])
  (:import [javax.crypto Cipher]
           [java.security KeyPairGenerator]
           [java.security KeyFactory]
           [java.security.spec X509EncodedKeySpec]
           [java.security.spec PKCS8EncodedKeySpec]
           [javax.crypto.spec OAEPParameterSpec]
           [java.security.spec MGF1ParameterSpec]
           [javax.crypto.spec PSource]))

(defn rsa-generate-keypair
  [^long bits]
  (go-try
   (when-not (or (= bits 2048)
                 (= bits 3072)
                 (= bits 4092))
     (throw (Exception. "RSA key size must be one of 2048, 3072, or 4096")))
   (let [generator (KeyPairGenerator/getInstance "RSA")]
     (.initialize generator bits)
     (let [keypair (.generateKeyPair generator)
           pubkey (.getPublic keypair)
           privkey (.getPrivate keypair)]
       {:public (.getEncoded pubkey)
        :private (.getEncoded privkey)}))))

(defn rsa-encrypt
  [^bytes plaintext
   ^bytes public-key]
  (go-try
   (let [key-factory (KeyFactory/getInstance "RSA")
         public-key (.generatePublic key-factory (X509EncodedKeySpec. public-key))
         cipher-instance (Cipher/getInstance "RSA/ECB/OAEPPadding")
         oaep-params (OAEPParameterSpec. "SHA-256"
                                         "MGF1"
                                         (MGF1ParameterSpec. "SHA-256")
                                         javax.crypto.spec.PSource$PSpecified/DEFAULT)]
     (.init cipher-instance Cipher/ENCRYPT_MODE public-key oaep-params)
     (.doFinal cipher-instance plaintext))))

(defn rsa-decrypt
  [^bytes ciphertext
   ^bytes private-key]
  (go-try
   (let [key-factory (KeyFactory/getInstance "RSA")
         private-key (.generatePrivate key-factory (PKCS8EncodedKeySpec. private-key))
         cipher-instance (Cipher/getInstance "RSA/ECB/OAEPPadding")
         oaep-params (OAEPParameterSpec. "SHA-256"
                                         "MGF1"
                                         (MGF1ParameterSpec. "SHA-256")
                                         javax.crypto.spec.PSource$PSpecified/DEFAULT)]
     (.init cipher-instance Cipher/DECRYPT_MODE private-key oaep-params)
     (.doFinal cipher-instance ciphertext))))
