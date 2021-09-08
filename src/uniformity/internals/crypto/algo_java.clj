(ns uniformity.internals.crypto.algo-java
  (:import [javax.crypto Cipher]
           [javax.crypto SecretKeyFactory]
           [javax.crypto.spec SecretKeySpec]
           [javax.crypto.spec PBEKeySpec]
           [javax.crypto.spec GCMParameterSpec]))

(defn pbkdf2-hmac-sha256
  [password salt iterations key-length]
  (let [pw-chars (.toCharArray password)
        kdf (SecretKeyFactory/getInstance "PBKDF2WithHmacSHA256")
        key-spec (PBEKeySpec. pw-chars salt iterations key-length)
        secret-key (.generateSecret kdf key-spec)]
    (.getEncoded secret-key)))

(defonce ^:private gcm-tag-length 128)
(defonce ^:private gcm-nonce-length (/ 96 8))

(defn aes-gcm-encrypt
  ^bytes
  [^bytes plaintext
   ^bytes key
   ^bytes nonce
   & {:keys [^bytes aad] :or {aad nil}}]
  {:pre [(contains? #{16 24 32} (count key))
         (= gcm-nonce-length (count nonce))]}
  (let [key-spec (SecretKeySpec. key "AES")
        gcm-spec (GCMParameterSpec. gcm-tag-length nonce)
        cipher-instance (Cipher/getInstance "AES/GCM/NoPadding")]
    (.init cipher-instance Cipher/ENCRYPT_MODE key-spec gcm-spec)
    (when (not (nil? aad))
      (.updateAAD cipher-instance aad))
    (.doFinal cipher-instance plaintext)))

(defn aes-gcm-decrypt
  ^bytes
  [^bytes ciphertext
   ^bytes key
   ^bytes nonce
   & {:keys [^bytes aad] :or {aad nil}}]
  {:pre [(contains? #{16 24 32} (count key))
         (= gcm-nonce-length (count nonce))]}
  (let [key-spec (SecretKeySpec. key "AES")
        gcm-spec (GCMParameterSpec. gcm-tag-length nonce)
        cipher-instance (Cipher/getInstance "AES/GCM/NoPadding")]
    (.init cipher-instance Cipher/DECRYPT_MODE key-spec gcm-spec)
    (when (not (nil? aad))
      (.updateAAD cipher-instance aad))
    (.doFinal cipher-instance ciphertext)))
