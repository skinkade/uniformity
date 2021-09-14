(ns uniformity.crypto
  (:require [uniformity.random :refer [rand-bytes]]
            [uniformity.util :as util]
            [uniformity.internals.validation :refer [compat-bytes?
                                                     compat-byte-array
                                                     compat-count]]
            [uniformity.internals.crypto.processing :as proc]
            #?(:clj [uniformity.internals.crypto.algo-java :as algo]
               :cljs [uniformity.internals.crypto.algo-js :as algo])))

(defonce ^:private padding-boundary 16)

(defn aes-gcm-encrypt
  " Encrypts plaintext using AES in GCM with key + nonce.
   Key must be 128, 192, or 256 bits long.
   Nonce must be 96 bits long.
   Authentication tag appended to ciphertext is 128 bits."
  [plaintext key nonce]
  {:pre [(compat-bytes? plaintext)
         (compat-bytes? key)
         (contains? #{16 24 32} (compat-count key))
         (compat-bytes? nonce)
         ;; Other nonce sizes technically valid but NIST strongly recommends
         ;; 96 bits, and most implementations use it
         (= 12 (compat-count nonce))]}
  (algo/aes-gcm-encrypt plaintext key nonce))

(defn aes-gcm-decrypt
  [plaintext key nonce]
  {:pre [(compat-bytes? plaintext)
         (compat-bytes? key)
         (contains? #{16 24 32} (compat-count key))
         (compat-bytes? nonce)
         (= 12 (compat-count nonce))]}
  (algo/aes-gcm-decrypt plaintext key nonce))

(defn encrypt
  " Encrypts plaintext with a random data encryption key.
   DEK is protected with each of the provided key encryption keys
   and stored in slots in the output.

   `plaintext` parameter may be either a byte array, or a string,
   which will be treated as UTF-8 bytes.
   `keys` parameter may be either a string password or byte array key, and may
   either be a scalar or a collection.
   
   Defaults to returning a self-describing map containing metadata
   and the ciphertext.
   
   Add `:json` to return a JSON string with compact field names.
   Add `:msgpack` to return a msgpack byte array with compact field names.
   Add `:padded` to PKCS#7-pad plaintext to nearest 16 bytes to hide
   exact plaintext length."
  [plaintext
   keys
   & flags]
  {:pre [(or (string? plaintext)
             (compat-bytes? plaintext))
         (or (string? keys)
             (compat-bytes? keys)
             (and (coll? keys)
                  (every? #(or
                            (string? %)
                            (compat-bytes? %)) keys)))]}
  (let [flags (set (flatten flags))
        padded (:padded flags)
        json (:json flags)
        msgpack (:msgpack flags)
        from-str (string? plaintext)
        plaintext (if from-str
                    (util/str->utf8 plaintext)
                    plaintext)
        plaintext (if padded
                    (proc/pkcs7-pad-bytes plaintext padding-boundary)
                    plaintext)
        keys (if (coll? keys)
               keys
               [keys])
        keys (mapv proc/key-from-value keys)
        dek (rand-bytes (/ proc/gcm-key-length 8))
        nonce (rand-bytes (/ proc/gcm-nonce-length 8))
        slots (mapv #(proc/encrypt-dek dek %) keys)
        ciphertext (aes-gcm-encrypt plaintext dek nonce)
        cryptopack {:cipher :aes-gcm
                    :nonce nonce
                    :key-slots slots
                    :ciphertext ciphertext}
        pack-flags (reduce conj #{}
                           (filter (complement nil?)
                                   [(when padded :padded)
                                    (when from-str :string)]))
        cryptopack (if (empty? pack-flags)
                     cryptopack
                     (assoc cryptopack :flags pack-flags))]
    (when (and json msgpack)
      (throw (ex-info ":json and :msgpack cannot be used together"
                      {:bad-flags-args flags})))
    (cond json (proc/cryptopack->json cryptopack)
          msgpack (proc/cryptopack->msgpack cryptopack)
          :default cryptopack)))

(defn decrypt
  " Decrypt ciphertext using one of the provided keys.
   
   `ciphertext` parameter may be either a cryptopack map, or a JSON-encoded
   compact cryptopack.
   
   `keys` parameter may be either a string password or byte array key, and may
   either be a scalar or a collection."
  [ciphertext key]
  {:pre [(or
          (string? ciphertext)
          (map? ciphertext)
          (compat-bytes? ciphertext))
         (or
          (string? key)
          (compat-bytes? key))]}
  (let [cryptopack (cond (string? ciphertext) (proc/json->cryptopack ciphertext)
                         (compat-bytes? ciphertext) (proc/msgpack->cryptopack ciphertext)
                         :default ciphertext)
        flags (if (contains? cryptopack :flags)
                (set (:flags cryptopack))
                #{})
        valid-key (proc/find-valid-key-slot key
                                            (:key-slots cryptopack))
        plaintext (aes-gcm-decrypt
                   (:ciphertext cryptopack)
                   valid-key
                   (:nonce cryptopack))
        plaintext (if (:padded flags)
                    (proc/pksc7-unpad-bytes plaintext padding-boundary)
                    plaintext)
        plaintext (if (:string flags)
                    (util/utf8->str plaintext)
                    plaintext)]
    plaintext))
