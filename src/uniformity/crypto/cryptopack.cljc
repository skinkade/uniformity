(ns uniformity.crypto.cryptopack
  (:require [uniformity.random :refer [rand-bytes]]
            [uniformity.util :as util]
            [uniformity.crypto.core :as core]
            [uniformity.internals.cryptopack.processing :as proc]
            [uniformity.internals.cryptopack.format :as fmt]
            [uniformity.internals.validation :refer [compat-bytes?
                                                     compat-byte-array
                                                     compat-count]]
            #?(:clj  [clojure.core.async :refer [go]]
               :cljs [cljs.core.async] :refer-macros [go])
            #?(:clj  [async-error.core :refer [go-try <?]]
               :cljs [async-error.core :refer-macros [go-try <?]])))

(defn ^:private parse-key-args [aes-key password rsa-pubkey]
  (go-try
   (let [;; these ugly loops are here becaue async makes `map` calls buggy
         aes-keys (cond (nil? aes-key) nil
                        (vector? aes-key)  (loop [i 0
                                                  acc []]
                                             (if (= i (count aes-key))
                                               acc
                                               (let [key (nth aes-key i)
                                                     key (proc/key-from-binary key)]
                                                 (recur (inc i)
                                                        (conj acc key)))))
                        :else (proc/key-from-binary aes-key))
         password-keys (cond (nil? password) nil
                             (vector? password) (loop [i 0
                                                       acc []]
                                                  (if (= i (count password))
                                                    acc
                                                    (let [key (nth password i)
                                                          key (<? (proc/key-from-password key))]
                                                      (recur (inc i)
                                                             (conj acc key)))))
                             :else (<? (proc/key-from-password password)))
         rsa-keys (cond (nil? rsa-pubkey) nil
                        (vector? rsa-pubkey) (loop [i 0
                                                    acc []]
                                               (if (= i (count rsa-pubkey))
                                                 acc
                                                 (let [key (nth rsa-pubkey i)
                                                       key (proc/key-from-rsa key :public)]
                                                   (recur (inc i)
                                                          (conj acc key)))))
                        :else (proc/key-from-rsa rsa-pubkey :public))
         keys (->> [aes-keys password-keys rsa-keys]
                   flatten
                   (filter some?))]
     (when (empty? keys)
       (throw (ex-info "No valid keys provided"
                       {:aes-key aes-key
                        :password password
                        rsa-pubkey rsa-pubkey})))
     keys)))

(defn encrypt
  "Encrypts plaintext with a random data encryption key.
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

  (def password \"A strong password\")
  (encrypt \"Attack at dawn\" :password password)

  Advanced example:

  (def backup-key (rand-bytes 16))
  (encrypt \"hello world\"
           :password [\"foo\" \"bar\"]
           :aes-key backup-key
           :output :msgpack
           :padding 16)"
  [plaintext
   & {:keys [aes-key password rsa-pubkey output padding enc-key-size]
      :or {output :map, padding nil, enc-key-size 128}}]
  (go-try
   (let [keys (<? (parse-key-args aes-key password rsa-pubkey))
         plaintext (if (string? plaintext)
                     (util/str->utf8 plaintext)
                     plaintext)
         plaintext (if padding
                     (proc/pkcs7-pad-bytes plaintext padding)
                     plaintext)
         dek (rand-bytes (/ enc-key-size 8))
         ;; hack to get around async limitations
         slots (loop [i 0
                      acc []]
                 (if (= i (count keys))
                   acc
                   (let [key (nth keys i)
                         encrypted (<? (proc/encrypt-dek dek key))]
                     (recur (inc i)
                            (conj acc encrypted)))))
         ciphertext (<? (core/aes-gcm-encrypt plaintext dek))
         cryptopack (-> ciphertext
                        (assoc :cipher :aes-gcm)
                        (assoc :key-slots slots))
         pack-flags (if padding
                      #{:padded}
                      #{})
         cryptopack (if (empty? pack-flags)
                      cryptopack
                      (assoc cryptopack :flags pack-flags))]
     (cond (= :json output) (fmt/cryptopack->json cryptopack)
           (= :msgpack output) (fmt/cryptopack->msgpack cryptopack)
           (= :map output) cryptopack
           :else (throw (ex-info "Invalid output type specified"
                                 {:output output}))))))

(defn decrypt
  "Decrypt ciphertext using one of the provided keys.

  `ciphertext` parameter is a cryptopack in the form of either:
  - a map
  - a string (compacted and JSON-encoded)
  - a byte array (compacted and messagepack-encoded)

  Decryption key must be supplied as one of:
  :aes-key some-byte-array
  :password some-string
  :rsa-privkey some-pkcs8-byte-array"
  [ciphertext
   & {:keys [aes-key password rsa-privkey output]
      :or {output :bytes}}]
  (go-try
   (let [cryptopack (fmt/derive-cryptopack ciphertext)
         flags (if (contains? cryptopack :flags)
                 (set (:flags cryptopack))
                 #{})
         valid-key (<? (proc/find-valid-decrypt-key (:key-slots cryptopack)
                                                    aes-key password rsa-privkey))
         plaintext (<? (core/aes-gcm-decrypt
                        (:ciphertext cryptopack)
                        valid-key
                        (:nonce cryptopack)))
         plaintext (if (:padded flags)
                     (proc/pksc7-unpad-bytes plaintext)
                     plaintext)
         output (if (nil? output)
                  :bytes
                  output)]
     (cond (= output :string) (util/utf8->str plaintext)
           (= output :bytes) plaintext
           :else (throw (ex-info "Unrecognized output type"
                                 {:output output}))))))
