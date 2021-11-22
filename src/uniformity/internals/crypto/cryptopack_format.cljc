(ns uniformity.internals.crypto.cryptopack-format
  (:require [clojure.spec.alpha :as s]
            [uniformity.internals.validation :refer [compat-bytes?
                                                     compat-byte-array
                                                     compat-count]]))

(def gcm-nonce-length (/ 96 8))
(s/def :cryptopack/nonce
  (s/and
   compat-bytes?
   #(= (compat-count %) gcm-nonce-length)))

;; ciphertext will have at least the 128-bit tag
(def gcm-tag-length (/ 128 8))
(s/def :cryptopack/ciphertext
  (s/and
   compat-bytes?
   #(>= (compat-count %) gcm-tag-length)))

(s/def :cryptopack/cipher
  #{:aes-gcm :rsa-oaep})

(s/def :cryptopack/encrypted-key compat-bytes?)

(s/def :cryptopack/key-type
  #{:binary :password :rsa})

(def min-salt-length (/ 128 8))
(s/def :cryptopack/salt
  (s/and
   compat-bytes?
   #(>= (compat-count %) min-salt-length)))

(s/def :cryptopack/iterations int?)

(s/def :cryptopack/hash
  #{:sha256})

(s/def :cryptopack/key-length
  (s/and
   int?
   #(= 0 (mod % 8))))

(s/def :cryptopack/kdf
  #{:pbkdf2})

(s/def :cryptopack/kdf-params
  (s/keys :req-un [:cryptopack/salt
                   :cryptopack/iterations
                   :cryptopack/hash
                   :cryptopack/key-length
                   :cryptopack/kdf]))

(s/def :cryptopack/key-slot-rsa
  (s/keys :req-un [:cryptopack/key-type
                   :cryptopack/encrypted-key]))

(s/def :cryptopack/key-slot-binary
  (s/keys :req-un [:cryptopack/key-type
                   :cryptopack/encrypted-key
                   :cryptopack/nonce
                   :cryptopack/cipher]))

(s/def :cryptopack/key-slot-password
  (s/keys :req-un [:cryptopack/key-type
                   :cryptopack/encrypted-key
                   :cryptopack/nonce
                   :cryptopack/cipher
                   :cryptopack/kdf-params]))

(defn valid-key-slot? [slot]
  (s/and
   (map? slot)
   (contains? slot :key-type)
   (condp = (:key-type slot)
     :binary (s/valid? :cryptopack/key-slot-binary slot)
     :password (s/valid? :cryptopack/key-slot-password slot)
     :rsa (s/valid? :cryptopack/key-slot-rsa slot)
     ;; default
     false)))

(s/def :cryptopack/key-slots
  (s/coll-of valid-key-slot?
             :kind vector?
             :min-count 1))

(s/def :cryptopack/format
  (s/keys :req-un [:cryptopack/nonce
                   :cryptopack/ciphertext
                   :cryptopack/cipher
                   :cryptopack/key-slots]))
