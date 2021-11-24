(ns uniformity.internals.cryptopack.format
  (:require [clojure.spec.alpha :as s]
            [uniformity.internals.validation :refer [compat-bytes?
                                                     compat-byte-array
                                                     compat-count]]
            [uniformity.util :as util]))

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



;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;; Deriving from / validating input  ;;
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

(defonce cryptopack-compact-fields {;; Top level
                                    "c" :cipher
                                    "gcm" :aes-gcm
                                    "n" :nonce
                                    "ks" :key-slots
                                    "ct" :ciphertext
                                    "fl" :flags
                                    ;; Slots
                                    "kg" :key-guid ; future feature
                                    "kt" :key-type
                                    "p" :password
                                    "b" :binary
                                    "rsa" :rsa
                                    "oaep" :rsa-oaep
                                    "ek" :encrypted-key
                                    "kp" :kdf-params
                                    ;; KDF params
                                    "fn" :kdf
                                    "pb2" :pbkdf2
                                    "h" :hash
                                    "s1" :sha1
                                    "s256" :sha256
                                    "s384" :sha384
                                    "s512" :sha512
                                    "it" :iterations
                                    "sa" :salt
                                    "kl" :key-length
                                    ;; Flags
                                    "pd" :padded})

(defn ^:private reverse-basic-map [m]
  (reduce-kv (fn [acc k v] (assoc acc v k)) {} m))

(defonce ^:private cryptopack-fields
  (reverse-basic-map cryptopack-compact-fields))

(defn cryptopack-compact-swap [c target-keys]
  (cond
    (map? c) (reduce-kv
              (fn [acc k v]
                (assoc acc
                       (cryptopack-compact-swap k target-keys)
                       (cryptopack-compact-swap v target-keys)))
              {} c)
    (coll? c) (mapv #(cryptopack-compact-swap % target-keys) c)
    (or (string? c) (keyword? c)) (if
                                   (contains? target-keys c)
                                    (get target-keys c)
                                    c)
    :else c))

(defn base64-bytes-swap [obj]
  (cond (compat-bytes? obj)
        (str "b64:" (util/base64-encode-urlsafe obj))

        (and (string? obj)
             (> (count obj) 4)
             (= "b64:" (subs obj 0 4)))
        (util/base64-decode (subs obj 4))

        (map? obj)
        (reduce-kv (fn [acc k v] (assoc acc k (base64-bytes-swap v)))
                   {}
                   obj)

        (coll? obj)
        (mapv base64-bytes-swap obj)

        :else obj))

(defn validate-cryptopack [c]
  (when-not (s/valid? :cryptopack/format c)
    (throw (ex-info "Cryptopack failed to validate"
                    {:reason (s/explain :cryptopack/format c)})))
  c)

(defn cryptopack->json [cryptopack]
  (as-> cryptopack c
    (cryptopack-compact-swap c cryptopack-fields)
    (base64-bytes-swap c)
    (util/json-encode c)
    (subs c 1 (dec (compat-count c))))) ; bug: data.json wraps in an array

(defn json->cryptopack [json]
  (-> json
      util/json-decode
      base64-bytes-swap
      (cryptopack-compact-swap cryptopack-compact-fields)
      validate-cryptopack))

(defn cryptopack->msgpack [cryptopack]
  (-> cryptopack
      (cryptopack-compact-swap cryptopack-fields)
      util/msgpack-serialize))

(defn msgpack->cryptopack [msgpack]
  (-> msgpack
      util/msgpack-deserialize
      (cryptopack-compact-swap cryptopack-compact-fields)
      validate-cryptopack))

(defn derive-cryptopack [c]
  (cond (string? c) (json->cryptopack c)
        (compat-bytes? c) (msgpack->cryptopack c)
        (map? c) (validate-cryptopack c)
        :else
        (throw (ex-info "Could not parse cryptopack"
                        {:reason "Was not string, byte array, or map"}))))