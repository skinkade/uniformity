(ns uniformity.internals.crypto.processing
  (:require [uniformity.internals.validation :refer [compat-bytes?
                                                     compat-byte-array
                                                     compat-count]]
            [uniformity.random :refer [rand-bytes]]
            [uniformity.util :as util]
            #?(:clj [uniformity.internals.crypto.algo-java :as algo]
               :cljs [uniformity.internals.crypto.algo-js :as algo])))

(defn throw-ex [ex]
  #?(:clj (throw (Exception. ex))
     :cljs (throw (js/Error. ex))))

(defonce gcm-key-length 128)
(defonce gcm-nonce-length 96)

(defonce cryptopack-compact-fields {;; Top level
                                    "c" :cipher
                                    "aes-gcm" :aes-gcm
                                    "n" :nonce
                                    "ks" :key-slots
                                    "ct" :ciphertext
                                    "fl" :flags
                                    ;; Slots
                                    "kg" :key-guid ; future feature
                                    "kt" :key-type
                                    "p" :password
                                    "b" :binary
                                    "ek" :encrypted-key
                                    "kp" :kdf-params
                                    ;; KDF params
                                    "fn" :kdf
                                    "pb2hs256" :pbkdf2-hmac-sha256
                                    "it" :iterations
                                    "sa" :salt
                                    ;; Flags
                                    "pad" :padded
                                    "str" :string})

(defn ^:private reverse-basic-map [m]
  (reduce-kv (fn [acc k v] (assoc acc v k)) {} m))

(defonce ^:private cryptopack-fields
  (reverse-basic-map cryptopack-compact-fields))

(defn ^:private cryptopack-compact-swap [c target-keys]
  (cond
    (map? c) (reduce-kv
              (fn [acc k v]
                (assoc acc
                       (cryptopack-compact-swap k target-keys)
                       (cryptopack-compact-swap v target-keys)))
              {} c)
    (coll? c) (mapv #(cryptopack-compact-swap % target-keys) c)
    (compat-bytes? c) (str "b64:" (util/base64-encode-urlsafe c))
    (and (string? c)
         (> (compat-count c) 4)
         (= "b64:" (subs c 0 4))) (util/base64-decode (subs c 4))
    (or (string? c) (keyword? c)) (if
                                   (contains? target-keys c)
                                    (get target-keys c)
                                    c)
    :else c))

(defn pkcs7-pad-bytes
  [bytes boundary]
  (let [bytes (vec bytes)
        len (count bytes)
        needed (- boundary (mod len boundary))
        needed (if (neg? needed)
                 (- needed)
                 needed)]
    (compat-byte-array
     (concat
      bytes
      (repeat needed needed)))))

(defn pksc7-unpad-bytes
  [bytes boundary]
  (let [bytes (vec bytes)
        len (count bytes)
        pad (nth bytes (dec len))]
    (when (not= 0 (mod len boundary))
      (throw-ex "Byte array does not align to padding"))
    (when (> pad boundary)
      (throw-ex "Padding exceeds boundary"))
    (let [padding (take-last pad bytes)
          new-len (- len pad)]
      (when
       (not (every? #(= pad %) padding))
        (throw-ex "Padding bytes do not all match"))
      (compat-byte-array
       (take new-len bytes)))))

(defn cryptopack->json [cryptopack]
  (as-> cryptopack c
    (cryptopack-compact-swap c cryptopack-fields)
    (util/json-encode c)
    (subs c 1 (dec (compat-count c))))) ; bug: data.json wraps in an array

(defn json->cryptopack [json]
  (-> json
      (util/json-decode)
      (cryptopack-compact-swap cryptopack-compact-fields)))

(defn key-from-password
  ([password] (key-from-password password
                                 100000
                                 (rand-bytes 16)))
  ([password iterations salt]
   (let [key (algo/pbkdf2-hmac-sha256 password
                                      salt
                                      iterations
                                      gcm-key-length)]
     {:key-type :password
      :key key
      :kdf-params {:kdf :pbkdf2-hmac-sha256
                   :iterations iterations
                   :salt salt}})))

(defn key-from-binary [key]
  {:key-type :binary
   :key key})

(defn key-from-value [val]
  (cond (string? val) (key-from-password val)
        (compat-bytes? val) (key-from-binary val)
        :else (throw-ex (str "Unrecognized data type for key: "
                             (type val)
                             " "
                             val))))

(defn encrypt-dek [dek keypack]
  (let [kek (:key keypack)
        key-type (:key-type keypack)
        nonce (rand-bytes (/ gcm-nonce-length 8))
        key-slot {:cipher :aes-gcm
                  :nonce nonce
                  :key-type key-type
                  :encrypted-key (algo/aes-gcm-encrypt dek
                                                       kek
                                                       nonce)}]
    (case key-type
      :binary key-slot
      :password (assoc key-slot
                       :kdf-params
                       (:kdf-params keypack)))))

(defn decrypt-dek-with-key
  [key slot]
  (compat-byte-array
   (algo/aes-gcm-decrypt
    (:encrypted-key slot)
    key
    (:nonce slot))))

(defn decrypt-dek-with-password
  [password slot]
  (if (= :password (:key-type slot))
    (let [kdf-params (:kdf-params slot)
          iterations (:iterations kdf-params)
          salt (:salt kdf-params)
          key (:key (key-from-password password iterations salt))]
      (decrypt-dek-with-key key slot))
    nil))

(defn decrypt-dek
  [key-or-password slot]
  {:pre [(or
          (string? key-or-password)
          (compat-bytes? key-or-password))]}
  (try
    (if (string? key-or-password)
      (decrypt-dek-with-password key-or-password slot)
      (decrypt-dek-with-key key-or-password slot))
    (catch #?(:cljs js/Error
              :default Exception) _ nil)))

(defn find-valid-key-slot
  [key slots]
  (let [attempts (map #(decrypt-dek key %) slots)
        successes (filter compat-bytes? attempts)
        valid-key (first successes)]
    (if (nil? valid-key)
      (throw-ex "Could not find valid key within slots")
      valid-key)))
