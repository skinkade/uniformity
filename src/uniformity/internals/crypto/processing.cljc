(ns uniformity.internals.crypto.processing
  (:require [uniformity.internals.validation :refer [compat-bytes?
                                                     compat-byte-array
                                                     compat-count]]
            [uniformity.random :refer [rand-bytes]]
            [uniformity.util :as util]
            [uniformity.crypto.core :as crypto]
            #?(:clj  [clojure.core.async :refer [go]]
               :cljs [cljs.core.async] :refer-macros [go])
            #?(:clj  [async-error.core :refer [go-try <?]]
               :cljs [async-error.core :refer-macros [go-try <?]])))

(defn throw-ex [ex]
  #?(:clj (throw (Exception. ex))
     :cljs (throw (js/Error. ex))))

;; (defonce gcm-key-length 128)
;; (defonce gcm-nonce-length 96)

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
  [bytes]
  (let [bytes (vec bytes)
        len (count bytes)
        pad (nth bytes (dec len))
        padding (take-last pad bytes)
        new-len (- len pad)]
    (when
     (not (every? #(= pad %) padding))
      (throw-ex "Padding bytes do not all match"))
    (compat-byte-array
     (take new-len bytes))))

(defn cryptopack->json [cryptopack]
  (as-> cryptopack c
    (cryptopack-compact-swap c cryptopack-fields)
    (base64-bytes-swap c)
    (util/json-encode c)
    (subs c 1 (dec (compat-count c))))) ; bug: data.json wraps in an array

(defn json->cryptopack [json]
  (-> json
      (util/json-decode)
      (base64-bytes-swap)
      (cryptopack-compact-swap cryptopack-compact-fields)))

(defn cryptopack->msgpack [cryptopack]
  (-> cryptopack
      (cryptopack-compact-swap cryptopack-fields)
      util/msgpack-serialize))

(defn msgpack->cryptopack [msgpack]
  (-> msgpack
      util/msgpack-deserialize
      (cryptopack-compact-swap cryptopack-compact-fields)))

(defn key-from-password
  [password & {:keys [params]}]
  (go-try
   (let [key-info (if (nil? params)
                    (<? (crypto/pbkdf2 password))
                    (<? (crypto/pbkdf2 password
                                       :salt (:salt params)
                                       :iterations (:iterations params)
                                       :hash (:hash params)
                                       :key-length (:key-length params))))]
     {:key-type :password
      :key (:key key-info)
      :kdf-params (-> key-info
                      (dissoc :key)
                      (assoc :kdf :pbkdf2))})))

(defn key-from-binary [key]
  {:key-type :binary
   :key key})

(defn key-from-rsa [key rsa-key-type]
  {:key-type :rsa
   :rsa-key-type rsa-key-type
   :key key})

(defn encrypt-dek [dek keypack]
  (go-try
   (case (:key-type keypack)
     :rsa {:cipher :rsa-oaep
           :key-type :rsa
           :encrypted-key (<? (crypto/rsa-encrypt dek (:key keypack)))}
     :binary (-> (<? (crypto/aes-gcm-encrypt dek (:key keypack)))
                 (assoc :cipher :aes-gcm)
                 (assoc :key-type :binary)
                 (clojure.set/rename-keys {:ciphertext :encrypted-key}))
     :password (-> (<? (crypto/aes-gcm-encrypt dek (:key keypack)))
                   (assoc :cipher :aes-gcm)
                   (assoc :key-type :password)
                   (assoc :kdf-params (:kdf-params keypack))
                   (clojure.set/rename-keys {:ciphertext :encrypted-key})))))

(defn decrypt-dek-with-bin-key
  [key slot]
  (go-try
   (if (= :aes-gcm (:cipher slot))
     (compat-byte-array
      (<? (crypto/aes-gcm-decrypt
           (:encrypted-key slot)
           key
           (:nonce slot))))
     nil)))

(defn decrypt-dek-with-password
  [password slot]
  (go-try
   (if (some? (:kdf-params slot))
     (let [kdf-params (:kdf-params slot)
           key (:key (<? (key-from-password password :params kdf-params)))]
       (<? (decrypt-dek-with-bin-key key slot)))
     nil)))

(defn decrypt-dek-with-rsa-key
  [privkey slot]
  (if (= :rsa-oaep (:cipher slot))
    (crypto/rsa-decrypt (:encrypted-key slot)
                        privkey)
    nil))

(defn find-valid-decrypt-key
  [slots aes-key password rsa-privkey]
  (go-try
   (let [key-type (cond (some? aes-key) :binary
                        (some? password) :password
                        (some? rsa-privkey) :rsa
                        :else (throw (ex-info "No valid key provided"
                                              {:cause "find-valid-decrypt-key requires either aes-key, password, or rsa-privkey to be non-nil"})))
         decrypt-fn (case key-type
                      :binary (partial decrypt-dek-with-bin-key aes-key)
                      :password (partial decrypt-dek-with-password password)
                      :rsa (partial decrypt-dek-with-rsa-key rsa-privkey))
         ;; hack to get around async limitations
         attempts (loop [i 0
                         acc []]
                    (if (= i (count slots))
                      acc
                      (let [slot (nth slots i)
                            decrypted (try (<? (decrypt-fn slot))
                                           (catch #?(:cljs js/Error
                                                     :default Exception) _ nil))]
                        (recur (inc i)
                               (conj acc decrypted)))))
         successes (filter some? attempts)
         valid-key (first successes)]
     (if (nil? valid-key)
       (throw-ex "Could not find valid key within slots")
       valid-key))))
