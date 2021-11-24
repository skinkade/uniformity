(ns uniformity.internals.cryptopack.processing
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
      (throw (ex-info "Padding bytes do not all match"
                      {:pad pad
                       :padding padding})))
    (compat-byte-array
     (take new-len bytes))))

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
       (throw (ex-info "Could not find valid key within slots"
                       {}))
       valid-key))))
