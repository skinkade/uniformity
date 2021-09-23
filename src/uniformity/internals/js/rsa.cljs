(ns uniformity.internals.js.rsa
  (:require [uniformity.internals.js.node-browser-compat :refer [crypto-type crypto]]
            [cljs.core.async :refer [go chan <! put!]]
            [cljs.core.async.interop :refer [p->c]]
            [async-error.core :refer-macros [go-try <?]]))

(def subtle (.-subtle crypto))

(defn browser-rsa-generate-keypair
  [^number bits]
  (go-try
   (when-not (or (= bits 2048)
                 (= bits 3072)
                 (= bits 4092))
     (throw (js/Error. "RSA key size must be one of 2048, 3072, or 4096")))
   (let [pub-chan (chan 1)
         priv-chan (chan 1)
         params (clj->js {"name" "RSA-OAEP"
                          "modulusLength" bits
                          "publicExponent" (js/Uint8Array. [0x01, 0x00, 0x01])
                          "hash" "SHA-256"})
         extractable true
         key-usages ["encrypt" "decrypt"]]
     (-> (.generateKey subtle
                       params
                       extractable
                       key-usages)
         (.then (fn [keypair]
                  ((-> (.exportKey ^Object subtle
                                   "spki"
                                   (.-publicKey keypair))
                       (.then (fn [key] (js/Uint8Array. key)))
                       (.then (fn [key] (put! pub-chan key))))
                   (-> (.exportKey subtle
                                   "pkcs8"
                                   (.-privateKey keypair))
                       (.then (fn [key] (js/Uint8Array. key)))
                       (.then (fn [key] (put! priv-chan key))))))))
     {:public (<? pub-chan)
      :private (<? priv-chan)})))

(defn browser-rsa-encrypt
  [^js/Uint8Array plaintext
   ^js/Uint8Array pubkey]
  (-> (.importKey subtle
                  "spki"
                  pubkey
                  (clj->js {"name" "RSA-OAEP"
                            "hash" "SHA-256"})
                  true
                  ["encrypt"])
      (.then (fn [cryptokey]
               (.encrypt ^Object subtle
                         (clj->js {"name" "RSA-OAEP"})
                         cryptokey
                         plaintext)))
      (.then (fn [ciphertext] (js/Uint8Array. ciphertext)))
      p->c))

(defn browser-rsa-decrypt
  [^js/Uint8Array ciphertext
   ^js/Uint8Array pubkey]
  (-> (.importKey subtle
                  "pkcs8"
                  pubkey
                  (clj->js {"name" "RSA-OAEP"
                            "hash" "SHA-256"})
                  true
                  ["decrypt"])
      (.then (fn [cryptokey]
               (.decrypt ^Object subtle
                         (clj->js {"name" "RSA-OAEP"})
                         cryptokey
                         ciphertext)))
      (.then (fn [plaintext] (js/Uint8Array. plaintext)))
      p->c))

(defn node-rsa-generate-keypair
  [^number bits]
  (go-try
   (when-not (or (= bits 2048)
                 (= bits 3072)
                 (= bits 4092))
     (throw (js/Error. "RSA key size must be one of 2048, 3072, or 4096")))
   (let [pubkey-chan (chan 1)
         privkey-chan (chan 1)
         err-chan (chan 1)]
     (.generateKeyPair ^Object crypto
                       "rsa"
                       (clj->js {"modulusLength" bits})
                       (fn [err pubkey privkey]
                         (if (some? err)
                           (put! err-chan err)
                           (do (put! err-chan false)
                               (->> (.export pubkey (clj->js {"type" "spki"
                                                              "format" "der"}))
                                    js/Uint8Array.
                                    (put! pubkey-chan))
                               (->> (.export privkey (clj->js {"type" "pkcs8"
                                                               "format" "der"}))
                                    js/Uint8Array.
                                    (put! privkey-chan))))))

     (<? err-chan)

     {:public (<? pubkey-chan)
      :private (<? privkey-chan)})))

(defn node-rsa-encrypt
  [^js/Uint8Array plaintext
   ^js/Uint8Array pubkey]
  (go-try
   (let [key-opts (clj->js {"key" pubkey
                            "format" "der"
                            "type" "spki"})
         crypto-pubkey (.createPublicKey ^Object crypto key-opts)
         rsa-opts (clj->js {"key" crypto-pubkey
                            "oaepHash" "sha256"})
         ciphertext (.publicEncrypt ^Object crypto rsa-opts plaintext)]
     (js/Uint8Array. ciphertext))))

(defn node-rsa-decrypt
  ^js/Uint8Array
  [^js/Uint8Array ciphertext
   ^js/Uint8Array privkey]
  (go-try
   (let [key-options (clj->js {"key" privkey
                               "format" "der"
                               "type" "pkcs8"})
         privkey (.createPrivateKey ^Object crypto key-options)
         rsa-opts (clj->js {"key" privkey
                            "oaepHash" "sha256"})]
     (js/Uint8Array. (.privateDecrypt ^Object crypto rsa-opts ciphertext)))))

(def rsa-generate-keypair
  (if (= :browser crypto-type)
    #'browser-rsa-generate-keypair
    #'node-rsa-generate-keypair))

(def rsa-encrypt
  (if (= :browser crypto-type)
    #'browser-rsa-encrypt
    #'node-rsa-encrypt))

(def rsa-decrypt
  (if (= :browser crypto-type)
    #'browser-rsa-decrypt
    #'node-rsa-decrypt))
