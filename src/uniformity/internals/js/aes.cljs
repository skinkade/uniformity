(ns uniformity.internals.js.aes
  (:require [uniformity.internals.js.node-browser-compat :refer [crypto-type crypto]]
            [cljs.core.async :as async]
            [cljs.core.async.interop :refer [p->c]]
            [async-error.core :refer-macros [go-try <?]]))

(defn node-aes-gcm-encrypt
  [^js/Uint8Array plaintext
   ^js/Uint8Array key
   ^js/Uint8Array nonce]
  (go-try
   (when-not (contains? #{16 24 32} (.-length key))
     (throw (js/Error. "AES key must be 128, 192, or 256 bits")))
   (when-not (= 12 (.-length nonce))
     (throw (js/Error. "AES-GCM nonce must be 96 bits")))
   (let [keysize (* 8 (.-length key))
         algo (str "aes-" keysize "-gcm")
         cipher (.createCipheriv crypto
                                 algo
                                 key
                                 nonce
                                 (clj->js {"authTagLength" 16}))
         ciphertext (.update cipher plaintext)]
     (.final cipher)
     (js/Uint8Array.
      (concat
       ciphertext
       (.getAuthTag cipher))))))

(defn node-aes-gcm-decrypt
  [^js/Uint8Array ciphertext
   ^js/Uint8Array key
   ^js/Uint8Array nonce]
  (go-try
   (when-not (contains? #{16 24 32} (.-length key))
     (throw (js/Error. "AES key must be 128, 192, or 256 bits")))
   (when-not (= 12 (.-length nonce))
     (throw (js/Error. "AES-GCM nonce must be 96 bits")))
   (let [keysize (* 8 (.-length key))
         algo (str "aes-" keysize "-gcm")
         cipher (.createDecipheriv ^Object crypto
                                   algo
                                   key
                                   nonce)
        ;; assume last 128 bits are auth tag
         ct-tag (split-at (- (.-length ciphertext) 16) ciphertext)
         ciphertext (js/Uint8Array. (nth ct-tag 0))
         tag (js/Uint8Array. (nth ct-tag 1))
         plaintext (.update cipher ciphertext)]
     (.setAuthTag cipher tag)
     (.final cipher)
     (js/Uint8Array. plaintext))))

(defn browser-aes-gcm-encrypt
  [^js/Uint8Array plaintext
   ^js/Uint8Array key
   ^js/Uint8Array nonce]
  ;; {:pre [(contains? #{16 24 32} (.-length key))
  ;;        (= 12 (.-length nonce))]}
  (let [algo-params (clj->js {"name" "AES-GCM"
                              "iv" nonce
                              "tagLength" 128})
        subtle (.-subtle crypto)]
    (-> (.importKey subtle
                    "raw"
                    key
                    "AES-GCM"
                    false
                    ["encrypt"])
        (.then (fn [cryptokey] (.encrypt ^Object subtle
                                         algo-params
                                         cryptokey
                                         plaintext)))
        (.then (fn [ciphertext] (js/Uint8Array. ciphertext)))
        p->c)))

(defn browser-aes-gcm-decrypt
  [^js/Uint8Array ciphertext
   ^js/Uint8Array key
   ^js/Uint8Array nonce]
  ;; {:pre [(contains? #{16 24 32} (.-length key))
  ;;        (= 12 (.-length nonce))]}
  (let [algo-params (clj->js {"name" "AES-GCM"
                              "iv" nonce
                              "tagLength" 128})
        subtle (.-subtle crypto)]
    (-> (.importKey subtle
                    "raw"
                    key
                    "AES-GCM"
                    false
                    ["decrypt"])
        (.then (fn [cryptokey] (.decrypt ^Object subtle
                                         algo-params
                                         cryptokey
                                         ciphertext)))
        (.then (fn [plaintext] (js/Uint8Array. plaintext)))
        p->c)))

(def aes-gcm-encrypt
  (if (= :browser crypto-type)
    browser-aes-gcm-encrypt
    node-aes-gcm-encrypt))

(def aes-gcm-decrypt
  (if (= :browser crypto-type)
    browser-aes-gcm-decrypt
    node-aes-gcm-decrypt))
