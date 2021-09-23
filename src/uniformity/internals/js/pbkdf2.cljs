(ns uniformity.internals.js.pbkdf2
  (:require [uniformity.internals.js.node-browser-compat :refer [crypto-type crypto]]
            [uniformity.internals.js.util :refer [str->utf8]]
            [cljs.core.async :as async]
            [cljs.core.async.interop :refer [p->c]]
            ;; [clojure.string :as string]
            [async-error.core :refer-macros [go-try <?]]))

(def browser-hash-lookup {:sha1   "SHA-1"
                          :sha256 "SHA-256"
                          :sha384 "SHA-384"
                          :sha512 "SHA-512"})

(def node-hash-lookup {:sha1   "SHA1"
                       :sha256 "SHA256"
                       :sha384 "SHA384"
                       :sha512 "SHA512"})

(defn browser-pbkdf2
  [^String password
   ^js/Uint8Array salt
   ^number iterations
   ^String hash
   ^number key-length]
  (go-try
   (when-not (or (= hash :sha1)
                 (= hash :sha256)
                 (= hash :sha384)
                 (= hash :sha512))
     (throw (js/Error. "PBKDF2 salt must be one of :sha1, :sha256, :sha384, or :sha512")))
   (let [c (async/chan)
         password (str->utf8 password)
         hash (get browser-hash-lookup hash)
         kdf-params (clj->js {"name" "PBKDF2"
                              "hash" (get browser-hash-lookup hash)
                              "salt" salt
                              "iterations" iterations})
         subtle (.-subtle crypto)]
     (-> (.importKey ^Object subtle
                     "raw"
                     password
                     #js {"name" "PBKDF2"}
                     true
                     ["deriveBits", "deriveKey"])
         (.then (fn [pass-key]
                  (.deriveBits subtle
                               kdf-params
                               pass-key
                               key-length)))
         (.then (fn [key] (js/Uint8Array. key)))
         (.then (fn [key] (async/put! c key))))
     (<? c))))

(defn node-pbkdf2
  [^String password
   ^js/Uint8Array salt
   ^number iterations
   ^String hash
   ^number key-length]
  (go-try
   (when-not (or (= hash :sha1)
                 (= hash :sha256)
                 (= hash :sha384)
                 (= hash :sha512))
     (throw (js/Error. "PBKDF2 salt must be one of :sha1, :sha256, :sha384, or :sha512")))
   (let [c (async/chan 1)
         password (str->utf8 password)
         hash (get node-hash-lookup hash)
         key-length (/ key-length 8)]
     (.pbkdf2 ^Object crypto
              password
              salt
              iterations
              key-length
              hash
              (fn [err key] (if (some? err)
                              (async/put! c err)
                              (async/put! c (js/Uint8Array. key)))))
     (<? c))))

(def pbkdf2
  (if (= :browser crypto-type)
    #'browser-pbkdf2
    #'node-pbkdf2))
