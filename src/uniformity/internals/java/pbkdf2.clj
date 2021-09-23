(ns uniformity.internals.java.pbkdf2
  (:require [clojure.core.async :refer [go]]
            [async-error.core :refer [go-try <?]])
  (:import [javax.crypto SecretKeyFactory]
           [javax.crypto.spec PBEKeySpec]))

(def hash-lookup {:sha1   "SHA1"
                  :sha256 "SHA256"
                  :sha384 "SHA384"
                  :sha512 "SHA512"})

(defn pbkdf2
  [password
   salt
   iterations
   hash
   key-length]
  (go-try
   (when-not (or (= hash :sha1)
                 (= hash :sha256)
                 (= hash :sha384)
                 (= hash :sha512))
     (throw (Exception. "PBKDF2 salt must be one of :sha1, :sha256, :sha384, or :sha512")))
   (let [hash (get hash-lookup hash)
         algo (str "PBKDF2WithHmac" hash)
         pw-chars (.toCharArray password)
         kdf (SecretKeyFactory/getInstance algo)
         key-spec (PBEKeySpec. pw-chars salt iterations key-length)
         secret-key (.generateSecret kdf key-spec)]
     (.getEncoded secret-key))))