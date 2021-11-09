(ns uniformity.internals.java.hash
  ;; (:require [clojure.core.async :refer [go]]
  ;;           [async-error.core :refer [go-try <?]])
  (:import [java.security MessageDigest]))

(defn ^:private java-hash [bytes type]
   (let [hasher (MessageDigest/getInstance type)]
     (.update hasher bytes)
     (.digest hasher)))

(defn md5 [^bytes bytes]
  (java-hash bytes "MD5"))

(defn sha1 [^bytes bytes]
  (java-hash bytes "SHA-1"))

(defn sha256 [^bytes bytes]
  (java-hash bytes "SHA-256"))

(defn sha384 [^bytes bytes]
  (java-hash bytes "SHA-384"))

(defn sha512 [^bytes bytes]
  (java-hash bytes "SHA-512"))

(comment
  (-> [1 2 3 4]
      byte-array
      md5
      uniformity.internals.java.util/hex-encode))