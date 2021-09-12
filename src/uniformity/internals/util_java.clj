(ns uniformity.internals.util-java
  (:require [clojure.data.json :as json])
  (:import [org.apache.commons.codec.binary Base64 Hex]))

(defn base64-encode
  ^String [^bytes bytes]
  (Base64/encodeBase64String bytes))

(defn base64-encode-urlsafe
  ^String [^bytes bytes]
  (Base64/encodeBase64URLSafeString bytes))

(defn base64-decode
  ^bytes [^String string]
  (Base64/decodeBase64 string))

(defn hex-encode
  ^String [^bytes bytes]
  (Hex/encodeHexString bytes))

(defn hex-decode
  ^bytes [^String string]
  (Hex/decodeHex string))

(defn json-encode
  ^String [object]
  (json/write-str object))

(defn json-decode
  [^String string]
  (json/read-str string))

(defn str->utf8
  ^bytes [^String string]
  (.getBytes string "UTF8"))

(defn utf8->str
  ^String [^bytes bytes]
  (String. bytes "UTF8"))
