(ns uniformity.internals.util-java
  (:require [clojure.data.json :as json])
  (:import [org.apache.commons.codec.binary Base64 Hex]))

(defn base64-encode [bytes]
  (Base64/encodeBase64String bytes))

(defn base64-encode-urlsafe [bytes]
  (Base64/encodeBase64URLSafeString bytes))

(defn base64-decode [string]
  (Base64/decodeBase64 string))

(defn hex-encode [bytes]
  (Hex/encodeHexString bytes))

(defn hex-decode [string]
  (Hex/decodeHex ^String string))

(defn json-encode [object]
  (json/write-str object))

(defn json-decode [string]
  (json/read-str string))

(defn str->utf8 [string]
  (.getBytes string "UTF8"))

(defn utf8->str [bytes]
  (String. bytes "UTF8"))
