(ns uniformity.internals.util-java
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
