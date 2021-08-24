(ns uniformity.util
  (:require #?(:clj [uniformity.internals.util-java :as internals]
               :cljs [uniformity.internals.util-js :as internals])))

(defn base64-encode [bytes]
  (internals/base64-encode bytes))

(defn base64-encode-urlsafe [bytes]
  (internals/base64-encode-urlsafe bytes))

(defn base64-decode [string]
  (internals/base64-decode string))

(defn hex-encode [bytes]
  (internals/hex-encode bytes))

(defn hex-decode [string]
  (internals/hex-decode string))
