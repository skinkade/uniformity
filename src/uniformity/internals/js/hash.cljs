(ns uniformity.internals.js.hash
  (:require [goog.crypt.Md5]
            [goog.crypt.Sha1]
            [goog.crypt.Sha256]
            [goog.crypt.Sha384]
            [goog.crypt.Sha512]))

(defn md5 [bytes]
  (let [hasher (goog.crypt.Md5.)]
    (.update hasher bytes)
    (js/Uint8Array. (.digest hasher))))

(defn sha1 [bytes]
  (let [hasher (goog.crypt.Sha1.)]
    (.update hasher bytes)
    (js/Uint8Array. (.digest hasher))))

(defn sha256 [bytes]
  (let [hasher (goog.crypt.Sha256.)]
    (.update hasher bytes)
    (js/Uint8Array. (.digest hasher))))

(defn sha384 [bytes]
  (let [hasher (goog.crypt.Sha384.)]
    (.update hasher bytes)
    (js/Uint8Array. (.digest hasher))))

(defn sha512 [bytes]
  (let [hasher (goog.crypt.Sha512.)]
    (.update hasher bytes)
    (js/Uint8Array. (.digest hasher))))
