(ns uniformity.internals.js.util
    (:require [goog.crypt :refer [byteArrayToHex hexToByteArray]]
            [goog.crypt.base64 :as base64]
            [clojure.string :as string]
            ["msgpack5" :as msgpack5]
            [uniformity.internals.validation :refer [compat-count]]))

(defonce msgpack (msgpack5))

(defn base64-encode
  ^String [^js/Uint8Array bytes]
  (base64/encodeByteArray bytes))

(defn base64-encode-urlsafe
  ^String [^js/Uint8Array bytes]
  (-> bytes
      (base64-encode)
      (string/replace "+" "-")
      (string/replace "/" "_")
      (string/replace "=" "")))

(defn ^:private pad-base64 [string]
  (if (= 0 (mod (compat-count string) 4))
    string
    (let [padding-needed (- 4 (mod (compat-count string) 4))]
      (apply str string (repeat padding-needed "=")))))

(defn base64-decode
  ^js/Uint8Array [^String string]
  (let [string (-> string
                   (string/replace "-" "+")
                   (string/replace "_" "/")
                   (pad-base64))]
    (base64/decodeStringToUint8Array string)))

(defn byte->hex
  ^String [^number byte]
  (-> byte
      (.toString 16)
      (.padStart 2 "0")))

(defn hex-encode
  ^String [^js/Uint8Array bytes]
  (byteArrayToHex bytes))

(defn hex-decode
  ^js/Uint8Array [^String string]
  (js/Uint8Array. (hexToByteArray string)))

(defn json-encode
  ^String [object]
  (->> object
       (clj->js)
       (.stringify js/JSON)))

(defn json-decode
  [^String string]
  (->> string
       (.parse js/JSON)
       (js->clj)))

(defn msgpack-serialize
  ^js/Uint8Array [object]
  (->> object
       clj->js
       (.encode msgpack)))

(defn msgpack-deserialize
  [^bytes bytes]
  (->> bytes
       (.decode msgpack)
       js->clj))

;; super hacky!
(defn str->utf8
  ^js/Uint8Array [^String string]
  (let [raw-str (-> string
                    (js/encodeURIComponent)
                    (js/unescape))
        chars (for [x (range (compat-count raw-str))]
                (.charCodeAt raw-str x))]
    (js/Uint8Array. chars)))

(defn utf8->str
  ^String [^js/Uint8Array bytes]
  (let [raw-str (->> bytes
                     (map #(.fromCharCode js/String %))
                     (apply str))]
    (-> raw-str
        (js/escape)
        (js/decodeURIComponent))))
