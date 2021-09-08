(ns uniformity.internals.util-js
  (:require [goog.crypt :refer [byteArrayToHex hexToByteArray]]
            [goog.crypt.base64 :as base64]
            [clojure.string :refer [replace]]
            [uniformity.internals.validation :refer [compat-count]]))

(defn base64-encode [bytes]
  (base64/encodeByteArray bytes))

(defn base64-encode-urlsafe [bytes]
  (-> bytes
      (base64-encode)
      (replace "+" "-")
      (replace "/" "_")
      (replace "=" "")))

(defn ^:private pad-base64 [string]
  (if (= 0 (mod (compat-count string) 4))
    string
    (let [padding-needed (- 4 (mod (compat-count string) 4))]
      (apply str string (repeat padding-needed "=")))))

(defn base64-decode [string]
  (let [string (-> string
                   (replace "-" "+")
                   (replace "_" "/")
                   (pad-base64))]
    (base64/decodeStringToUint8Array string)))

(defn byte->hex [byte]
  (-> byte
      (.toString 16)
      (.padStart 2 "0")))

(defn hex-encode [bytes]
  (byteArrayToHex bytes))

(defn hex-decode [string]
  (js/Uint8Array. (hexToByteArray string)))

(defn json-encode [object]
  (->> object
       (clj->js)
       (.stringify js/JSON)))

(defn json-decode [string]
  (->> string
       (.parse js/JSON)
       (js->clj)))

;; super hacky!
(defn str->utf8 [string]
  (let [raw-str (-> string
                    (js/encodeURIComponent)
                    (js/unescape))
        chars (for [x (range (compat-count raw-str))]
                (.charCodeAt raw-str x))]
    (js/Uint8Array. chars)))

(defn utf8->str [bytes]
  (let [raw-str (->> bytes
                     (map #(.fromCharCode js/String %))
                     (apply str))]
    (-> raw-str
        (js/escape)
        (js/decodeURIComponent))))
