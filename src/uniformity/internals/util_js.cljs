(ns uniformity.internals.util-js
  (:require [base64-js]
            [clojure.string :refer [replace]]))

(defn base64-encode [bytes]
  (base64-js/fromByteArray bytes))

(defn base64-encode-urlsafe [bytes]
  (-> bytes
      (base64-encode)
      (replace "+" "-")
      (replace "/" "_")
      (replace "=" "")))

(defn ^:private pad-base64 [string]
  (if (= 0 (mod (count string) 4))
    string
    (let [padding-needed (- 4 (mod (count string) 4))]
      (apply str string (repeat padding-needed "=")))))

(defn base64-decode [string]
  (let [string (-> string
                   (replace "-" "+")
                   (replace "_" "/")
                   (pad-base64))]
    (base64-js/toByteArray string)))

(defn byte->hex [byte]
  (-> byte
      (.toString 16)
      (.padStart 2 "0")))

(defn hex-encode [bytes]
  (apply str (map byte->hex bytes)))

(defn hex-decode [string]
  (->> string
       (partition 2)
       (map #(apply str %))
       (map #(js/parseInt % 16))
       (.from js/Uint8Array)))
