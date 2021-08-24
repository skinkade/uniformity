(ns uniformity.util-test
  (:require [uniformity.util :refer [base64-encode
                                     base64-encode-urlsafe
                                     base64-decode
                                     hex-encode
                                     hex-decode]]
            #?(:clj  [clojure.test :refer [deftest is]]
               :cljs [cljs.test :refer-macros [deftest is]])
            #?(:clj  [clojure.core :as cc]
               :cljs [cljs.core :as cc])))

(defn arr->bytes [arr]
  #?(:cljs (.from js/Uint8Array arr)
     :default (cc/byte-array arr)))

(defn bytes->uints [^bytes bs] (map #(bit-and % 0xFF) bs))

(def reference [0 25 50 75 100 125 150 175 200 225 250])
(def reference-bytes (arr->bytes reference))

(deftest base64-encode-test
  (is (= "ABkyS2R9lq/I4fo=" (base64-encode reference-bytes))))

(deftest base64-encode-urlsafe-test
  (is (= "ABkyS2R9lq_I4fo" (base64-encode-urlsafe reference-bytes))))

(deftest base64-decode-test
  (is (= reference
    (bytes->uints (base64-decode "ABkyS2R9lq/I4fo=")))))

;; should work with or without padding
(deftest base64-decode-urlsafe-test1
  (is (= reference
    (bytes->uints (base64-decode "ABkyS2R9lq_I4fo")))))
(deftest base64-decode-urlsafe-test2
  (is (= reference
    (bytes->uints (base64-decode "ABkyS2R9lq_I4fo=")))))

(deftest hex-encode-test
  (is (= "0019324b647d96afc8e1fa" (hex-encode reference-bytes))))

(deftest hex-decode-test
  (is (= reference
    (bytes->uints (hex-decode "0019324b647d96afc8e1fa")))))
