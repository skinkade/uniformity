(ns uniformity.internals.js.rand
  (:require [uniformity.internals.js.node-browser-compat :refer [crypto-type crypto]]
            [uniformity.internals.js.util :refer [byte->hex]]))

(defn ^:private browser-rand-bytes
  ^js/Uint8Array
  [^number n]
  {:pre [(> n 0)]
   :post [(= n (.-length %))]}
  (let [bs (js/Uint8Array. n)]
    (. ^Object crypto getRandomValues bs)
    bs))

(defn ^:private node-rand-bytes
  ^js/Uint8Array
  [^number n]
  {:pre [(> n 0)]
   :post [(= n (.-length %))]}
    (js/Uint8Array.
     (. ^Object crypto randomBytes n)))

(def rand-bytes
  (if (= :browser crypto-type)
    browser-rand-bytes
    node-rand-bytes))

;; 48-bit int can is the largest that can be contained within a double in JS
(defonce ^:private rand-max 0xFFFFFFFFFFFF)

(defn ^:private rand-uint48be []
  (let [bytes (rand-bytes 6)]
    (+
     (* (aget bytes 0) (Math/pow 2 8))
     (* (aget bytes 1) (Math/pow 2 32))
     (* (aget bytes 2) (Math/pow 2 24))
     (* (aget bytes 3) (Math/pow 2 16))
     (* (aget bytes 4) (Math/pow 2 8))
     (aget bytes 5))))

(defn rand-int32
  (^number [] (rand-int32 0 (Math/pow 2 31)))
  (^number [^number max] (rand-int32 0 max))
  (^number [^number min
            ^number max]
   {:pre [(> max min)
          (<= (- max min) rand-max)
          (.isSafeInteger js/Number min)
          (.isSafeInteger js/Number max)]
    :post [(< % max)
           (>= % min)]}
   (let [range (- max min)
         rand-limit (- rand-max (mod rand-max range))]
     (loop [x (rand-uint48be)]
       (if (< x rand-limit)
         (+ (mod x range) min)
         (recur (rand-uint48be)))))))

(defn rand-uuid ^uuid []
  (let [bytes (rand-bytes 16)
        hex (map byte->hex bytes)
        version (-> (aget bytes 6)
                    (bit-and 0x0f)
                    (bit-or 0x40)
                    (byte->hex))
        variant (-> (aget bytes 8)
                    (bit-and 0x3f)
                    (bit-or 0x80)
                    (byte->hex))]
    (uuid
     (str
      (nth hex 0) (nth hex 1) (nth hex 2) (nth hex 3) "-"
      (nth hex 4) (nth hex 5) "-"
      version (nth hex 7) "-"
      variant (nth hex 9) "-"
      (nth hex 10) (nth hex 11) (nth hex 12)
      (nth hex 13) (nth hex 14) (nth hex 15)))))
