(ns uniformity.random-test
  (:require [uniformity.random :refer [rand-bytes
                                       rand-bool
                                       rand-int32
                                       rand-uuid]]
            #?(:clj  [clojure.test :refer [deftest is]]
               :cljs [cljs.test :refer-macros [deftest is]])))

(defn bytes->uints [^bytes bs] (map #(bit-and % 0xFF) bs))

;; Core functionality tests

(deftest rand-bytes-valid
  (let [bytes (bytes->uints (rand-bytes 1000))
        vals-in-range (map #(and
                             (> % 0)
                             (< % 256)) bytes)]
    (is true (reduce 'and vals-in-range))))

(defonce max-int32-bound (Math/pow 2 31))

(deftest rand-int32-max-bound
  (let [nums (repeatedly 1000 rand-int32)
        vals-in-range (map #(and
                             (>= % 0)
                             (< % max-int32-bound)) nums)]
    (is true (reduce 'and vals-in-range))))

(deftest rand-int32-bound
  (let [nums (repeatedly 1000 #(rand-int32 1000))
        vals-in-range (map #(and
                             (>= % 0)
                             (< % 1000)) nums)]
    (is true (reduce 'and vals-in-range))))

(deftest rand-int32-range
  (let [nums (repeatedly 1000 #(rand-int32 1000 2000))
        vals-in-range (map #(and
                             (>= % 1000)
                             (< % 2000)) nums)]
    (is true (reduce 'and vals-in-range))))

(deftest rand-int32-neg-range
  (let [nums (repeatedly 1000 #(rand-int32 -2000 -1000))
        vals-in-range (map #(and
                             (>= % -2000)
                             (< % -1000)) nums)]
    (is true (reduce 'and vals-in-range))))

(deftest rand-bool-valid
  (is (boolean? (rand-bool))))

(deftest rand-uuid-valid
  (is (uuid? (rand-uuid))))

;; Statistical tests

(defn pow [num exp]
  (Math/pow num exp))

(defn abs [num]
  (Math/abs num))

(defn sqrt [num]
  (Math/sqrt num))

;; https://en.wikibooks.org/wiki/Algorithm_Implementation/Pseudorandom_Numbers/Chi-Square_Test
(defn chi-square-distrib-rng? [f r]
  (let [n-r 11
        n (* r n-r)
        rand-nums (repeatedly n #(f r))
        ht (vals (frequencies rand-nums))
        chi-square (/ (reduce + (map #(pow (- % n-r) 2) ht)) n-r)]
    (<=
     (abs (- chi-square r))
     (* 2 (sqrt r)))))

(comment
  (chi-square-distrib-rng? rand-int32 256)
  (def range-sample
    (into [] (repeatedly 1000000 #(rand-int32 1000))))
  (def freqs (frequencies range-sample))
  (clojure.pprint/pprint freqs))
