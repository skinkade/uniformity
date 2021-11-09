(ns uniformity.hash-test
  (:require [uniformity.internals.validation :refer [compat-byte-array]]
            [uniformity.hash :as hash]
            #?(:clj  [clojure.test :refer [deftest is]]
               :cljs [cljs.test :refer-macros [deftest is]])))

(def reference-bytes
  (compat-byte-array [1 2 3 4]))

(def md5-reference-hash
  "08d6c05a21512a79a1dfeb9d2a8f262f")

(deftest md5-test
  (is (hash/hashes-equal? (hash/md5 reference-bytes)
                          md5-reference-hash)))


(def sha1-reference-hash
  "12dada1fff4d4787ade3333147202c3b443e376f")

(deftest sha1-test
  (is (hash/hashes-equal? (hash/sha1 reference-bytes)
                          sha1-reference-hash)))


(def sha256-reference-hash
  "9f64a747e1b97f131fabb6b447296c9b6f0201e79fb3c5356e6c77e89b6a806a")

(deftest sha256-test
  (is (hash/hashes-equal? (hash/sha256 reference-bytes)
                          sha256-reference-hash)))


(def sha384-reference-hash
  "5a667d62430a8c253ebae433333904dc6e1d41dcdc479704773159b905a3ad82d2bad7762d81a366cc46fbb2e2327f5c")

(deftest sha384-test
  (is (hash/hashes-equal? (hash/sha384 reference-bytes)
                          sha384-reference-hash)))


(def sha512-reference-hash
  "a7c976db1723adb41274178dc82e9b777941ab201c69de61d0f2bc6d27a3598f594fa748e50d88d3c2bf1e2c2e72c3cfef78c3c6d4afa90391f7e33ababca48e")

(deftest sha512-test
  (is (hash/hashes-equal? (hash/sha512 reference-bytes)
                          sha512-reference-hash)))
