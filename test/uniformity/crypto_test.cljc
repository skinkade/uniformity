(ns uniformity.crypto-test
  (:require [uniformity.internals.validation :refer [compat-byte-array]]
            [uniformity.crypto :refer [encrypt
                                       decrypt]]
            [uniformity.util :refer [hex-decode]]
            #?(:clj  [clojure.test :refer [deftest is]]
               :cljs [cljs.test :refer-macros [deftest is]])))

(def test-password "jmkPRiqVk3fgLZivqm")
(def test-bin-key
  (hex-decode
   "9fa510b0ccc70f84c700189ec4f34bf4"))

(def test-plaintext-string "foobar")
(def test-plaintext-bytes
  (compat-byte-array [1 2 3 4]))



;; Core functionality tests

(deftest single-password
  (let [ciphertext-str (encrypt test-plaintext-string
                                test-password)
        ciphertext-bytes (encrypt test-plaintext-bytes
                                  test-password)]
    (is test-plaintext-string (decrypt ciphertext-str test-password))
    (is (= (vec test-plaintext-bytes)
           (vec (decrypt ciphertext-bytes test-password))))))

(deftest single-bin-key
  (let [ciphertext-str (encrypt test-plaintext-string
                                test-bin-key)
        ciphertext-bytes (encrypt test-plaintext-bytes
                                  test-bin-key)]
    (is test-plaintext-string (decrypt ciphertext-str test-bin-key))
    (is (= (vec test-plaintext-bytes)
           (vec (decrypt ciphertext-bytes test-bin-key))))))

(deftest mixed-keys
  (let [ciphertext-str (encrypt test-plaintext-string
                                [test-password test-bin-key])
        ciphertext-bytes (encrypt test-plaintext-bytes
                                  [test-password test-bin-key])]
    (is test-plaintext-string (decrypt ciphertext-str test-password))
    (is (= (vec test-plaintext-bytes)
           (vec (decrypt ciphertext-bytes test-password))))
    (is test-plaintext-string (decrypt ciphertext-str test-bin-key))
    (is (= (vec test-plaintext-bytes)
           (vec (decrypt ciphertext-bytes test-bin-key))))))



;; Confirm that a JSON-encoded map encrypted with a Unicode password
;; and using pre-padding is able to be decrypted
;;
;; This is partially to make sure Unicode strings are properly handled between
;; Java, JavaScript, and .NET

(def unicode-password "🗼🙂⏯📔朝午後夜")

;; generated with:
(comment
  (encrypt test-plaintext-string
           [test-password unicode-password]
           :padded :json))

(def test-json
  "{\"c\":\"aes-gcm\",\"n\":\"b64:g1ABMTxHMHa6LvsP\",\"ks\":[{\"c\":\"aes-gcm\",\"n\":\"b64:48_U6ZcWOfOJv3HU\",\"kt\":\"p\",\"ek\":\"b64:VqpEWoBvf8fgT9h_HjQpILi2sq423XIdO1zRWpkUdoI\",\"kp\":{\"fn\":\"pb2hs256\",\"it\":100000,\"sa\":\"b64:8E0beNmuyvrBICJzH_oFjQ\"}},{\"c\":\"aes-gcm\",\"n\":\"b64:AbGzl6Xtv8E1s6ck\",\"kt\":\"p\",\"ek\":\"b64:Sl-DWBC_F5YeQaxCpJIN2thStJKAb0q_-r8trKji8x8\",\"kp\":{\"fn\":\"pb2hs256\",\"it\":100000,\"sa\":\"b64:VefWlegsWiQl5eTA-ekwLQ\"}}],\"ct\":\"b64:ZNmFxJGh_YUhFnVZ1bjyELgpRZVsNht2xxvsb2yn5Ys\",\"fl\":[\"str\",\"pad\"]}")

(deftest json-simple-password
  (is test-plaintext-string
      (decrypt test-json test-password)))

(deftest json-unicode-password
  (is test-plaintext-string
      (decrypt test-json unicode-password)))
