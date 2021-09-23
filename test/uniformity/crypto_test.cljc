(ns uniformity.crypto-test
  (:require [uniformity.internals.validation :refer [compat-byte-array]]
            [uniformity.crypto.core :as crypto]
            [uniformity.crypto.cryptopack :refer [encrypt decrypt]]
            [uniformity.util :refer [hex-decode]]
            [uniformity.test-util :refer [test-async]]
            #?(:clj  [async-error.core :refer [go-try <?]]
               :cljs [async-error.core :refer-macros [go-try <?]])
            #?(:clj  [clojure.test :refer [deftest is]]
               :cljs [cljs.test :refer-macros [deftest is]])
            #?(:clj  [clojure.core.async :refer [chan go >! <! <!! take!]]
               :cljs [cljs.core.async :refer [chan go >! <!]])))


;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;                                                       ;;
;;       Global variables used in all the tests          ;;
;;                                                       ;;
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

(def test-password "jmkPRiqVk3fgLZivqm")
(def test-bin-key
  (hex-decode
   "9fa510b0ccc70f84c700189ec4f34bf4"))
(def test-nonce
  (compat-byte-array
   [1 2 3 4 5 6 7 8 9 10 11 12]))
(def test-iv
  (compat-byte-array
   [1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16]))
(def test-salt test-iv)

(def test-plaintext-string "foobar")
(def test-plaintext-bytes
  (compat-byte-array [1 2 3 4]))



;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;                                                       ;;
;;                          AES                          ;;
;;                                                       ;;
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

(comment
  (crypto/aes-gcm-encrypt test-plaintext-bytes
                          test-bin-key
                          test-nonce))
;; below generated with above on JVM
(def aes-gcm-reference-ciphertext
  (hex-decode
   "f133d4acee2aff268b0f92692487b84bc5353b4d"))

(deftest aes-gcm-encryption
  (test-async
   (go
     (let [ciphertext (:ciphertext
                       (<? (crypto/aes-gcm-encrypt test-plaintext-bytes
                                                   test-bin-key
                                                   :nonce test-nonce)))
           plaintext (<? (crypto/aes-gcm-decrypt ciphertext
                                                 test-bin-key
                                                 test-nonce))]
       (is (= (vec aes-gcm-reference-ciphertext)
              (vec ciphertext)))
       (is (= (vec test-plaintext-bytes)
              (vec plaintext)))))))



;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;                                                       ;;
;;                        PBKDF2                         ;;
;;                                                       ;;
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

(comment
  (def pwkey (atom nil))
  (take! (crypto/pbkdf2 test-password
                        test-salt
                        100000
                        :sha256
                        128)
         (fn [pk] (reset! pwkey (:key pk)))))
;; below generated with above on JVM
(def reference-pbkdf2-result
  (hex-decode
   "1975235f2ef8e3435f7f277f68913656"))

(deftest pbkdf2-derive-match
  (test-async
   (go
     (let [password-key (:key (<? (crypto/pbkdf2 test-password
                                                 :salt test-salt
                                                 :iterations 100000
                                                 :hash :sha256
                                                 :key-length 128)))]
       (is (= (vec reference-pbkdf2-result)
              (vec password-key)))))))



;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;                                                       ;;
;;                         RSA                           ;;
;;                                                       ;;
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

(deftest basic-rsa-flow
  (test-async
   (go
     (let [keypair (<? (crypto/rsa-generate-keypair 2048))
           pubkey (:public keypair)
           privkey (:private keypair)
           ciphertext (<! (crypto/rsa-encrypt test-plaintext-bytes
                                              pubkey))
           plaintext (<! (crypto/rsa-decrypt ciphertext
                                             privkey))]
       (is (= (vec test-plaintext-bytes)
              (vec plaintext)))))))

(comment
  (go
    (let [keypair (<? (crypto/rsa-generate-keypair 3072))
          pubkey (:public keypair)
          privkey (:private keypair)
          ciphertext (<? (crypto/rsa-encrypt test-plaintext-bytes pubkey))]
      (with-open [pubkey-output (java.io.FileOutputStream. "test/uniformity/test-pubkey.bin")]
        (.write pubkey-output pubkey))
      (with-open [privkey-output (java.io.FileOutputStream. "test/uniformity/test-privkey.bin")]
        (.write privkey-output privkey))
      (with-open [ciphertext-output (java.io.FileOutputStream. "test/uniformity/test-rsa-ciphertext.bin")]
        (.write ciphertext-output ciphertext)))))

(defn read-test-bytes [path]
  #?(:clj (with-open [s (java.io.FileInputStream. path)]
            (.readAllBytes s))
     :cljs (let [fs (js/require "fs")]
             (.readFileSync fs path))))

(def test-pubkey
  (read-test-bytes "test/uniformity/test-pubkey.bin"))
(def test-privkey
  (read-test-bytes "test/uniformity/test-privkey.bin"))
(def test-rsa-ciphertext
  (read-test-bytes "test/uniformity/test-rsa-ciphertext.bin"))

(deftest rsa-decrypt-existing
  (test-async
   (go
     (let [plaintext (<! (crypto/rsa-decrypt test-rsa-ciphertext
                                             test-privkey))]
       (is (= (vec test-plaintext-bytes)
              (vec plaintext)))))))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;                                                       ;;
;;                 Cryptopack Symmetric                  ;;
;;                                                       ;;
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

(deftest single-password
  (test-async
   (go
     (let [ciphertext-str (<? (encrypt test-plaintext-string
                                       :password test-password))
           ciphertext-bytes (<? (encrypt test-plaintext-bytes
                                         :password test-password))]
       (is test-plaintext-string (<? (decrypt ciphertext-str
                                              :password test-password
                                              :output :string)))
       (is (= (vec test-plaintext-bytes)
              (vec (<? (decrypt ciphertext-bytes
                                :password test-password)))))))))

(deftest single-bin-key
  (test-async
   (go
     (let [ciphertext-str (<? (encrypt test-plaintext-string
                                       :aes-key test-bin-key))
           ciphertext-bytes (<? (encrypt test-plaintext-bytes
                                         :aes-key test-bin-key))]
       (is test-plaintext-string (<? (decrypt ciphertext-str
                                              :aes-key test-bin-key
                                              :output :string)))
       (is (= (vec test-plaintext-bytes)
              (vec (<? (decrypt ciphertext-bytes :aes-key test-bin-key)))))))))

(deftest mixed-keys
  (test-async
   (go
     (let [ciphertext-str (<? (encrypt test-plaintext-string
                                       :password test-password
                                       :aes-key test-bin-key))
           ciphertext-bytes (<? (encrypt test-plaintext-bytes
                                         :password test-password
                                         :aes-key test-bin-key))]
       (is test-plaintext-string (<? (decrypt ciphertext-str
                                              :password test-password
                                              :output :string)))
       (is (= (vec test-plaintext-bytes)
              (vec (<? (decrypt ciphertext-bytes :password test-password)))))
       (is test-plaintext-string (<? (decrypt ciphertext-str
                                              :aes-key test-bin-key
                                              :output :string)))
       (is (= (vec test-plaintext-bytes)
              (vec (<? (decrypt ciphertext-bytes :aes-key test-bin-key)))))))))



;; Confirm that a JSON-encoded map encrypted with a Unicode password
;; and using pre-padding is able to be decrypted
;;
;; This is partially to make sure Unicode strings are properly handled between
;; Java, JavaScript, and .NET

(def unicode-password "🗼🙂⏯📔朝午後夜")

;; generated with:
(comment
  (<!!
   (encrypt test-plaintext-string
            :password [test-password unicode-password]
            :padding 32
            :output :json)))

(def test-json
  "{\"n\":\"b64:BgKduNQqy5FhTFAr\",\"ct\":\"b64:_wNG5S-iMv3zo7QvWq2UpvDavfgI20YgU2eVndNoBfaA70-OsLnBFEiW2B_R_NSl\",\"c\":\"gcm\",\"ks\":[{\"n\":\"b64:reMVOhFAfxlx0Bca\",\"c\":\"gcm\",\"kt\":\"p\",\"kp\":{\"sa\":\"b64:oDbkjoMLP_Jswhz3MZGOgg\",\"it\":100000,\"h\":\"s256\",\"kl\":128,\"fn\":\"pb2\"},\"ek\":\"b64:Qk0VntP6WjRUW0R9l-GONWzunI45qXqWin-NcnNXnkc\"},{\"n\":\"b64:rM-Cm72zOiVSvUIx\",\"c\":\"gcm\",\"kt\":\"p\",\"kp\":{\"sa\":\"b64:qTgZqq7GUnkSydHMUmaVyQ\",\"it\":100000,\"h\":\"s256\",\"kl\":128,\"fn\":\"pb2\"},\"ek\":\"b64:lhVQroTyKEHwqgGzNaej80Tzz7S_9TmhKj0IyKR0-Mo\"}],\"fl\":[\"pd\"]}")

(deftest json-simple-password
  (test-async
   (go
     (is test-plaintext-string
         (<? (decrypt test-json
                      :password test-password
                      :output :string))))))

(deftest json-unicode-password
  (test-async
   (go
     (is test-plaintext-string
         (<? (decrypt test-json
                      :password unicode-password
                      :output :string))))))



;; ;; msgpack tests

(def test-msgpack-file "test/uniformity/msgpack-test.bin")

;; Test binary generated with:
(comment
  (def msgpack-ciphertext (atom nil))
  (take! (encrypt test-plaintext-string
                  :password [test-password unicode-password]
                  :padding 16
                  :output :msgpack)
         (fn [ct] (reset! msgpack-ciphertext ct)))
  (with-open [output (java.io.FileOutputStream. test-msgpack-file)]
    (.write output @msgpack-ciphertext)))

(def msgpack-test-bytes
  #?(:clj (with-open [out (java.io.ByteArrayOutputStream.)]
            (clojure.java.io/copy
             (clojure.java.io/input-stream test-msgpack-file)
             out)
            (.toByteArray out))
     :cljs (let [fs (js/require "fs")]
             (.readFileSync fs test-msgpack-file))
     :default nil))

(deftest msgpack-simple-password
  (test-async
   (go
     (is test-plaintext-string
         (<? (decrypt msgpack-test-bytes
                      :password test-password
                      :output :string))))))

(deftest msgpack-unicode-password
  (test-async
   (go
     (is test-plaintext-string
         (<? (decrypt msgpack-test-bytes
                      :password unicode-password
                      :output :string))))))



;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;                                                       ;;
;;                Cryptopack Asymmetric                  ;;
;;                                                       ;;
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

(deftest cryptopack-rsa
  (test-async
   (go
     (let [keypair (<? (crypto/rsa-generate-keypair 2048))
           pubkey (:public keypair)
           privkey (:private keypair)
           ciphertext (<? (encrypt test-plaintext-bytes
                                   :rsa-pubkey pubkey))
           plaintext (<? (decrypt ciphertext
                                  :rsa-privkey privkey))]
       (is (= (vec test-plaintext-bytes)
              (vec plaintext)))))))

(comment
  (go
    (let [ciphertext (<? (encrypt test-plaintext-bytes
                                  :rsa-pubkey test-pubkey
                                  :output :msgpack))]
      (with-open [ciphertext-output (java.io.FileOutputStream. "test/uniformity/test-rsa-cryptopack.bin")]
        (.write ciphertext-output ciphertext)))))

(def test-rsa-cryptopack
  (read-test-bytes "test/uniformity/test-rsa-cryptopack.bin"))

(deftest cryptopack-rsa-existing
  (test-async
   (go
     (let [plaintext (<? (decrypt test-rsa-cryptopack
                                  :rsa-privkey test-privkey))]
       (is (= (vec plaintext)
              (vec test-plaintext-bytes)))))))
