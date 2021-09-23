# uniformity.crypto.core

The core cryptography module provides asynchronous primitives for
AES-GCM, RSA, and PBKDF2.
Each function returns a channel containing either the result of the operation,
or and Exception (JVM) or Error (JS).

The AES-GCM encryption function auto-generates a 96-bit random nonce if one is
not provided. For this reason, the return value is a map containing the nonce
and the ciphertext.

```clojure
(def plaintext (byte-array [1 2 3 4]))
(def enc-key (rand-bytes 16))
(def enc-nonce (rand-bytes 12))

;; with nonce provided
(<!! (aes-gcm-encrypt plaintext enc-key :nonce enc-nonce))
;; => {:nonce #object["[B" 0x321111aa "[B@321111aa"],
;;     :ciphertext #object["[B" 0x6098f59e "[B@6098f59e"]}

;; auto-generated nonce
(<!! (aes-gcm-encrypt plaintext enc-key))
;; => {:nonce #object["[B" 0x61d1f2ad "[B@61d1f2ad"],
;;     :ciphertext #object["[B" 0x222d5723 "[B@222d5723"]}
```

`rsa-generate-keypair` creates a public/private keypair of 2048, 3072,
or 4096 bits.
Public keys are in SPKI format, and private keys are in PKCS#8 format, as bytes.

```clojure
(<!!
 (go
   (let [plaintext (byte-array [1 2 3 4])
         keypair (<? (rsa-generate-keypair 2048))
         pubkey (:public keypair)
         privkey (:private keypair)
         ciphertext (<! (rsa-encrypt plaintext
                                     pubkey))
         decrypted (<! (rsa-decrypt ciphertext
                                    privkey))]
     (vec decrypted))))
;; => [1 2 3 4]
```

The PBKDF2 function only requires passing a password, and provides sane defaults
for all other parameters.

```clojure
(<!! (pbkdf2 "password"))
;; => {:key #object["[B" 0x78783c2b "[B@78783c2b"],
;;     :salt #object["[B" 0x1c59c4af "[B@1c59c4af"],
;;     :iterations 100000,
;;     :hash :sha256,
;;     :key-length 128}

;; equivalent to above
(<!! (pbkdf2 "password"
             :salt (rand-bytes 16)
             :iterations 100000
             :hash :sha256
             :key-length 128))
```
