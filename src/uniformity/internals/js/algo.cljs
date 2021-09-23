;; (ns uniformity.internals.js.algo
;;   (:require ["asmcrypto.js" :as asmcrypto]
;;             [uniformity.util :as util]
;;             [clojure.core.async :as async]
;;             [cljs.core.async.interop :refer [p->c]]))

;; (defn pbkdf2-hmac-sha256
;;   ^js/Uint8Array
;;   [password
;;    ^js/Uint8Array salt
;;    ^number iterations
;;    ^number key-length-bits]
;;   {:pre [(or
;;           (string? password)
;;           (instance? js/Uint8Array password))
;;          (>= (.-length salt) 16)
;;          (>= iterations 1000)
;;          (= 0 (mod key-length-bits 8))]
;;    :post [(= (.-length %)
;;              (/ key-length-bits 8))]}
;;   (let [password (if (string? password)
;;                    (util/str->utf8 password)
;;                    password)
;;         key-length (/ key-length-bits 8)]
;;     (asmcrypto/Pbkdf2HmacSha256 password salt iterations key-length)))

;; (defonce ^:private gcm-tag-length (/ 128 8))
;; (defonce ^:private gcm-nonce-length (/ 96 8))

;; (defn aes-gcm-encrypt
;;   ^js/Uint8Array
;;   [^js/Uint8Array plaintext
;;    ^js/Uint8Array key
;;    ^js/Uint8Array nonce
;;    & {:keys [aad] :or {aad []}}]
;;   {:pre [(contains? #{16 24 32} (.-length key))
;;          (= gcm-nonce-length (.-length nonce))]}
;;   (.encrypt asmcrypto/AES_GCM
;;             plaintext
;;             key
;;             nonce
;;             aad
;;             gcm-tag-length))

;; (defn aes-gcm-decrypt
;;   ^js/Uint8Array
;;   [^js/Uint8Array ciphertext
;;    ^js/Uint8Array key
;;    ^js/Uint8Array nonce
;;    & {:keys [aad] :or {aad []}}]
;;   {:pre [(contains? #{16 24 32} (.-length key))
;;          (= gcm-nonce-length (.-length nonce))]}
;;   (.decrypt asmcrypto/AES_GCM
;;             ciphertext
;;             key
;;             nonce
;;             aad
;;             gcm-tag-length))

;; (defonce ^:private crypto
;;   (try
;;     (js/require "crypto")
;;     (catch :default _ nil)))

;; (def gen-rsa-key
;;   (if (some? crypto)
;;     (fn [bits]
;;       (let [keypair (.generateKeyPairSync crypto
;;                                           "rsa"
;;                                           #js {"modulusLength" 2048})
;;             pubkey (.export keypair.publicKey #js {"type" "spki"
;;                                                    "format" "der"})
;;             privkey (.export keypair.privateKey #js {"type" "pkcs8"
;;                                                      "format" "der"})]
;;         {:public (js/Uint8Array. pubkey)
;;          :private (js/Uint8Array. privkey)}))
;;     nil))

;; (defn subtle-rsa-key []
;;   (let [a (atom nil)
;;         c (async/chan)
;;         params #js {"name" "RSA-OAEP"
;;                     "modulusLength" 2048
;;                     "publicExponent" (js/Uint8Array. [0x01, 0x00, 0x01])
;;                     "hash" "SHA-256"}
;;         extractable true
;;         key-usages ["encrypt" "decrypt"]
;;         subtle js/window.crypto.subtle]
;;     (async/go
;;       (-> (.generateKey subtle
;;                         params
;;                         extractable
;;                         key-usages)
;;           (.then (fn [val] (async/>! c val)))))
;;     (async/go
;;       (reset! a (async/<! c)))
;;     @a))

;; (defn rsa-encrypt
;;   ^js/Uint8Array
;;   [^js/Uint8Array plaintext
;;    ^js/Uint8Array pubkey]
;;   (async/go
;;     (let [key-options #js {"key" pubkey
;;                            "format" "der"
;;                            "type" "spki"}
;;           pubkey (.createPublicKey crypto key-options)
;;           rsa-opts #js {"key" pubkey
;;                         "oaepHash" "sha256"}]
;;       (js/Uint8Array. (.publicEncrypt crypto rsa-opts plaintext)))))

;; (defn rsa-decrypt
;;   ^js/Uint8Array
;;   [^js/Uint8Array ciphertext
;;    privkey]
;;   (async/go
;;    (let [key-format (if (string? privkey)
;;                       "pem"
;;                       "der")
;;          key-options #js {"key" privkey
;;                           "format" key-format
;;                           "type" "pkcs8"}
;;          privkey (.createPrivateKey crypto key-options)
;;          rsa-opts #js {"key" privkey
;;                        "oaepHash" "sha256"}]
;;      (js/Uint8Array. (.privateDecrypt crypto rsa-opts ciphertext)))))
