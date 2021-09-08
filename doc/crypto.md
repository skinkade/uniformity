# Symmetric Encryption

`uniformity` provides easy-to-use encryption functionality using AES128-GCM
and a self-describing output format, refered to as a 'cryptopack'.

User-provided keys and passwords are never directly used to encrypt user-provided
plaintext. Rather, a unique data encryption key is generated for each piece of
data, and user-provided keys and passwords are used for key encryption keys.
Encrypted copies of the data encryption key are stored in key slots within the
metadata alongside the ciphertext.

Allowed length for keys are 128, 192, and 256 bits.
Nonces are 96 bits, and authentication tags are 128 bits.

For more implementation details and rationale, see associated articles.

Note that the pretty-printed vectors of integers below are in reality byte arrays
(byte[] on JVM, Uint8Array in JS).

Plaintext strings are treated as UTF-8 bytes.



### Flags to know about

`encrypt` can take two additional flags:
- `:json` makes a compact cryptopack and serializes it to JSON
- `:padded` - while AES-GCM internally pads plaintext to intervals of 16 bytes,
  this flag enables pre-emptive padding so that the length of the ciphertext
  does not match that of the plaintext



## Examples

```clojure
(ns com.example
  (:require [uniformity.crypto :refer [encrypt
                                       decrypt]]
            [uniformity.random :refer [rand-bytes]]
            [uniformity.util :refer [hex-decode]]
            [clojure.pprint :refer [pprint]]))
```

### Password-based encryption

`uniformity` defaults to using PBKDF2-HMAC-SHA256 with 100,000 rounds and a
random 128-bit salt to derive key encryption keys from passwords.

Password strings are treated as UTF-8 bytes.

```clojure

clj꞉com.example꞉> (pprint (encrypt "Attack at dawn" "Some strong password"))
{:cipher :aes-gcm,
 :nonce [-99, 123, 66, -7, 55, -2, 100, -87, -9, -81, -121, 20],
 :key-slots
 [{:cipher :aes-gcm,
   :nonce [65, -101, 97, 90, 74, -37, 47, 8, -70, -75, 0, -70],
   :key-type :password,
   :encrypted-key
   [-61, 80, -6, -106, -14, 71, -31, 72, -42, 104, 15, 104, -65, 119,
    -2, -20, -57, 7, -109, 47, -118, 120, -104, 5, -71, 118, -9, 86,
    27, -128, -96, -45],
   :kdf-params
   {:kdf :pbkdf2-hmac-sha256,
    :iterations 100000,
    :salt
    [-103, -25, 23, -67, -7, 69, 123, -108, 39, -24, 78, 26, -29, 60,
     -2, 63]}}],
 :ciphertext
 [-14, 3, -11, 36, -111, 70, 98, -15, -36, 116, -37, -1, 78, -83, -34,
  64, -92, -63, -21, -64, 109, -42, 104, 43, 41, 84, -64, 114, 90,
  -69],
 :flags #{:string}}


clj꞉com.example꞉> (def ciphertext
                    (encrypt "Attack at dawn"
                             "Some strong password"
                             :padded :json))
#'com.example/ciphertext ; formatted below
```
```json
{
    "c": "aes-gcm",
    "n": "b64:LJUha8j605ZJvF9n",
    "ks": [
        {
            "c": "aes-gcm",
            "n": "b64:uR_SwckAwBEmEWV4",
            "kt": "p",
            "ek": "b64:P6ld6SyDWwNu6MOzrZrGv9nXxtyJi3OwfqMxjQDRo7s",
            "kp": {
                "fn": "pb2hs256",
                "it": 100000,
                "sa": "b64:CQxR7kSMG2zZgSHSJpKcfw"
            }
        }
    ],
    "ct": "b64:9F6EqB47WHaGJN9p0FYvj5si2sx5_eKFxwrX0oEWdPo",
    "fl": [
        "str",
        "pad"
    ]
}
```

```clojure
clj꞉com.example꞉> (decrypt ciphertext "Some strong password")
"Attack at dawn"
```



### Binary key encryption

```clojure

clj꞉com.example꞉> (def plaintext (byte-array [1 2 3 4]))
#'com.example/plaintext

clj꞉com.example꞉> (def secret-key (rand-bytes 16)) ; or 24 or 32
#'com.example/secret-key

clj꞉com.example꞉> (def ciphertext (encrypt plaintext secret-key))
#'com.example/ciphertext

clj꞉com.example꞉> (pprint ciphertext)
{:cipher :aes-gcm,
 :nonce [-91, -38, -58, 92, 76, -120, -18, -40, -10, -115, -66, -39],
 :key-slots
 [{:cipher :aes-gcm,
   :nonce
   [103, 109, -118, -88, -63, 21, -127, 119, -23, -92, 98, -126],
   :key-type :binary,
   :encrypted-key
   [75, 5, 108, 45, 40, -37, -32, 75, 46, -97, 85, 120, 113, 117, -73,
    -54, -94, 78, -124, 18, -107, 64, 10, -58, -128, 34, 72, 115, 59,
    -123, 26, 50]}],
 :ciphertext
 [-121, 91, 80, 92, -50, -83, 73, -9, -87, -4, -122, -24, -51, -125,
  57, -20, 89, 48, 6, -57]}

clj꞉com.example꞉> (vec (decrypt ciphertext secret-key))
[1 2 3 4]
```

### Multi-key encryption

Because `uniformity` uses a random data encryption key with slots for key
encryption keys, a number of keys can be used for the same ciphertext,
as opposed to encrypting the plaintext multiple times for different copies.

In the following example, we encrypt a piece of data both with a password,
and with a backup key (perhaps read from a file) in case the password is forgotten.

```clojure

clj꞉com.example꞉> (def backup-key
                    (hex-decode "9fa510b0ccc70f84c700189ec4f34bf4"))
#'com.example/backup-key

clj꞉com.example꞉> (def password "jmkPRiqVk3fgLZivqm"))
#'com.example/password

clj꞉com.example꞉> (def ciphertext
                    (encrypt "multi-key test"
                             [backup-key password]))
#'com.example/ciphertext



;; either key works to decrypt

clj꞉com.example꞉> (decrypt ciphertext "jmkPRiqVk3fgLZivqm")
"multi-key test"

clj꞉com.example꞉> (decrypt ciphertext
                           (hex-decode
                            "9fa510b0ccc70f84c700189ec4f34bf4"))
"multi-key test"
```
