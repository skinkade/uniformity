# Hex encoding / decoding

```clojure
clj꞉uniformity.util꞉> (def sample-bytes
  (uniformity.random/rand-bytes 8))
#'uniformity.util/sample-bytes

clj꞉uniformity.util꞉> (hex-encode sample-bytes)
"3da5f664c0f0746f"

;; byte[] on JVM, Uint8Array in JS
clj꞉uniformity.util꞉> (hex-decode "3da5f664c0f0746f")
#object["[B" 0x5ad517df "[B@5ad517df"]

;; cast to array for value comparison
clj꞉uniformity.util꞉> 
(= (into [] sample-bytes)
   (into [] (hex-decode "3da5f664c0f0746f")))
true
```



# Base64 encoding / decoding

```clojure
clj꞉uniformity.util꞉> (def sample-bytes
  (uniformity.random/rand-bytes 8))
#'uniformity.util/sample-bytes

clj꞉uniformity.util꞉> (base64-encode sample-bytes)
"FND/t6BzewM="

clj꞉uniformity.util꞉> (base64-encode-urlsafe sample-bytes)
"FND_t6BzewM"

;; base64 decode works on both normal and URL-safe strings
clj꞉uniformity.util꞉> 
(= (into [] sample-bytes)
   (into [] (base64-decode "FND/t6BzewM="))
   (into [] (base64-decode "FND_t6BzewM")))
true
```
