# Hashing

`uniformity.hash` provides MD5, SHA1, SHA256, SHA384, and SHA512 hashes
with binary, hex, base64, or URL-safe base64 encoding.

It also provides a `hashes-equal?` function to check for hash equality.
Note that encoding of its two inputs must be the same (i.e. both hex
or both binary format).

```clojure
clj꞉uniformity.hash꞉> (def test-bytes (byte-array [1 2 3 4]))
#'uniformity.hash/test-bytes

;; defaults to hex encoding
clj꞉uniformity.hash꞉> (md5 test-bytes)
"08d6c05a21512a79a1dfeb9d2a8f262f"

;; or you can specify format
clj꞉uniformity.hash꞉> (sha1 test-bytes :format :hex)
"12dada1fff4d4787ade3333147202c3b443e376f"

clj꞉uniformity.hash꞉> (sha256 test-bytes :format :bytes)
#object["[B" 0x528b135d "[B@528b135d"]

clj꞉uniformity.hash꞉> (sha384 test-bytes :format :base64)
"WmZ9YkMKjCU+uuQzMzkE3G4dQdzcR5cEdzFZuQWjrYLSutd2LYGjZsxG+7LiMn9c"

clj꞉uniformity.hash꞉> (sha512 test-bytes :format :base64-urlsafe)
"p8l22xcjrbQSdBeNyC6bd3lBqyAcad5h0PK8bSejWY9ZT6dI5Q2I08K_HiwucsPP73jDxtSvqQOR9-M6urykjg"

;; equality comparison
clj꞉uniformity.hash꞉> (hashes-equal? (md5 test-bytes) "08d6c05a21512a79a1dfeb9d2a8f262f")
true