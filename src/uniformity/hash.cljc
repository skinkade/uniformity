(ns uniformity.hash
  (:require #?(:clj [uniformity.internals.java.hash :as internals]
               :cljs [uniformity.internals.js.hash :as internals])
            [uniformity.util :as util]))

(defn ^:private hash-format [hash format]
  (case format
    :bytes hash
    :hex (util/hex-encode hash)
    :base64 (util/base64-encode hash)
    :base64-urlsafe (util/base64-encode-urlsafe hash)
    (throw (ex-info "Unidentified hash format"
                    {:format format}))))

(defn md5
  "Produces a MD5 hash of input bytes.
  Optional :format parameter determines output:
    :bytes
    :hex (default)
    :base64
    :base64-urlsafe"
  [bytes
   & {:keys [format] :or {format :hex}}]
  (hash-format (internals/md5 bytes)
               format))

(defn sha1
  "Produces a SHA-1 hash of input bytes.
  Optional :format parameter determines output:
    :bytes
    :hex (default)
    :base64
    :base64-urlsafe"
  [bytes
   & {:keys [format] :or {format :hex}}]
  (hash-format (internals/sha1 bytes)
               format))

(defn sha256
  "Produces a SHA-256 hash of input bytes.
  Optional :format parameter determines output:
    :bytes
    :hex (default)
    :base64
    :base64-urlsafe"
  [bytes
   & {:keys [format] :or {format :hex}}]
  (hash-format (internals/sha256 bytes)
               format))

(defn sha384
  "Produces a SHA-384 hash of input bytes.
  Optional :format parameter determines output:
    :bytes
    :hex (default)
    :base64
    :base64-urlsafe"
  [bytes
   & {:keys [format] :or {format :hex}}]
  (hash-format (internals/sha384 bytes)
               format))

(defn sha512
  "Produces a SHA-512 hash of input bytes.
  Optional :format parameter determines output:
    :bytes
    :hex (default)
    :base64
    :base64-urlsafe"
  [bytes
   & {:keys [format] :or {format :hex}}]
  (hash-format (internals/sha512 bytes)
               format))

(defn hashes-equal?
  "Compares equality of two hashes by comparing every element
  to inhibit timing attacks."
  [hash1 hash2]
  (if (not= (count hash1) (count hash2))
    false
    (reduce (fn [equals idx]
              (and equals
                   (= (get hash1 idx)
                      (get hash2 idx))))
            true
            (range (count hash1)))))
