(ns uniformity.internals.rand-java
  (:import java.security.SecureRandom))

;; Performance notes:
;;
;; After benchmarking various algorithm options for SecureRandom with OpenJDK on Linux,
;; I found negligible differences between mean execution time for e.g. nextInt().
;; It seems reasonable to just allow the default constructor to choose one.
;;
;; SecureRandom is thread-safe, however there is a possibility that heavily
;; calling on an instance from many threads could lead to a performance penalty.
;; If this does turn out to be an issue, we could use ThreadLocal<SecureRandom>.

(defonce sec-rand (SecureRandom.))

(defn rand-bytes [n]
  (let [bs (byte-array n)]
    (.nextBytes sec-rand bs)
    bs))

(defn rand-int32
  ([] (rand-int32 (Math/pow 2 31)))
  ([bound]
   {:pre [(<= bound (Math/pow 2 31))
          (> bound 0)]}
   (.nextInt sec-rand bound))
  ([lower upper]
   {:pre [(> upper lower)]}
   (let [bound (- upper lower)
         result (rand-int32 bound)]
     (+ result lower))))

(defn rand-uuid []
  ;; randomUUID uses a CSPRNG, according to Java docs
  (java.util.UUID/randomUUID))
