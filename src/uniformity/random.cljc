(ns uniformity.random
  (:require [clojure.set :refer [intersection]]
            [clojure.string :as string]
            [uniformity.internals.validation :refer [compat-count]]
            [uniformity.util :as util]
            #?(:clj [uniformity.internals.rand-java :as internals]
               :cljs [uniformity.internals.rand-js :as internals])))

(defn rand-bytes
  "Generate an array of n cryptographically random bytes"
  ^bytes [n]
  {:pre [(> n 0)]}
  (internals/rand-bytes n))

(defn rand-int32
  "Returns a value between -2^31 and 2^31, exclusive of upper bound.
  When called with no argument, or one argument for upper bound,
  defaults to a lower bound of 0."
  ([] (int (internals/rand-int32)))
  ([max] (int (internals/rand-int32 max)))
  ([min max]
   {:pre [(>= min (Math/pow -2 31))
          (<= max (Math/pow 2 31))
          (> max min)]}
   (int (internals/rand-int32 min max))))

(defn rand-bool
  "Returns a cryptographically random boolean"
  ^Boolean []
  (= 1 (rand-int32 2)))

(defn rand-hex-string
  "Generates hex-encoded string of n bytes"
  [n]
  {:pre [(> n 0)]}
  (util/hex-encode (rand-bytes n)))

(defn rand-base64-string
  "Generates base64-encoded string of n bytes"
  [n]
  {:pre [(> n 0)]}
  (util/base64-encode (rand-bytes n)))

(defn rand-web-token
  "Generates URL-safe base64-encoded string of n bytes"
  [n]
  {:pre [(> n 0)]}
  (util/base64-encode-urlsafe (rand-bytes n)))

(defn rand-uuid
  "Generates a cryptographically random UUIDv4"
  []
  (internals/rand-uuid))

(defn rand-selection
  "Returns a cryptographically random element from a collection, or a character from a string.
  Can take a count as the second argument to return a sequence of selections."
  ([coll]
   {:pre [(> (compat-count coll) 0)
          (or (coll? coll) (string? coll))]}
   (nth coll (rand-int32 (compat-count coll))))
  ([coll n] (repeatedly n #(rand-selection coll))))

(defn rand-shuffle
  "Shuffles a collection in cryptographically random manner."
  [coll]
  {:added "0.2.1"
   :pre [(or
          (list? coll)
          (vector? coll))
         (> (count coll) 1)]}
  (letfn [(durstenfeld [coll i]
            (if (> 0 i)
              coll
              (let [j (rand-int32 (inc i))
                    i-ele (nth coll i)
                    j-ele (nth coll j)
                    updated (-> coll
                                (assoc i j-ele)
                                (assoc j i-ele))]
                (recur updated (dec i)))))]
    (let [coll (vec coll)]
      (durstenfeld coll
                   (dec (count coll))))))

(defn rand-password
  "Generates password, either from a character mask (provided as string), or a collection of mask option keywords.
  Mask options:
    :upper adds A-Z
    :lower adds a-z
    :digits adds 0-9
    :special adds !@#$%^&*-_+=
    :non-ambiguous removes O01Il"
  ([length mask-or-opts]
   {:pre [(> length 0)
          (> (compat-count mask-or-opts) 0)
          (or
           (string? mask-or-opts)
           (and
            (coll? mask-or-opts)
            (seq
             (intersection
              (set mask-or-opts)
              #{:upper :lower :digits :special}))))]}
   (if (string? mask-or-opts)
     (let [mask mask-or-opts] (apply str (rand-selection mask length)))
     (let [opts (set mask-or-opts)
           mask (reduce str [(when (contains? opts :upper) "ABCDEFGHIJKLMNOPQRSTUVWXYZ")
                             (when (contains? opts :lower) "abcdefghijklmnopqrstuvwxyz")
                             (when (contains? opts :digits) "0123456789")
                             (when (contains? opts :special) "!@#$%^&*-_+=")])]
       (if (contains? opts :non-ambiguous)
         (rand-password length (string/replace mask #"[O01Il]" ""))
         (rand-password length mask))))))

(defn rand-passphrase
  "Generates passphrase from a wordlist, optionally taking delimiter (defaults to -)."
  ([length wordlist] (rand-passphrase length wordlist "-"))
  ([length wordlist delimiter]
   {:pre [(> length 0)
          (and (coll? wordlist) (> (compat-count wordlist) 0))
          (or (string? delimiter) (char? delimiter))]}
   (string/join delimiter (rand-selection wordlist length))))
