(ns uniformity.internals.validation)

(defn compat-bytes? [bytes]
  #?(:cljs (instance? js/Uint8Array bytes)
     :default (clojure.core/bytes? bytes)))

(defn compat-byte-array [bytes]
  #?(:cljs (js/Uint8Array. bytes)
     :default (clojure.core/byte-array bytes)))

(defn compat-count [coll]
  #?(:cljs (aget coll "length")
     :default (count coll)))
