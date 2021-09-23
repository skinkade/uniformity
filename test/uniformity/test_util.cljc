(ns uniformity.test-util
  (:require #?(:clj [clojure.core.async :refer [<!!]]
               :cljs [cljs.core.async :refer [take!]])
            #?(:cljs [cljs.test :refer [async]])))

(defn test-async
  "Asynchronous test awaiting ch to produce a value or close."
  [ch]
  #?(:clj
     (<!! ch)
     :cljs
     (async done
            (take! ch (fn [_] (done))))))
