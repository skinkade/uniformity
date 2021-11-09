(defproject io.github.skinkade/uniformity "0.3.1"
  :description "A Clojure(Script) library for easy-to-use cryptography"
  :url "https://github.com/skinkade/uniformity"
  :license {:name "EPL-2.0 OR GPL-2.0-or-later WITH Classpath-exception-2.0"
            :url "https://www.eclipse.org/legal/epl-2.0/"}
  :dependencies [[org.clojure/clojure "1.10.1"]
                 [org.clojure/core.async "1.3.618"]
                 [commons-codec/commons-codec "1.15"]
                 [org.clojure/data.json "2.4.0"]
                 [clojure-msgpack "1.2.1"]
                 [org.clojars.akiel/async-error "0.3"]]
  :repl-options {:init-ns uniformity.random})
