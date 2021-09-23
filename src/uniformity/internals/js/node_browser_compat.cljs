(ns uniformity.internals.js.node-browser-compat)

(defonce crypto-info (let [browser-crypto (resolve 'js/window.crypto)
                           ms-browser-crypto (resolve 'js/window.msCrypto)
                           js-require (resolve 'js/require)
                           crypto-type (cond js-require :node
                                             (or browser-crypto
                                                 ms-browser-crypto) :browser
                                             :else nil)
                           crypto-info {:type crypto-type}]
                       (case crypto-type
                         :browser (assoc crypto-info :crypto @(or browser-crypto
                                                                  ms-browser-crypto))
                         :node (assoc crypto-info :crypto (js-require "crypto"))
                         (throw (ex-info "Could not find entropy source"
                                         {:cause
                                          "Unable to find entropy source from one of
                                                 window.crypto, window.msCrypto,
                                                 or requiring a Node.js crypto"})))))

(defonce crypto-type (:type crypto-info))
(defonce crypto (:crypto crypto-info))