(ns ^:no-doc pem-reader.rsa
  (:import (java.security KeyFactory)
           (java.security.spec KeySpec)))

(defn as-private-key
  [^KeySpec spec]
  (let [kf (KeyFactory/getInstance "RSA")]
    (.generatePrivate kf spec)))

(defn as-public-key
  [^KeySpec spec]
  (let [kf (KeyFactory/getInstance "RSA")]
    (.generatePublic kf spec)))
