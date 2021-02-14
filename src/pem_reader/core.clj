(ns pem-reader.core
  (:refer-clojure :exclude [read])
  (:require [pem-reader.readers
             [pkcs1 :refer [read-pkcs1-spec]]]
            [pem-reader
             [parse :refer [parse-pem]]
             [rsa :as rsa]]
            [clojure.java.io :as io])
  (:import [java.security.spec
            PKCS8EncodedKeySpec
            X509EncodedKeySpec]
           [java.security.cert
            CertificateFactory]))

;; ## Readers

(defn- gen-x509-certificate
  [bytes]
  (with-open [in (io/input-stream bytes)]
    (let [factory (CertificateFactory/getInstance "X.509")]
      {:type        :x509-certificate
       :certificate (.generateCertificate factory in)})))

(defn- gen-x509-public-key
  [bytes]
  (let [spec (X509EncodedKeySpec. bytes)]
    {:type       :x509-public-key
     :public-key (rsa/as-public-key spec)}))

(defn- gen-pkcs8
  [bytes]
  (let [spec (PKCS8EncodedKeySpec. bytes)]
    {:type        :pkcs8
     :private-key (rsa/as-private-key spec)}))

(defn- gen-pkcs1
  [bytes]
  (let [{:keys [private public]} (read-pkcs1-spec bytes)]
    {:type        :pkcs1
     :public-key  (rsa/as-public-key public)
     :private-key (rsa/as-private-key private)}))


;; ## Read Function

(defn read
  "Read a PEM file. The following formats (identified by the PEM's `BEGIN`
   block) are supported:

   - PKCS#1 (`RSA PRIVATE KEY`)
   - PKCS#8 (`PRIVATE KEY`)
   - X509 Public Key (`PUBLIC KEY`)
   - X509 Certificate (`CERTIFICATE`)

   The result will be a map with `:type` being one of `:pkcs1`, `:pkcs8`,
   `:x509-public-key` or `:x509-certificate` and additional, type-specific
   data."
  [file]
  (with-open [in (io/input-stream file)]
    (let [{:keys [type bytes]} (parse-pem in)]
      (case type
        :rsa-private-key (gen-pkcs1 bytes)
        :private-key     (gen-pkcs8 bytes)
        :certificate     (gen-x509-certificate bytes)
        :public-key      (gen-x509-public-key bytes)
        (throw
          (IllegalArgumentException.
            (format "Cannot read PEMs of type '%s'" type)))))))
