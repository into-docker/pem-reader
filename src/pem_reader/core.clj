(ns pem-reader.core
  (:refer-clojure :exclude [read])
  (:require [pem-reader.readers
             [pkcs1 :refer [read-pkcs1-spec]]]
            [pem-reader
             [parse :refer [parse-pem]]
             [rsa :as rsa]]
            [clojure.java.io :as io])
  (:import (java.security
            KeyPair
            PrivateKey
            PublicKey)
           (java.security.spec
            PKCS8EncodedKeySpec
            X509EncodedKeySpec)
           (java.security.cert
            CertificateFactory
            X509Certificate)))

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
  "Read a PEM input. The following formats (identified by the PEM's `BEGIN`
   block) are supported:

   - PKCS#1 (`RSA PRIVATE KEY`)
   - PKCS#8 (`PRIVATE KEY`)
   - X509 Public Key (`PUBLIC KEY`)
   - X509 Certificate (`CERTIFICATE`)

   The result will be a map with `:type` being one of `:pkcs1`, `:pkcs8`,
   `:x509-public-key` or `:x509-certificate` and additional, type-specific
   data."
  [input]
  (with-open [in (io/input-stream input)]
    (let [{:keys [type bytes]} (parse-pem in)]
      (case type
        :rsa-private-key (gen-pkcs1 bytes)
        :private-key     (gen-pkcs8 bytes)
        :certificate     (gen-x509-certificate bytes)
        :public-key      (gen-x509-public-key bytes)
        (throw
          (IllegalArgumentException.
            (format "Cannot read PEMs of type '%s'" type)))))))

;; ## Syntactic Sugar

(defn read-certificate
  "Read an `X509Certificate` from the given input. Will throw an
  `AssertionError` if the input does not contain a certificate."
  ^X509Certificate [input]
  (let [{:keys [type certificate]} (read input)]
    (assert (some? certificate) (str "No certificate in input type: " type))
    certificate))

(defn read-private-key
  "Read a `PrivateKey` from the given input. Will throw an `AssertionError` if
   the input does not contain a private key."
  ^PrivateKey [input]
  (let [{:keys [type private-key]} (read input)]
    (assert (some? private-key) (str "No private key in input type: " type))
    private-key))

(defn read-public-key
  "Read a `PublicKey` from the given input. Will throw an `AssertionError` if
   the input does not contain a public key."
  ^PublicKey [input]
  (let [{:keys [type public-key]} (read input)]
    (assert (some? public-key) (str "No public key in input type: " type))
    public-key))

(defn read-key-pair
  "Read a `KeyPair` from the given input. Will throw an `AssertionError` if
   the input does not contain a private key.

   Note that the key pair might not contain a public key (e.g. in the case of
   PKCS#8 input)."
  ^KeyPair [input]
  (let [{:keys [type private-key public-key]} (read input)]
    (assert (some? private-key) (str "No private key in input type: " type))
    (KeyPair. ^PublicKey public-key ^PrivateKey private-key)))
