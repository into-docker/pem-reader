(ns pem-reader.core
  (:refer-clojure :exclude [read type])
  (:require [pem-reader.readers.pkcs1 :refer [read-pkcs1-spec]]
            [clojure.java.io :as io]
            [clojure.data.codec.base64 :as b64]
            [clojure.string :as string])
  (:import [java.security KeyFactory]
           [java.security.spec
            PKCS8EncodedKeySpec
            X509EncodedKeySpec]
           [javax.security.cert
            X509Certificate]))

;; ## Protocol + Implementation

(defprotocol ReadablePEM
  "Protocol for a read PEM file."
  (type [_]
    "Keyword identifying the key type, generated from the PEM's `BEGIN` block,
     e.g. `:rsa-private-key` for `RSA PRIVATE KEY`.")
  (private-key [_]
    "Get the key as an instance of `java.security.PrivateKey`.")
  (public-key [_]
    "Get the key as an instance of `java.security.PublicKey`."))

(defprotocol ByteConvert
  (as-bytes [_]))

(deftype PEM [type private-key public-key]
  ReadablePEM
  (type [_]
    type)
  (private-key [_]
    private-key)
  (public-key [_]
    public-key)

  ByteConvert
  (as-bytes [_]
    (.getEncoded (or private-key public-key))))

(extend-protocol ByteConvert
  java.security.PrivateKey
  (as-bytes [k]
    (.getEncoded k))

  java.security.PublicKey
  (as-bytes [k]
    (.getEncoded k)))

;; ## Helpers

(def ^:private +pem-pattern+
  #"^\s*-{5}BEGIN (.+)-{5}\s+([a-zA-Z0-9-_/+\s=]+)\s+-{5}END (.+)-{5}\s*$")

(defmacro ^:private spec->key-data
  "Generate the key byte array from a KeySpec using the given algorithm and
   lookup method."
  [algorithm spec which]
  `(let [spec# ~spec
         kf# (KeyFactory/getInstance ~algorithm)
         which# ~which]
     {:private-key (if (which# :private) (.generatePrivate kf# spec#))
      :public-key  (if (which# :public) (.generatePublic kf# spec#))}))

(defn- rsa-key
  "Generate an RSA private key from the given KeySpec."
  [spec which]
  (spec->key-data "RSA" spec which))

;; ## Reader Logic

(defn- read-type
  "Keywordize the PEM/key type."
  [v]
  (-> v
      (string/lower-case)
      (string/replace #"[\s_]+" "-")
      (keyword)))

(defn- read-key-bytes
  "Read the Base64 encoded key byte array."
  [^String private-key]
  (-> private-key
      (string/replace #"\s+" "")
      (.getBytes "UTF-8")
      (b64/decode)))

(defmulti read-key
  "Read key from byte array. `type` is the lowercased, keywordized value
   of the PEM's `BEGIN` block, e.g. `:rsa-private-key` for `RSA PRIVATE KEY`."
  (fn [type bytes] type))

(defmethod read-key :private-key
  [_ bytes]
  (rsa-key
    (PKCS8EncodedKeySpec. bytes)
    #{:private}))

(defmethod read-key :rsa-private-key
  [_ bytes]
  (rsa-key
    (read-pkcs1-spec bytes)
    #{:private}))

(defmethod read-key :certificate
  [_ bytes]
  (let [crt (X509Certificate/getInstance bytes)]
    {:public-key (.getPublicKey crt)}))

(defmethod read-key :public-key
  [_ bytes]
  (rsa-key
    (X509EncodedKeySpec. bytes)
    #{:public}))

(defmethod read-key :default
  [type _]
  (throw
    (IllegalArgumentException.
      (format "cannot read PEMs of type '%s'" (str type)))))

;; ## Read Function

(defn read
  "Read a PEM file. The following formats (identified by the PEM's `BEGIN`
   block) are supported:

   - PKCS#1 (`RSA PRIVATE KEY`)
   - PKCS#8 (`PRIVATE KEY`)
   - X509 Public Key (`PUBLIC KEY`)
   - X509 Certificate (`CERTIFICATE`)

   The result will implement the `pem-reader.core/ReadablePEM` protocol."
  [file]
  (with-open [in (io/input-stream file)]
    (let [data (slurp in :encoding "UTF-8")]
      (when-let [[_ begin private-key end] (re-find +pem-pattern+ data)]
        (assert (= begin end) "BEGIN and END block do not match.")
        (let [key-bytes (read-key-bytes private-key)
              key-type  (read-type begin)
              key-data       (read-key key-type key-bytes)]
          (->PEM
            key-type
            (:private-key key-data)
            (:public-key key-data)))))))
