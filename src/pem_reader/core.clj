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
  (as-bytes [_]
    "Get the key as a byte array."))

(deftype PEM [type bytes]
  ReadablePEM
  (type [_]
    type)
  (as-bytes [_]
    bytes))

;; ## Helpers

(def ^:private +pem-pattern+
  #"^\s*-{5}BEGIN (.+)-{5}\s+([a-zA-Z0-9-_/+\s=]+)\s+-{5}END (.+)-{5}\s*$")

(defmacro ^:private spec->key
  "Generate the key byte array from a KeySpec using the given algorithm and
   lookup method."
  [algorithm spec generate-method]
  `(let [spec# ~spec]
     (.. (KeyFactory/getInstance ~algorithm)
         (~generate-method spec#)
         getEncoded)))

(defn- rsa-private-key
  "Generate an RSA private key from the given KeySpec."
  [spec]
  (spec->key "RSA" spec generatePrivate))

(defn- rsa-public-key
  "Generate an RSA public key from the given KeySpec."
  [spec]
  (spec->key "RSA" spec generatePublic))

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
  (rsa-private-key
    (PKCS8EncodedKeySpec. bytes)))

(defmethod read-key :rsa-private-key
  [_ bytes]
  (rsa-private-key
    (read-pkcs1-spec bytes)))

(defmethod read-key :certificate
  [_ bytes]
  (-> (X509Certificate/getInstance bytes)
      (.getPublicKey)
      (.getEncoded)))

(defmethod read-key :public-key
  [_ bytes]
  (rsa-public-key
    (X509EncodedKeySpec. bytes)))

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
              key       (read-key key-type key-bytes)]
          (->PEM key-type key))))))
