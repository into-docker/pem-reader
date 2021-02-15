(ns ^:no-doc pem-reader.parse
  (:require [clojure.string :as string]
            [clojure.data.codec.base64 :as b64]))

;; ## Pattern for PEM files

(def ^:private +pem-pattern+
  #"^\s*-{5}BEGIN (.+)-{5}\s+([a-zA-Z0-9-_/+\s=]+)\s+-{5}END (.+)-{5}\s*$")

;; ## Helpers

(defn- read-type
  "Keywordize the PEM/key type."
  [v]
  (-> v
      (string/lower-case)
      (string/replace #"[\s_]+" "-")
      (keyword)))

(defn- decode-base64
  "Read the Base64 encoded key byte array."
  [^String base64-data]
  (-> base64-data
      (string/replace #"\s+" "")
      (.getBytes "UTF-8")
      (b64/decode)))

;; ## Parse

(defn parse-pem
  "Parse PEM file, creating a map of `:type` (content type) and `:bytes`
  (decoded content as byte array)."
  [in]
  (let [data (slurp in :encoding "UTF-8")]
    (or (when-let [[_ begin base64-data end] (re-find +pem-pattern+ data)]
          (assert (= begin end) "BEGIN and END block do not match.")
          {:type   (read-type begin)
           :bytes  (decode-base64 base64-data)})
        (throw
         (IllegalArgumentException.
           "Not in PEM format!")))))
