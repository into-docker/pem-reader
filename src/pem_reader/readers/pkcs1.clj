(ns pem-reader.readers.pkcs1
  (:require [clojure.string :as string])
  (:import [java.security.spec RSAPrivateCrtKeySpec]))

;; ## Derivative
;;
;; Based in parts on `net.oauth.signature.pem.PEMReader`, licensed as follows:
;;
;; Copyright  (c) 1998-2009 AOL LLC.
;;
;; Licensed under the Apache License, Version 2.0  (the  "License");
;; you may not use this file except in compliance with the License.
;; You may obtain a copy of the License at
;;
;;     http://www.apache.org/licenses/LICENSE-2.0
;;
;; Unless required by applicable law or agreed to in writing, software
;; distributed under the License is distributed on an  "AS IS" BASIS,
;; WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
;; See the License for the specific language governing permissions and
;; limitations under the License.

;; ## Helpers

(defn- expected-tags
  [tag]
  (case tag
    0x02 [:integer  :primitive]
    0x10 [:sequence :constructed]))

(defn- expected-classes
  [class]
  (case class
    0x0 :universal))

(defn- bytes->integer
  ^BigInteger [bytes]
  (->> bytes (cons (byte 0)) byte-array biginteger))

(defn- format-bytes
  [bytes]
  (->> (map #(format "%02x" %) bytes)
       (partition 32 32 nil)
       (map #(string/join " " %))
       (string/join "\n")))

;; ## Reader Logic

(defn- read-length
  [[initial-octet & rst]]
  (let [long? (bit-test initial-octet 7)
        value (bit-and initial-octet 0x7f)]
    (if long?
      (let [[a b] (split-at value rst)
            length (bytes->integer a)
            actual-length (count b)]
        (assert
          (>= (count b) length)
          (format "DER: expected content of length %d, only %d available:%n%s"
                  length
                  actual-length
                  (format-bytes b)))
        [length b])
      [value rst])))

(defn- read-value
  [[classifier-octet & rst]]
  (let [class        (bit-shift-right classifier-octet 6)
        constructed? (if (bit-test classifier-octet 5)
                       :constructed
                       :primitive)
        tag          (bit-and classifier-octet 0x1f)
        [type-k c?]  (expected-tags tag)
        class-k      (expected-classes class)
        [length rst] (read-length rst)]
    (assert (= constructed? c?) "DER: primitive/constructed conflict.")
    {:type         type-k
     :content      (take length rst)
     :remaining    (drop length rst)}))

(defn- read-key-sequence
  [bytes]
  {:post [(= (count %) 9)]}
  (when (seq bytes)
    (let [{:keys [type content remaining]} (read-value bytes)]
      (assert (= type :sequence) "DER: SEQUENCE type expected.")
      (assert (empty? remaining) "DER: Only one value expected.")
      (assert (seq content) "DER: Key values expected.")
      (->> (iterate
             (fn [{:keys [type content remaining]}]
               (when-not (nil? remaining)
                 (assert (= type :integer) "DER: expected only INTEGER in SEQUENCE.")
                 (-> (some-> remaining seq read-value)
                     (assoc :value (bytes->integer content)))))
             (read-value content))
           (rest)
           (take-while identity)
           (mapv :value)))))

;; ## Key Specification

(defn read-pkcs1-spec
  "Read a PKCS#1 encoded private key into a `RSAPrivateCrtKeySpec`."
  [bytes]
  (let [[_ m e d p q e1 e2 c] (read-key-sequence bytes)]
    (RSAPrivateCrtKeySpec. m e d p q e1 e2 c)))
