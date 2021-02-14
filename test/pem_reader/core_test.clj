(ns pem-reader.core-test
  (:require [clojure.test :refer [deftest is]]
            [pem-reader.core :as pem])
  (:import (java.security PrivateKey PublicKey)
           (java.security.cert X509Certificate)))

;; Example PEMs taken from:
;;
;;    http://fm4dd.com/openssl/certexamples.htm
;;
;; (could not find a LICENSE.)

(deftest t-pkcs8
  (let [result (pem/read "test/keys/private-key.pem")]
    (is (= :pkcs8 (:type result)))
    (is (instance? PrivateKey (:private-key result)))))

(deftest t-pkcs1
  (let [result (pem/read "test/keys/rsa-private-key.pem")]
    (is (= :pkcs1 (:type result)))
    (is (instance? PrivateKey (:private-key result)))
    (is (instance? PublicKey (:public-key result)))))

(deftest t-x509-certificate
  (let [result (pem/read "test/keys/certificate.pem")]
    (is (= :x509-certificate (:type result)))
    (is (instance? X509Certificate (:certificate result)))))

(deftest t-x509-public-key
  (let [result (pem/read "test/keys/public-key.pem")]
    (is (= :x509-public-key (:type result)))
    (is (instance? PublicKey (:public-key result)))))

(deftest t-invalid-format
  (is (thrown-with-msg?
       IllegalArgumentException
       #"Not in PEM format!"
       (pem/read "project.clj")))
  (is (thrown-with-msg?
       AssertionError
       #"BEGIN and END block do not match"
       (pem/read
        (.getBytes "-----BEGIN X-----\nabcdef\n-----END Y-----")))))
