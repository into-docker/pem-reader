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
  (let [file "test/keys/private-key.pem"
        result (pem/read file)]
    (is (= :pkcs8 (:type result)))
    (is (instance? PrivateKey (:private-key result)))
    (is (instance? PrivateKey (pem/read-private-key file)))))

(deftest t-pkcs1
  (let [file "test/keys/rsa-private-key.pem"
        result (pem/read file)]
    (is (= :pkcs1 (:type result)))
    (is (instance? PrivateKey (:private-key result)))
    (is (instance? PublicKey (:public-key result)))
    (is (instance? PrivateKey (pem/read-private-key file)))
    (is (instance? PublicKey (pem/read-public-key file)))))

(deftest t-x509-certificate
  (let [file "test/keys/certificate.pem"
        result (pem/read file)]
    (is (= :x509-certificate (:type result)))
    (is (instance? X509Certificate (:certificate result)))
    (is (instance? X509Certificate (pem/read-certificate file)))))

(deftest t-x509-public-key
  (let [file "test/keys/public-key.pem"
        result (pem/read file)]
    (is (= :x509-public-key (:type result)))
    (is (instance? PublicKey (:public-key result)))
    (is (instance? PublicKey (pem/read-public-key file)))))

(deftest t-content-mismatch
  (is (thrown-with-msg?
       AssertionError
       #"No certificate in input type: "
       (pem/read-certificate "test/keys/private-key.pem")))
  (is (thrown-with-msg?
       AssertionError
       #"No private key in input type: "
       (pem/read-private-key "test/keys/public-key.pem")))
  (is (thrown-with-msg?
       AssertionError
       #"No public key in input type: "
       (pem/read-public-key "test/keys/private-key.pem"))))

(deftest t-invalid-format
  (is (thrown-with-msg?
       IllegalArgumentException
       #"Not in PEM format!"
       (pem/read "project.clj")))
  (is (thrown-with-msg?
       AssertionError
       #"BEGIN and END block do not match"
       (pem/read
        (.getBytes "-----BEGIN X-----\nabcdef\n-----END Y-----"))))
  (is (thrown-with-msg?
       IllegalArgumentException
       #"Cannot read PEMs of type ':unknown'"
       (pem/read
        (.getBytes "-----BEGIN UNKNOWN-----\nabcdef\n-----END UNKNOWN-----")))))
