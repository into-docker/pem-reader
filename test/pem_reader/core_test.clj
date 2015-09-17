(ns pem-reader.core-test
  (:require [clojure.test :refer :all]
            [pem-reader.core :as pem])
  (:import [java.security PrivateKey PublicKey]))

;; Example PEMs taken from:
;;
;;    http://fm4dd.com/openssl/certexamples.htm
;;
;; (could not find a LICENSE.)

(deftest t-private-keys
  (let [k0 (pem/read "test/keys/private-key.pem")
        k1 (pem/read "test/keys/rsa-private-key.pem")]
    (is (= (pem/type k0) :private-key))
    (is (= (pem/type k1) :rsa-private-key))
    (is (nil? (pem/public-key k0)))
    (is (nil? (pem/public-key k1)))
    (is (instance? PrivateKey (pem/private-key k0)))
    (is (instance? PrivateKey (pem/private-key k1)))
    (is (= (seq (pem/as-bytes k0)) (seq (pem/as-bytes k1))))))

(deftest t-public-keys
  (let [k0 (pem/read "test/keys/public-key.pem")
        k1 (pem/read "test/keys/certificate.pem")]
    (is (= (pem/type k0) :public-key))
    (is (= (pem/type k1) :certificate))
    (is (nil? (pem/private-key k0)))
    (is (nil? (pem/private-key k1)))
    (is (instance? PublicKey (pem/public-key k0)))
    (is (instance? PublicKey (pem/public-key k1)))
    (is (= (seq (pem/as-bytes k0)) (seq (pem/as-bytes k1))))))
