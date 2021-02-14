(defproject into-docker/pem-reader "1.0.0-SNAPSHOT"
  :description "A lightweight reader for key/certificate files"
  :url "https://github.com/xsc/pem-reader"
  :license {:name "MIT"
            :url "https://choosealicense.com/licenses/mit"
            :year 2015
            :key "mit"
            :comment "MIT License"}
  :dependencies [[org.clojure/clojure "1.10.2" :scope "provided"]
                 [org.clojure/data.codec "0.1.1"]]
  :pedantic? :abort)
