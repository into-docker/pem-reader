(defproject into-docker/pem-reader "1.0.0"
  :description "A lightweight reader for key/certificate files"
  :url "https://github.com/into-docker/pem-reader"
  :license {:name "MIT"
            :url "https://choosealicense.com/licenses/mit"
            :year 2015
            :key "mit"
            :comment "MIT License"}
  :dependencies [[org.clojure/clojure "1.10.2" :scope "provided"]
                 [org.clojure/data.codec "0.1.1"]]
  :profiles {:dev
             {:global-vars {*warn-on-reflection* true}}
             :kaocha
             {:dependencies [[lambdaisland/kaocha "1.0.732"
                              :exclusions [org.clojure/spec.alpha]]
                             [lambdaisland/kaocha-cloverage "1.0.75"]]}
             :ci
             [:kaocha
              {:global-vars {*warn-on-reflection* false}}]}
  :aliases {"kaocha"    ["with-profile" "+kaocha" "run" "-m" "kaocha.runner"]
            "ci"        ["with-profile" "+ci" "run" "-m" "kaocha.runner"
                         "--reporter" "documentation"
                         "--plugin"   "cloverage"
                         "--codecov"
                         "--no-cov-html"]}
  :pedantic? :abort)
