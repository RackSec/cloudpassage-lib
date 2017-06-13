(defproject cloudpassage-lib "1.1.1-SNAPSHOT"
  :description "A library for interacting with cloudpassage apis."
  :url "http://github.com/RackSec/cloudpassage-lib"
  :license {:name "Eclipse Public License"
            :url "http://www.eclipse.org/legal/epl-v10.html"}
  :dependencies [[org.clojure/clojure "1.8.0"]
                 [org.clojure/core.cache "0.6.5"]
                 [com.taoensso/timbre "4.7.4"]
                 [manifold "0.1.5"]
                 [aleph "0.4.1"]
                 [clj-time "0.12.2"]
                 [base64-clj "0.1.1"]
                 [com.taoensso/timbre "4.2.0"]
                 [banach "0.2.0"]
                 [environ "1.1.0"]
                 [cheshire "5.6.3"]
                 [camel-snake-kebab "0.4.0"]
                 [org.clojure/math.numeric-tower "0.0.4"]
                 [com.cemerick/url "0.1.1"]]
  :plugins [[lein-auto "0.1.2"]
            [lein-ancient "0.6.10"]
            [lein-cljfmt "0.3.0"]
            [jonase/eastwood "0.2.3"]
            [lein-pprint "1.1.1"]
            [lein-environ "1.0.2"]
            [lein-cloverage "1.0.9"]]
  :min-lein-version "2.0.0"
  :profiles {:dependencies [[pjstadig/humane-test-output "0.7.1"]]
             :injections [(require 'pjstadig.humane-test-output)
                          (pjstadig.humane-test-output/activate!)]})
