(ns cloudpassage-lib.core-test
  (:require [clojure.test :refer :all]
            [manifold.deferred :as md]
            [manifold.time :as mt]
            [clj-time.core :as ct]
            [cheshire.core :as json]
            [environ.core :refer [env]]
            [cloudpassage-lib.core :as core]
            [cloudpassage-lib.test-utils :refer [use-atom-log-appender!]]))

(deftest no-redis-vars-test
  (testing "Die when redis environment variables are not defined"
    (let [exited (atom false)]
      (with-redefs [env (dissoc env :redis-url :redis-timeout)
                    com.gfredericks.system-slash-exit/exit
                    ;; System/exit must be faked with an exception; otherwise
                    ;; execution will not halt
                    (fn [_] (reset! exited true)
                      (throw (Exception. "boom dead")))]
        (let [log (use-atom-log-appender!)]
          (is (thrown-with-msg? Exception #"boom dead"
                                (core/redis-connection)))
          (is (clojure.string/includes?
               (first @log)
               "REDIS_URL and REDIS_TIMEOUT environment vars must be defined"))
          (is (= true @exited)))))))

(deftest get-auth-token!-tests
  (testing "returns an authentication token"
    (let [sent-at (ct/now)
          expires-at (ct/plus sent-at (ct/seconds 900))
          response {:access_token "ffad76cc550110fc4c84a18397b6e104"
                    :expires_in 900
                    :token_type "bearer"}
          fake-post (fn [_addr _opts]
                      (md/success-deferred {:body (json/generate-string response)}))]
      (with-redefs [aleph.http/post fake-post
                    clj-time.core/now (fn [] sent-at)]
        (is (= response @(core/get-auth-token! "secret-key" "id"))))))
  (testing "retries getting the token and fails with the last exception"
    (let [sent-at (ct/now)
          attempts (atom 0)
          fake-post (fn [_addr _opts]
                      (swap! attempts inc)
                      (md/error-deferred (Exception. "401")))
          c (mt/mock-clock)]
      (with-redefs [aleph.http/post fake-post
                    clj-time.core/now (fn [] sent-at)]
        (mt/with-clock c
          (let [result (core/get-auth-token! "secret-key" "id")]
            (is (= 1 @attempts))

            (mt/advance c (mt/seconds 4))
            (is (= 2 @attempts))

            (mt/advance c (mt/seconds 16))
            (is (= 3 @attempts))
            (is (thrown-with-msg? Exception #"401" @result))))))))

(deftest iso-date-tests
  (testing "it actually formats dates"
    (let [a-date (ct/date-time 1986 10 14 4 3 27 456)
          formatted (core/->cp-date a-date)]
      (is (= "1986-10-14T04:03:27Z" formatted)))))

(deftest get-single-events-page!-tests
  (testing "returns ::fetch-error on exception"
    (let [fake-get (fn [_addr _headers]
                     (md/error-deferred (Exception. "kaboom")))]
      (with-redefs [aleph.http/get fake-get]
        (is (= :cloudpassage-lib.core/fetch-error
               @(core/get-single-events-page! "" ""))))))
  (testing "returns deserialized json body"
    (let [fake-get (fn [_addr _headers]
                     (md/success-deferred {:body (json/generate-string {:events []})}))]
      (with-redefs [aleph.http/get fake-get]
        (is (= {:events []}
               @(core/get-single-events-page! "" "")))))))
