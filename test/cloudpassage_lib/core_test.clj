(ns cloudpassage-lib.core-test
  (:require [clojure.test :refer :all]
            [manifold.deferred :as md]
            [manifold.time :as mt]
            [clj-time.core :as ct]
            [cheshire.core :as json]
            [clojure.math.numeric-tower :as math]
            [clojure.string :as str]
            [cloudpassage-lib.test-utils :refer [use-atom-log-appender!]]
            [cloudpassage-lib.core :as core]))

(deftest retry-tests
  (testing "retries until stop is reached and returns error deferred"
    (let [c (mt/mock-clock)
          attempts (atom 0)
          p 4
          exc "inner explosion"
          f (fn []
              (swap! attempts inc)
              (let [d (md/deferred)]
                (md/error! d (Exception. exc))
                d))
          stop 3]
      (mt/with-clock c
        (let [log (use-atom-log-appender!)
              ret (core/retry f p stop)]
          (is (= 1 @attempts))
          (is (str/includes? (first @log) (str "Failure retrying: " exc)))

          (mt/advance c (mt/seconds p))
          (is (= 2 @attempts))
          (is (str/includes? (second @log) (str "Failure retrying: " exc)))

          (mt/advance c (mt/seconds (* p p)))
          (is (= 3 @attempts))
          (is (str/includes? (second (rest @log)) (str "Failure retrying: " exc)))
          (is (str/includes?
               (last @log)
               "Failed retrying 3 times; stopping"))
          (is (thrown-with-msg?
               Exception
               #"Failed retrying; stopping"
               @ret))))))
  (testing "returns success deferred on completion"
    (let [c (mt/mock-clock)
          v "hi"
          stop 1
          p 5
          f (fn []
              (let [d (md/deferred)]
                (md/success! d v)
                d))]
      (mt/with-clock c
        (let [ret (core/retry f p stop)]
          (mt/advance c 1)
          (is (= v @ret)))))))

(deftest get-auth-token!-tests
  (testing "returns an authentication token"
    (let [sent-at (ct/now)
          expires-at (ct/plus sent-at (ct/seconds 900))
          response {:access_token "ffad76cc550110fc4c84a18397b6e104"
                    :expires_in 900
                    :token_type "bearer"}
          fake-post (fn [_addr _opts]
                      (let [d (md/deferred)]
                        (md/success!
                         d
                         {:body (json/generate-string response)})
                        d))]
      (with-redefs [aleph.http/post fake-post
                    clj-time.core/now (fn [] sent-at)]
        (is (= response @(core/get-auth-token! "secret-key" "id"))))))
  (testing "retries getting the token and fails with a retry exception"
    (let [sent-at (ct/now)
          attempts (atom 0)
          fake-post (fn [_addr _opts]
                      (swap! attempts inc)
                      (let [d (md/deferred)]
                        (md/error! d (Exception. "401"))
                        d))
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
            (is (thrown-with-msg?
                 Exception
                 #"Failed retrying; stopping"
                 @result)))))))
  )

(deftest iso-date-tests
  (testing "it actually formats dates"
    (let [a-date (ct/date-time 1986 10 14 4 3 27 456)
          formatted (core/->cp-date a-date)]
      (is (= formatted "1986-10-14T04:03:27Z")))))

(deftest get-single-events-page!-tests
  (testing "returns ::fetch-error on exception"
    (let [fake-get (fn [_addr _headers]
                     (let [d (md/deferred)]
                       (md/error! d (Exception. "kaboom"))
                       d))]
      (with-redefs [aleph.http/get fake-get]
        (is (= :cloudpassage-lib.core/fetch-error
               @(core/get-single-events-page! "" ""))))))
  (testing "returns deserialized json body"
    (let [fake-get (fn [_addr _headers]
                     (let [d (md/deferred)]
                       (md/success! d {:body (json/generate-string {:events []})})
                       d))]
      (with-redefs [aleph.http/get fake-get]
        (is (= {:events []}
               @(core/get-single-events-page! "" "")))))))
