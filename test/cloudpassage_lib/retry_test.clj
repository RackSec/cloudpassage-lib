(ns cloudpassage-lib.retry-test
  (:require [clojure.test :refer :all]
            [manifold.deferred :as md]
            [manifold.time :as mt]
            [clojure.math.numeric-tower :as math]
            [cloudpassage-lib.test-utils :refer [use-atom-log-appender!]]
            [cloudpassage-lib.retry :as retry]))

(deftest exponentially-tests
  (testing "returns a function that will raise the wait period to the number of failures"
    (let [f (retry/exponentially 10)]
      (is (= 1 (f [])))
      (is (= 10 (f [:a])))
      (is (= 1000 (f [:a :b :c]))))))

(deftest up-to-tests
  (testing "raises most recent exception when number of tries exceeded"
    (let [tries [(Exception. "earlier")
                 (Exception. "recent")]
          stop 2
          retry? #(throw (Exception. "I shouldn't have been called"))
          f (retry/up-to stop retry?)]
      (is (thrown-with-msg?
           Exception
           #"recent"
           (f tries)))))
  (testing "returns the result of retry when number of tries less than max"
    (let [tries []
          retry? (constantly :success)
          stop 2
          f (retry/up-to stop retry?)]
      (is (= :success (f tries))))))

(deftest retry-exp-backoff-tests
  (testing "retries until stop is reached and re-throws last exception"
    (let [c (mt/mock-clock)
          attempts (atom 0)
          p 4
          exc "explosion"
          f (fn []
              (swap! attempts inc)
              (let [d (md/deferred)]
                (md/error! d (Exception. exc))
                d))
          stop 3]
      (mt/with-clock c
        (let [log (use-atom-log-appender!)
              ret (retry/retry-exp-backoff f p stop)]
          (is (= 1 @attempts))

          (mt/advance c (mt/seconds p))
          (is (= 2 @attempts))

          (mt/advance c (mt/seconds (* p p)))
          (is (= 3 @attempts))
          (is (thrown-with-msg? Exception #"explosion" @ret))))))
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
        (let [ret (retry/retry-exp-backoff f p stop)]
          (mt/advance c 1)
          (is (= v @ret)))))))
