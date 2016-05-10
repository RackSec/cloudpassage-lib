(ns cloudpassage-lib.redis-test
  (:require [clojure.test :refer :all]
            [clj-time.core :as ct]
            [clj-time.coerce :as c]
            [taoensso.carmine :as car]
            [fernet.core :as fernet]
            [cloudpassage-lib.core :as core]
            [manifold.deferred :as md]))

(defn ^:private flush-redis! []
  (core/wcar* (car/flushall)))

(deftest fetch-token!-tests
  (let [fernet-key (fernet/generate-key)
        succeed-get-fake-token (fn [t]
                                 (let [d (md/deferred)]
                                   (md/success! d t)
                                   d))]
    (testing "encrypts new api token with fernet"
      (let [client-id "client-id"
            token-key (str "account-" client-id)
            called (atom false)
            fake-token {:expires_in 900
                        :token_type "bearer"
                        :access_token "12"}
            expected-token (:access_token fake-token)
            get-token (fn [_ _] (succeed-get-fake-token fake-token))]
        (with-redefs [core/get-auth-token! get-token]
          (flush-redis!)
          ;; this sets and returns the token.
          ;; a side effect is the token being stored in redis
          (core/fetch-token! client-id "unused secret" fernet-key)
          (is (not= fake-token (core/wcar* (car/get token-key)))
              "plaintext not stored in redis")
          (is (= "12" (core/fetch-token! client-id "unused secret" fernet-key))
              "returns the plaintext access token"))))
    (testing "returns cached token when present"
      (let [client-id "client-id"
            token-key (str "account-" client-id)
            called (atom false)
            fake-token {:expires_in 900
                        :token_type "bearer"
                        :access_token "12"}
            expected-token (:access_token fake-token)
            encrypted-token (fernet/encrypt-string fernet-key expected-token)
            get-fake-token (fn [_ _] (reset! called true))]
        (with-redefs [core/get-auth-token! get-fake-token]
          (flush-redis!)
          (core/wcar* (car/set token-key encrypted-token))
          (is (= expected-token (core/fetch-token! client-id "unused-secret" fernet-key)))
          (is (false? @called)))))
    (testing "expires token after expiration"
      (let [client-id "client-id"
            token-key (str "account-" client-id)
            fake-token {:expires_in 101
                        :token_type "bearer"
                        :access_token "12"}
            get-token (fn [_ _] (succeed-get-fake-token fake-token))]
        (with-redefs [core/get-auth-token! get-token]
          (flush-redis!)
          ;; cause the caching side-effect
          (core/fetch-token! client-id "unused-secret" fernet-key)
          ;; the token should have been purged from redis as its ttl was 1
          ;; wait a real second for redis to purge the key. This is gross
          ;; but is the only real way to test the interaction with redis.
          (Thread/sleep 1000)
          (is (nil? (core/wcar* (car/get token-key)))))))
    (testing "sets expiration of token to 100 seconds less than actual"
      (let [client-id "client-id"
            token-key (str "account-" client-id)
            fake-token {:expires_in 900
                        :token_type "bearer"
                        :access_token "12"}
            get-token (fn [_ _] (succeed-get-fake-token fake-token))]
        (with-redefs [core/get-auth-token! get-token]
          (flush-redis!)
          ;; cause the caching side-effect
          (core/fetch-token! client-id "unused-secret" fernet-key)
          ;; this might not be a good assertion; as the test could
          ;; hang, and cause the assertion to fail.
          (is (= 800 (core/wcar* (car/ttl token-key)))))))
    (testing "fetches new token when needed"
      (let [client-id "clientid"
            token-key (str "account" client-id)
            fake-token {:expires_in 900
                        :token_type "bearer"
                        :access_token "12"}
            expected-token (:access_token fake-token)
            get-token (fn [_ _] (succeed-get-fake-token fake-token))]
        (with-redefs [core/get-auth-token! get-token]
          (flush-redis!)
          ;; there is no token in redis
          (is (nil? (core/wcar* (car/get token-key)))
              "the key is not in redis")
          (is (= expected-token (core/fetch-token! client-id "unused-secret" fernet-key))
              "returns the token provided by the fake http call"))))))
