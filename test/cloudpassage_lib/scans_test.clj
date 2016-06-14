(ns cloudpassage-lib.scans-test
  (:require
   [cloudpassage-lib.scans :as scans]
   [cloudpassage-lib.core :as cpc :refer [cp-date-formatter]]
   [cloudpassage-lib.test-utils :refer [use-atom-log-appender!]]
   [clj-time.format :as tf]
   [clj-time.core :as t :refer [hours ago within?]]
   [clojure.string :as str]
   [clojure.test :refer [deftest testing is are]]
   [manifold.deferred :as md]
   [manifold.stream :as ms]
   [manifold.time :as mt]
   [cemerick.url :as u]))

(deftest scans-url-tests
  (are [opts expected] (= expected (#'scans/scans-url opts))
    {"modules" "fim"}
    "https://api.cloudpassage.com/v1/scans?modules=fim"

    {"modules" "fee,fie,foe,fim"}
    "https://api.cloudpassage.com/v1/scans?modules=fee%2Cfie%2Cfoe%2Cfim"

    {"modules" ["fee" "fie" "foe" "fim"]}
    "https://api.cloudpassage.com/v1/scans?modules=fee%2Cfie%2Cfoe%2Cfim")
  (testing "with specified base URL"
    (are [url opts expected-query] (= expected-query
                                      (-> (#'scans/scans-url url opts)
                                          u/url
                                          :query))
      "https://api.cloudpassage.com/v1/scans?since=2016-01-01"
      {"modules" "fim"}
      {"modules" "fim"
       "since" "2016-01-01"})))

(deftest scan-server-url-tests
  (is (= "https://api.cloudpassage.com/v1/servers/server-id/svm"
         (#'scans/scan-server-url "server-id" "svm"))))

(deftest get-page-retry!-tests
  (let [fake-get (fn [token uri]
                   (md/success-deferred :cloudpassage-lib.core/fetch-error))]
    (with-redefs [cpc/get-single-events-page! fake-get]
      (testing "Throws an exception after three retries"
        (let [c (mt/mock-clock 0)
              timeout 2
              num-retries 3
              total-time 14  ;; 2 + 4 + 8
              log (use-atom-log-appender!)]
          (mt/with-clock c
            (let [response (#'scans/get-page-retry! '_ '_ num-retries timeout)]
              (mt/advance c (* 1000 total-time))  ;; mt/clock needs millis
              (is (thrown-with-msg?
                   Exception
                   #"No more retries\."
                   @response))))
          (is (= (inc num-retries) (count @log)))
          (doseq [logline @log]
            (is (str/includes? logline "Couldn't fetch page.")))))
      (testing "Exception thrown in report isn't handled by manifold"
        (with-redefs [cpc/fetch-token! (constantly "yay")]
          (let [log (use-atom-log-appender!)]
            (is (thrown-with-msg?
                 Exception
                 #"Report failed to generate"
                 (dorun (vec (scans/fim-report! '_ '_))))) ;; make lazyseq eval
            (is (str/includes?
                 (last @log)
                 "Report failed to generate; aborting.")))))))
  (testing "Doesn't retry on good response"
    (let [scan {:scan-id 1 :module "fim"}
          fake-get (fn [token uri]
                     (md/success-deferred scan))]
      (with-redefs [cpc/get-single-events-page! fake-get]
        (let [log (use-atom-log-appender!)
              ;; Returns instantly since no retries are necessary
              response @(#'scans/get-page-retry! '_ '_ 3 3000)]
          (is (= scan response))
          (is (= 0 (count @log))))))))

(defn ^:private index->module
  "Given an index of a (fake, test-only) scan, return a module for that scan."
  [i]
  (case (mod i 3)
    0 "fim"    ;; file integrity management
    1 "svm"    ;; software version management
    2 "ccm"))  ;; configuration change management

(def ^:private fake-pages 3)
(def ^:private scans-per-page 5)
(def ^:private details-query-url
  (#'scans/scans-url {"details" "true"}))

(defn ^:private fake-scans-page
  "Returns a paginated map, similar to what get-page! returns for top-level
   queries."
  [page-num next-page]
  {:scans (for [index-in-page (range scans-per-page)
                :let [scan-index (+ (* scans-per-page (dec page-num))
                                    index-in-page)]]
            {:scan-id scan-index
             :module (index->module scan-index)
             :url details-query-url})
   :pagination {:next next-page}})

(defn ^:private fake-details-page
  "Returns a simple map with scan details, similar to what get-page! returns
   for a details-level query."
  []
  {:scan-id "0"
   :module "fim"
   :url details-query-url
   :scan {}})

(defn ^:private fake-get-page!
  "Returns two kinds of fake pages. If a 'details' query is specified, returns
   a page with the map with keys [scan-id module url scan] and some default
   values.

   Otherwise, returns a paginated query result with various module types.

   The only valid credentials are the account:secret pair 'lvh:hunter2'."
  [client-id client-secret url]
  (is (= "lvh" client-id))
  (is (= "hunter2" client-secret))
  (let [parsed-url (u/url url)
        query (:query parsed-url)
        page-num (-> query
                     (get "next" "1")
                     Integer/parseInt)
        next-page (if (< page-num fake-pages)
                    (str (assoc-in parsed-url [:query "next"] (inc page-num)))
                    "")]
    (when-some [since (query "since")]
      (let [since (tf/parse cp-date-formatter since)
            fudged (t/interval (-> 4 hours ago) (-> 3 hours ago))]
        (is (within? fudged since))))
    (if (query "details")
      (fake-details-page)
      (fake-scans-page page-num next-page))))

(deftest scans!-tests
  (testing "Successful scan with pagination."
    (with-redefs [scans/get-page! fake-get-page!]
      (let [scans-stream (scans/scans! "lvh" "hunter2" {"modules" "fim"})
            scans (ms/stream->seq scans-stream)]
        (is (= (for [scan-id (range (* fake-pages scans-per-page))]
                 {:scan-id scan-id
                  :module (index->module scan-id)
                  :url details-query-url})
               scans))
        (is (ms/closed? scans-stream))))))

(deftest resources-with-details!-tests
  (testing "Typical scan returns expected page details."
    (with-redefs [scans/get-page! fake-get-page!]
      (let [scans-stream (scans/scans! "lvh" "hunter2" {"modules" "fim"})
            scans-with-details
            (scans/resources-with-details! "lvh" "hunter2"
                                           :scan :scan scans-stream)
            scans (ms/stream->seq scans-with-details)]
        (is (= (for [scan-id (range (* fake-pages scans-per-page))]
                 {:scan-id scan-id
                  :module (index->module scan-id)
                  :url details-query-url
                  :scan {}})
               scans))
        (is (ms/closed? scans-stream))
        (is (ms/closed? scans-with-details)))))
  (testing "Blank input stream won't block."
    (let [empty-stream (ms/stream 0)]
      (ms/close! empty-stream)
      (->> empty-stream
           (scans/resources-with-details! '_ '_ :_ :_)
           ms/stream->seq
           doall))))

(defn ^:private parse-fake-request
  [client-id client-secret url]
  (is (= "lvh" client-id))
  (is (= "hunter2" client-secret))
  (let [parsed-url (u/url url)
        path (:path parsed-url)
        query (:query parsed-url)
        page-num (-> query (get "page" "1") Integer/parseInt)]
    {:page-num page-num :path path}))

(deftest list-servers!-tests
  (testing "Returns all servers if paginated call is OK."
    (with-redefs [scans/get-page!
                  (fn [client-id client-secret url]
                    (let [{:keys [page-num path]}
                          (parse-fake-request client-id client-secret url)]
                      (is (= "/v1/servers" path))
                      (case page-num
                        1 {:servers [{:id "server-id-1"} {:id "server-id-2"}]
                           :pagination
                           {:next (str @#'scans/base-servers-url "?page=2")}}
                        2 {:servers [{:id "server-id-3"}]})))]
      (let [server-stream (scans/list-servers! "lvh" "hunter2")
            id-list (map :id (ms/stream->seq server-stream))]
        (is (= ["server-id-1" "server-id-2" "server-id-3"] id-list))
        (is (ms/closed? server-stream))))))

(deftest scan-each-server!-tests
  (testing "Scan can handle an empty stream."
    (let [input (ms/stream)]
      (ms/close! input)
      (let [scan-stream (scans/scan-each-server! "lvh" "hunter2" "svm" input)
            scan-result (ms/stream->seq scan-stream)]
        (is (empty? scan-result)))))
  (testing "Returns results of multiple server scans as a seq"
    (with-redefs [scans/get-page!
                  (fn [client-id client-secret url]
                    (let [{:keys [path]}
                          (parse-fake-request client-id client-secret url)]
                      (case path
                        "/v1/servers/server-1/svm" :one
                        "/v1/servers/server-2/svm" :two
                        "/v1/servers/server-3/svm" :three)))]
      ;; note - if the input-stream's buffer is too small; then this test will
      ;; fail. `put-all` must be able to place all elements in the stream''
      ;; buffer size is set to 2, as it will be able to fill up with 3 elements
      (let [input (ms/stream 2)]
        (ms/put-all! input [{:id "server-1"} {:id "server-2"} {:id "server-3"}])
        (ms/close! input)
        (let [scan-result (ms/stream->seq
                           (scans/scan-each-server! "lvh" "hunter2" "svm" input))]
          (is (= [:one :two :three] scan-result)))))))

(defn ^:private test-report
  [report-fn! expected-module]
  (with-redefs [scans/get-page!
                (fn [client-id client-secret url]
                  (let [{:keys [page-num path]}
                        (parse-fake-request client-id client-secret url)]
                    (cond
                      ;; fetch the servers
                      (= path "/v1/servers")
                      {:servers [{:id "server-id-1"}]}

                      ;; fetch the report for the server
                      (= path (str "/v1/servers/server-id-1/" expected-module))
                      {:id "1" :scan {:i_was_a_snake_cased_keyword 42}})))]

    (let [report (report-fn! "lvh" "hunter2")]
      (is (= '({:id "1" :scan {:i-was-a-snake-cased-keyword 42}}) report)))))

(deftest fim-report!-tests
  (test-report scans/fim-report! "fim"))

(deftest svm-report!-tests
  (test-report scans/svm-report! "svm"))

(deftest sca-report!-tests
  (test-report scans/sca-report! "sca"))
