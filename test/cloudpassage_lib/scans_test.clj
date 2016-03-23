(ns cloudpassage-lib.scans-test
  (:require
   [cloudpassage-lib.scans :as scans]
   [cloudpassage-lib.core :refer [cp-date-formatter]]
   [clj-time.format :as tf]
   [clj-time.core :as t :refer [millis hours ago within?]]
   [clojure.test :refer [deftest testing is are]]
   [manifold.stream :as ms]
   [manifold.deferred :as md]
   [cemerick.url :as u]
   [camel-snake-kebab.core :as cskc]
   [camel-snake-kebab.extras :as cske]
   [taoensso.timbre :as timbre :refer [info spy]]))

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

(deftest scans-detail-url-tests
  (is (= "https://api.cloudpassage.com/v1/scans/abcdef"
         (#'scans/scans-detail-url "abcdef")))
  (is (= "https://abc.com/v1/scans/abcdef"
         (#'scans/scans-detail-url "https://abc.com/" "abcdef"))))

(deftest finding-detail-url-tests
  (is (= "https://api.cloudpassage.com/v1/scans/abcdef/findings/xyzzy"
         (#'scans/finding-detail-url "abcdef" "xyzzy")))
  (is (= "https://abc.com/v1/scans/abcdef/findings/xyzzy"
         (#'scans/finding-detail-url "https://abc.com/" "abcdef" "xyzzy"))))

(deftest scan-server-url-tests
  (is (= "https://api.cloudpassage.com/v1/servers/server-id/svm"
         (#'scans/scan-server-url "server-id" "svm"))))

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
  (is (= client-id "lvh"))
  (is (= client-secret "hunter2"))
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

(defn ^:private fake-get-page-with-snakes
  "Return snake-cased versions of what is returned by `fake-get-page`"
  [client-id client-secret url]
  (cske/transform-keys
   cskc/->snake_case_keyword
   (fake-get-page! client-id client-secret url)))

(defn ^:private fake-get-page-with-bad-response!
  "Like fake-get-page, but returns a bad status code."
  [client-id client-secret url]
  (is (= client-id "lvh"))
  (is (= client-secret "hunter2"))
  :cloudpassage-lib.core/fetch-error)

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
        (is (ms/closed? scans-stream)))))
  (testing "If an error occurs an empty result is returned."
    ;;TODO: Replacing the error thing to detect it was logged might be helpful.
    (with-redefs [scans/get-page! fake-get-page-with-bad-response!]
      (let [scans-stream (scans/scans! "lvh" "hunter2" {"modules" "fim"})
            result (clojure.string/join "" (ms/stream->seq scans-stream))]
        (is (ms/drained? scans-stream))
        (is (ms/closed? scans-stream))
        (is (= result ""))))))

(deftest scans-with-details!-tests
  (testing "Typical scan returns expected page details."
    (with-redefs [scans/get-page! fake-get-page!]
      (let [scans-stream (scans/scans! "lvh" "hunter2" {"modules" "fim"})
            scans-with-details (scans/scans-with-details! "lvh"
                                                          "hunter2"
                                                          scans-stream)
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
           (scans/scans-with-details! '_ '_)
           ms/stream->seq
           doall))))

(defn ^:private mock-get-page
  "Generates a fake page function. Give it the expected base path and a
   function to call with the current page number."
  [cb]
  (fn [client-id client-secret url]
    (is (= client-id "lvh"))
    (is (= client-secret "hunter2"))
    (let [parsed-url (u/url url)
          path (:path parsed-url)
          query (:query parsed-url)
          page-num (-> query
                       (get "page" "0")
                       Integer/parseInt)]
      (cb {:page-num page-num :path path}))))

(deftest list-servers!-tests
  (testing "Returns all servers if paginated call is OK."
    (println #'scans/base-servers-url)
    (with-redefs [scans/get-page!
                  (mock-get-page
                   (fn [{:keys [page-num path]}]
                     (is (= "/v1/servers" path))
                     (case page-num
                       0 {:servers [{:id "server-id-1"} {:id "server-id-2"}]
                          :pagination {:next (str @#'scans/base-servers-url "?page=1")}}
                       1 {:servers [{:id "server-id-3"}]})))]
      (let [server-stream (scans/list-servers! "lvh" "hunter2")
            id-list (map :id (ms/stream->seq server-stream))]
        (is (= ["server-id-1" "server-id-2" "server-id-3"] id-list))
        (is (ms/closed? server-stream))))
    (testing "If page 2 is bad, a partial list is returned."
      (with-redefs [scans/get-page!
                    (mock-get-page
                     (fn [{:keys [page-num path]}]
                       (is (= "/v1/servers" path))
                       (case page-num
                         0 {:servers [{:id "server-id-1"} {:id "server-id-2"}]
                            :pagination {:next (str @#'scans/base-servers-url "?page=1")}}
                         1 :cloudpassage-lib.core/fetch-error)))]
        (let [server-stream (scans/list-servers! "lvh" "hunter2")
              id-list (map :id (ms/stream->seq server-stream))]
          (is (= ["server-id-1" "server-id-2"] id-list))
          (is (ms/closed? server-stream)))))))

(deftest scan-server-tests
  (with-redefs
   [scans/get-page! (mock-get-page
                     (fn [{:keys [path]}]
                       (is (= "/v1/servers/server-id-here/svm" path))
                       "GOOD"))]
    (is (= "GOOD" (scans/scan-server "lvh" "hunter2" "server-id-here" "svm")))))

(deftest scan-each-server!-tests
  (testing "Scan can handle an empty stream."
    (let [input (ms/stream)]
      (ms/close! input)
      (let [scan-stream (scans/scan-each-server! "lvh" "hunter2" "svm"
                                                 input)
            scan-result (clojure.string/join "" (ms/stream->seq scan-stream))]
        (is (= "" scan-result)))))
  (testing "When the server scan page is broken, we get back nadda."
    (with-redefs [scans/get-page! (mock-get-page
                                   (fn [{:keys [path]}]
                                     (is (= "/v1/servers/server-id-here/svm" path))
                                     :cloudpassage-lib.core/fetch-error))]
      (let [input (ms/stream)]
        (ms/put! input {:id "server-id-here"})
        (ms/close! input)
        (let [scan-stream (scans/scan-each-server! "lvh" "hunter2" "svm"
                                                   input)
              scan-result (clojure.string/join "" (ms/stream->seq scan-stream))]
          (is (= "" scan-result))))))
  (testing "Server scan can get back several pages of data."
    (with-redefs [scans/get-page! (mock-get-page
                                   (fn [{:keys [path]}]
        ;; The real data returning from a valid scan-server call would be a
        ;; map containing a bunch of scan data. But for testing purposes all
        ;; that matters is that scan-each-server! puts whatever comes back
        ;; into the its output stream.
                                     (case path
                                       "/v1/servers/server-1/svm" "ONE"
                                       "/v1/servers/server-2/svm" "TWO"
                                       "/v1/servers/server-3/svm" "THREE!")))]
      (let [input (ms/stream 2)]
        (ms/put-all! input [{:id "server-1"} {:id "server-2"} {:id "server-3"}])
        (ms/close! input)
        (let [scan-stream
              (scans/scan-each-server! "lvh" "hunter2" "svm" input)
              scan-result
              (clojure.string/join "..." (ms/stream->seq scan-stream))]
          (is (= "ONE...TWO...THREE!" scan-result)))))))

(defn ^:private test-report
  [report-fn! expected-module]
  (with-redefs
   [scans/get-page!
    (mock-get-page
     (fn [{:keys [path]}]
       (cond
         (= path "/v1/servers") {:servers [{:id "server-id-1"} {:id "server-id-2"}]}
         (= path (str "/v1/servers/server-id-1/" expected-module)) {:id "1" :scan {}}
         (= path (str "/v1/servers/server-id-2/" expected-module)) {:id "2" :scan {}})))]
    (let [report (report-fn! "lvh" "hunter2")
          result (clojure.string/join "..." report)]
      (is (= (str {:id "1", :scan {}} "..." {:id "2", :scan {}})
             result)))))

(deftest fim-report!-tests
  (test-report scans/fim-report! "fim"))

(deftest svm-report!-tests
  (test-report scans/svm-report! "svm"))

(deftest sca-report!-tests
  (test-report scans/sca-report! "sca"))
