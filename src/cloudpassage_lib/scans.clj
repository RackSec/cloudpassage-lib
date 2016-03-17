(ns cloudpassage-lib.scans
  "Access to Halo scans."
  (:require
   [cemerick.url :as u]
   [clojure.string :as str]
   [manifold.stream :as ms]
   [aleph.http :as http]
   [manifold.deferred :as md]
   [manifold.stream :as ms]
   [environ.core :refer [env]]
   [cloudpassage-lib.core :as cpc]
   [taoensso.timbre :as timbre :refer [info spy]]
   [clj-time.core :as t :refer [hours ago]]
   [clj-time.format :as tf]
   [camel-snake-kebab.core :as cskc]
   [camel-snake-kebab.extras :as cske]
   [clojure.java.io :as io]))

(def ^:private base-scans-url
  "https://api.cloudpassage.com/v1/scans/")

(def ^:private scans-path
  (partial str "/v1/scans/"))

(defn ^:private maybe-flatten-list
  [maybe-list]
  (if (or (string? maybe-list) (nil? maybe-list))
    maybe-list
    (str/join "," maybe-list)))

(defn ^:private scans-url
  ([opts]
   (scans-url base-scans-url opts))
  ([url opts]
   (let [opts (update opts "modules" maybe-flatten-list)]
     (-> (u/url url)
         (update :query merge opts)
         str))))

(defn ^:private scans-detail-url
  "Compute the URL for a scan detail."
  ([scan-id]
   (scans-detail-url base-scans-url scan-id))
  ([url scan-id]
   (-> (u/url url)
       (assoc :path (scans-path scan-id))
       str)))

(defn ^:private finding-detail-url
  "Compute the URL for a particular finding in a particular scan."
  ([scan-id finding-id]
   (finding-detail-url base-scans-url scan-id finding-id))
  ([url scan-id finding-id]
   (-> (u/url url)
       (assoc :path (scans-path scan-id "/findings/" finding-id))
       str)))

(defn get-page!
  "Gets a page, and handles auth for you."
  [client-id client-secret url]
  (let [token (cpc/fetch-token! client-id client-secret (:fernet-key env))]
    (cpc/get-single-events-page! token url)))

(defn scans!
  "Returns a stream of historical scan results matching opts."
  [client-id client-secret opts]
  (let [urls-stream (ms/stream 10) ;; absolutely no science here
        scans-stream (ms/stream 20) ;; nor here
        shovel (fn [url]
                 (md/chain
                  (get-page! client-id client-secret url)
                  ;; TODO: error handling here?
                  (fn [response]
                    (let [{:keys [pagination scans]} response
                          next-url (:next pagination)]
                      (if (or (= "" next-url) (nil? next-url))
                        (do (info "no more urls to fetch")
                            (ms/close! urls-stream)
                            (ms/close! scans-stream))
                        (ms/put! urls-stream next-url))
                      (ms/put-all! scans-stream scans)))))]
    (ms/put! urls-stream (scans-url opts))
    (ms/consume-async shovel urls-stream)
    scans-stream))

(defn scans-with-details!
  "Returns a stream of historical scan results with their details.

  Because of the way the CloudPassage API works, you need to first
  query the scans, and then you need to fetch the details for each
  scan, and then you need to fetch the FIM scan details for the
  details (iff the details are FIM). See CloudPassage API docs for
  more illustration."
  [client-id client-secret scans-stream]
  (let [scans-with-details (ms/stream 10)
        add-details
        (fn [scan]
          (md/chain
           (get-page! client-id client-secret (:url scan))
           (fn [response]
             (ms/put! scans-with-details (assoc scan :scan (:scan response)))
             (when (ms/drained? scans-stream)
               (ms/close! scans-with-details)))))]
    (ms/consume-async add-details scans-stream)
    ;; TODO: Figure out a way to automatically close the stream this function
    ;;       returns without using the lower-level on-drained callback.
    (ms/on-drained scans-stream #(ms/close! scans-with-details))
    scans-with-details))

(defn ^:private report-for-module!
  "Get recent report data for a certain client, and filter based on module."
  [client-id client-secret module-name]
  ;; The docs say we can use "module" as a query parameter but it does
  ;; not work for FIM or SVM, so we have to filter out those items instead.
  (let [opts {"since" (cpc/->cp-date (-> 3 hours ago))}]
    (->> (scans! client-id client-secret opts)
         (ms/filter (fn [{:keys [module]}] (= module module-name)))
         (scans-with-details! client-id client-secret)
         (ms/map #(cske/transform-keys cskc/->kebab-case-keyword %))
         ms/stream->seq)))

(defn fim-report!
  "Get the current (recent) FIM report for a particular client."
  [client-id client-secret]
  (report-for-module! client-id client-secret "fim"))

(defn svm-report!
  "Get the current (recent) SVM report for a particular client."
  [client-id client-secret]
  (report-for-module! client-id client-secret "svm"))

(defn sca-report!
  "Get the current (recent) sca report for a particular client."
  [client-id client-secret]
  (report-for-module! client-id client-secret "sca"))
