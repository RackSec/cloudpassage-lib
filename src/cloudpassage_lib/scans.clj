(ns cloudpassage-lib.scans
  "Access to Halo scans."
  (:require
   [cemerick.url :as u]
   [clojure.string :as str]
   [aleph.http :as http]
   [manifold.deferred :as md]
   [manifold.stream :as ms]
   [manifold.time :as mt]
   [taoensso.timbre :as timbre :refer [warn error info]]
   [camel-snake-kebab.core :as cskc]
   [camel-snake-kebab.extras :as cske]
   [cloudpassage-lib.core :as cpc]
   [banach.retry :as retry]))

(def ^:private base-scans-url
  "https://api.cloudpassage.com/v1/scans/")

(def ^:private base-servers-url
  "https://api.cloudpassage.com/v1/servers/")

(def ^:private base-policies-url
  "https://api.cloudpassage.com/v1/policies/")

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

(defn ^:private scan-server-url
  "URL for fetching most recent scan results of a server."
  [server-id module]
  (str (u/url base-servers-url server-id module)))

(defn ^:private get-page-retry!
  "Gets a page, and exponentially retries the fetch on error."
  [token url num-retries timeout]
  (let [num-tries (inc num-retries)
        get-events-page-or-throw
        #(md/chain
          (cpc/get-single-events-page! token url)
          (fn [response]
            (if (cpc/page-response-ok? response)
              response
              (do (warn "Couldn't fetch page.")
                  (throw (Exception. "No more retries."))))))]
    (retry/retry-exp-backoff
     get-events-page-or-throw
     timeout
     num-tries)))

(defn ^:private handle-stream-exception
  [deferred output-stream input-stream]
  (md/catch deferred
            Exception
    (fn [exc]
      (ms/put! output-stream ::fetch-error)
      (error "Failed to complete stream processing:" exc)
      (ms/close! input-stream)
      (ms/close! output-stream))))

(defn ^:private get-page!
  "Gets a page, and handles auth for you."
  [client-id client-secret url]
  (let [token (cpc/fetch-token! client-id client-secret)
        num-retries 3
        timeout 2]  ;; timeout in seconds
    (get-page-retry! token url num-retries timeout)))

(defn ^:private stream-paginated-resources!
  "Returns a stream of resources retrieved according to a paginated
   chain of objects."
  [client-id client-secret initial-url resource-key]
  (let [urls-stream (ms/stream 10)
        resources-stream (ms/stream 20)]
    (ms/put! urls-stream initial-url)
    (ms/connect-via
     urls-stream
     (fn [url]
       (-> (get-page! client-id client-secret url)
           (md/chain
            (fn [response]
              (let [resource (resource-key response)
                    pagination (:pagination response)
                    next-url (:next pagination)]
                (if (str/blank? next-url)
                  (do (info "no more urls to fetch")
                      (ms/close! urls-stream))
                  (ms/put! urls-stream next-url))
                (ms/put-all! resources-stream resource))))
           (handle-stream-exception resources-stream urls-stream)))
     resources-stream)
    resources-stream))

(defn list-servers!
  "Returns a stream of servers for the given account."
  [client-id client-secret]
  (stream-paginated-resources!
   client-id
   client-secret
   base-servers-url
   :servers))

(defn list-policies!
  "Returns a stream of policies for the given account."
  [client-id client-secret]
  (stream-paginated-resources!
   client-id
   client-secret
   base-policies-url
   :policies))

(defn scans!
  "Returns a stream of historical scan results matching opts."
  [client-id client-secret opts]
  (stream-paginated-resources!
   client-id
   client-secret
   (scans-url opts)
   :scans))

(defn resources-with-details!
  "Returns a stream of resources with their details fetched.

  Because of the way the CloudPassage API works, you need to first
  query the resource endpoint for a list of resources, and then you
  need to fetch the details for each resource. See CloudPassage API
  docs for more illustration."
  [client-id client-secret resource-key get-resource resources-stream]
  (let [resources-with-details-stream (ms/stream 10)]
    (ms/connect-via
     resources-stream
     (fn [scan]
       (-> (get-page! client-id client-secret (:url scan))
           (md/chain
            (fn [response]
              (ms/put! resources-with-details-stream
                       (assoc scan resource-key (get-resource response)))))
           (handle-stream-exception resources-stream
                                    resources-with-details-stream)))
     resources-with-details-stream)
    resources-with-details-stream))

(defn scan-each-server!
  "Fetches a new report for each server passed in via the servers-stream.
  The module determines which type of report will be fetched.

  Returns a stream that contains the complete report for each server."
  [client-id client-secret module servers-stream]
  (let [server-details-stream (ms/stream 10)
        scan-server! (fn [server-id module]
                       (let [url (scan-server-url server-id module)]
                         (get-page! client-id client-secret url)))]
    (ms/connect-via
     servers-stream
     (fn [{:keys [id]}]
       (-> (scan-server! id module)
           (md/chain
            (fn [response]
              (ms/put! server-details-stream response)))
           (handle-stream-exception server-details-stream servers-stream)))
     server-details-stream)
    server-details-stream))

(defn ^:private generate-report!
  "Generate a report by fetching and transforming the data, handling
   any errors encountered."
  [get-report-data!]
  (let [report
        (->> (get-report-data!)
             (ms/map #(cske/transform-keys cskc/->kebab-case-keyword %))
             ms/stream->seq)]
    (if (some #(= % ::fetch-error) report)
      (do (error "Report failed to generate; aborting.")
          (throw (Exception. "Report failed to generate")))
      report)))

(defn ^:private report-for-module!
  "Get recent report data for a certain client, and filter based on module."
  [client-id client-secret module-name]
  (generate-report!
   (fn []
     (->> (list-servers! client-id client-secret)
          (scan-each-server! client-id client-secret module-name)))))

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

(defn policies-with-details!
  "Get the current SCA policies set for a particular client."
  [client-id client-secret]
  (generate-report!
   (fn []
     (->> (list-policies! client-id client-secret)
          (resources-with-details!
           client-id
           client-secret
           :rules
           (comp :rules :policy))))))
