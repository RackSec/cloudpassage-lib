(ns cloudpassage-lib.core
  (:require
   [clojure.string :as str]
   [clojure.core.cache :as cache]
   [aleph.http :as http]
   [environ.core :refer [env]]
   [manifold.deferred :as md]
   [byte-streams :as bs]
   [taoensso.timbre :as timbre :refer [info warn]]
   [base64-clj.core :as base64]
   [clj-time.core :as time]
   [clj-time.format :as f]
   [banach.retry :as retry]
   [cheshire.core :as json]))

;; the url from which new auth-tokens can be obtained.
(def auth-uri "https://api.cloudpassage.com/oauth/access_token?grant_type=client_credentials")
(def events-uri "https://api.cloudpassage.com/v1/events?")

(defn ^:private ->basic-auth-header
  [client-id client-key]
  (let [together (str client-id ":" client-key)
        encoded (base64/encode together)]
    {"Authorization" (str/join " " ["Basic" encoded])}))

(defn ^:private ->bearer-auth-header
  [auth-token]
  {"Authorization" (str/join " " ["Bearer" auth-token])})

(def cp-date-formatter
  (f/formatter "yyyy-MM-dd'T'HH:mm:ss'Z'"))

(defn ->cp-date
  [date]
  (f/unparse cp-date-formatter date))

(defn get-auth-token!
  "Using the secret key and an ID, fetch a new auth token.

  client-key - a string representing the key provided by cloudpassage.
  client-id - a string representing an customer.

  returns a `manifold.deferred/deferred' wrapping an authentication
  token hash map"
  [client-id client-key]
  (info "fetching new auth token for" client-id)
  (let [sent-at (time/now)
        auth-header (->basic-auth-header client-id client-key)
        starting-retry 4
        stop-after 3]
    (md/chain
     (retry/retry-exp-backoff
      #(http/post auth-uri {:headers auth-header})
      starting-retry
      stop-after)
     #(json/parse-stream (bs/to-reader (:body %)) true))))

(defn get-single-events-page!
  "get a page at `uri` using the provided `auth-token`.

  returns a `manifold.deferred/deferred` that when realized contains a clojure
  map representing the body of an http response."
  [auth-token uri]
  (info "fetching" uri)
  (let [auth-header (->bearer-auth-header auth-token)]
    (->
     (md/chain
      (http/get uri {:headers auth-header})
      :body
      bs/to-reader
      #(json/parse-stream % true))
     (md/catch
      Exception
      (fn [exc]
        (warn "problem fetching events page:" (.getMessage exc))
        ::fetch-error)))))

(defn page-response-ok?
  "Returns false if there was an error retrieving a page."
  [response]
  (not= ::fetch-error response))

(def ^:private cache-ttl-milliseconds 8000)

(defn ^:private build-cache
  []
  (atom
   (cache/ttl-cache-factory {} :ttl cache-ttl-milliseconds)))

(def ^:private cache-state (build-cache))

(defn fetch-token!
  "Fetch an access token for the cloudpassage api that belongs to the
  client-id/secret pair.

  This will be backed by an in-memory TTL cache (though the consumer doesn't
  need to care about this) that his hidden behind an atom.

  Returns an access-token as a string."
  [client-id client-secret]
  (let [account-key (str client-id)
        current-cache @cache-state]
    (if (cache/has? current-cache account-key)
      ;; if there is a token, then return it
      (let [updated-cache (swap! cache-state cache/hit account-key)]
        (timbre/trace "Cache hit" account-key)
        (cache/lookup updated-cache account-key))
      ;; otherwise, go fetch a new one, cache it (with the default for the cache)
      ;; and return the _new_ token
      (let [{:keys [access_token]} @(get-auth-token! client-id client-secret)]
        (timbre/trace "Cache miss" account-key)
        (swap! cache-state cache/miss account-key access_token)
        access_token))))
