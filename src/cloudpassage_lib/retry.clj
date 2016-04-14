(ns cloudpassage-lib.retry
  (:require
   [clojure.math.numeric-tower :as math]
   [manifold.deferred :as md]
   [manifold.time :as mt]))

(defn exponentially
  "Returns a function that when evaluated will produce the initial wait
  raised to the number of failures.

  This is intended to be used in conjunction with other 1-arg combinators,
  that take a vector of failures."
  [wait]
  (fn [failures]
    (math/expt wait (count failures))))

(defn up-to
  "Returns a function that when evaluated will either

  1) return a number to use to wait until retrying a function again. Or,
  2) throw an exception because the maximum number of retries, `stop`, has
  been reached.

  This is intended to be used in conjunction with other 1-arg combinators,
  that take a vector of failures."
  [stop retry?]
  (fn [failures]
    (if (< (count failures) stop)
      (retry? failures)
      (throw (last failures)))))

(defn retry-exp-backoff
  "Takes a function that returns a `manifold.deferred/deferred`. Retries that
  function until it succeeds or the number of failures equal the stop value.

  Expects to encounter exceptions when retrying `f`. As such,
  it will catch all exceptions that `f` might throw and continue retrying.

  f - a function that should be retried; must return a
      `manifold.deferred/deferred'
  p - an int representing the initial number of seconds to wait before retrying.
      This will grow exponentially for each attempt.
  stop - an int representing the number of tries that the api should make before
         giving up and returning the last exception encountered.

  Returns a deferred wrapping the results of `f`."
  [f p stop]
  (let [try-after (->> (exponentially p)
                       (up-to stop))]
    (md/loop [failures []]
      (md/catch
       (f)
       Exception
        (fn [exc]
          (let [all-failures (conj failures exc)
                wait (try-after all-failures)]
            (mt/in (mt/seconds wait) #(md/recur all-failures))))))))
