#!/usr/bin/env bb
;; Generates the static digest convenience fns (md5, sha-256, ...) and writes
;; them into the marked region of the source namespaces. Run from the repo
;; root:  bb dev/gen.clj
;;
;; The standard JCA algorithm set below is stable across JVMs. Any *extra*
;; algorithm a JVM exposes at runtime is still given a convenience fn by the
;; `create-missing-fns!` fallback in the source, so this list does not need to
;; chase provider-specific additions.
(ns gen
  (:require [clojure.string :as str]))

(def standard-algorithms
  ["MD2" "MD5" "SHA" "SHA1" "SHA-1" "SHA-224" "SHA-256" "SHA-384" "SHA-512"
   "SHA3-224" "SHA3-256" "SHA3-384" "SHA3-512"])

(defn fn-form [algo]
  (format
   (str/join "\n"
             ["(defn %s"
              "  \"Encode the given message with the %s algorithm.\""
              "  {:arglists '([message])}"
              "  [message]"
              "  (digest \"%s\" message))"])
   (str/lower-case algo) algo algo))

(def begin ";; >>> generated convenience fns - run `bb dev/gen.clj` to regenerate >>>")
(def end   ";; <<< end generated convenience fns <<<")

(defn region []
  (str begin "\n" (str/join "\n\n" (map fn-form standard-algorithms)) "\n" end))

(defn rewrite! [path]
  (let [src (slurp path)
        re  (re-pattern (str "(?s)"
                             (java.util.regex.Pattern/quote begin)
                             ".*?"
                             (java.util.regex.Pattern/quote end)))]
    (if (re-find re src)
      (do (spit path (str/replace src re (java.util.regex.Matcher/quoteReplacement (region))))
          (println "regenerated" path))
      (println "no marker region found in" path "- skipped"))))

(run! rewrite! ["src/clj_commons/digest.clj" "src/digest.clj"])
