(ns
  ^{:author "Miki Tebeka <miki.tebeka@gmail.com>"
    :doc    "Message digest algorithms for Clojure"}
  clj-commons.digest
  (:require [clojure.string :refer [join lower-case split]])
  (:import (java.io File FileInputStream InputStream)
           (java.security MessageDigest Provider Security)
           (java.util Arrays)))

; Default buffer size for reading
(def ^:dynamic *buffer-size* 1024)

(defn- read-some
  "Read some data from reader. Return [data size] if there's more to read,
  otherwise nil."
  [^InputStream reader]
  (let [^bytes buffer (make-array Byte/TYPE *buffer-size*)
        size (.read reader buffer)]
    (when (pos? size)
      (if (= size *buffer-size*) buffer (Arrays/copyOf buffer size)))))

(defn- byte-seq
  "Return a sequence of [data size] from reader."
  [^InputStream reader]
  (take-while some? (repeatedly (partial read-some reader))))

(defn- signature
  "Get signature (string) of digest."
  [^MessageDigest algorithm]
  (let [size (* 2 (.getDigestLength algorithm))
        sig (.toString (BigInteger. 1 (.digest algorithm)) 16)
        padding (join (repeat (- size (count sig)) "0"))]
    (str padding sig)))

(defprotocol Digestible
  (-digest [message algorithm]))

(extend-protocol Digestible
  (class (make-array Byte/TYPE 0))
  (-digest [message algorithm]
    (-digest [message] algorithm))

  java.util.Collection
  ;; Code "borrowed" from
  ;; * http://www.holygoat.co.uk/blog/entry/2009-03-26-1
  ;; * http://www.rgagnon.com/javadetails/java-0416.html
  (-digest [message algorithm]
    (let [^MessageDigest algo (MessageDigest/getInstance algorithm)]
      (.reset algo)
      (doseq [^bytes b message] (.update algo b))
      (signature algo)))

  String
  (-digest [message algorithm]
    (-digest [(.getBytes message)] algorithm))

  InputStream
  (-digest [reader algorithm]
    (-digest (byte-seq reader) algorithm))

  File
  (-digest [file algorithm]
    (with-open [f (FileInputStream. file)]
      (-digest f algorithm)))

  nil
  (-digest [message algorithm]
    nil))

(defn digest
  "Returns digest for message with given algorithm."
  [algorithm message]
  (-digest message algorithm))

(defn algorithms
  "List supported digest algorithms."
  []
  (let [providers (vec (Security/getProviders))
        names (mapcat (fn [^Provider p] (enumeration-seq (.keys p))) providers)
        digest-names (filter #(re-find #"MessageDigest\.[A-Z0-9-]+$" %) names)]
    (set (map #(last (split % #"\.")) digest-names))))

(defn- create-fn!
  [algorithm-name]
  (let [update-meta (fn [meta]
                      (assoc meta
                             :doc (str "Encode the given message with the " algorithm-name " algorithm.")
                             :arglists '([message])))]
    (-> (intern *ns*
                (symbol (lower-case algorithm-name))
                (partial digest algorithm-name))
        (alter-meta! update-meta))))

;; The convenience fns below are statically defined (rather than interned at
;; load time) so clj-kondo and cljdoc can see them. They are produced by
;; dev/gen.clj from the standard JCA algorithm set; do not edit by hand.
;; >>> generated convenience fns - run `bb dev/gen.clj` to regenerate >>>
(defn md2
  "Encode the given message with the MD2 algorithm."
  {:arglists '([message])}
  [message]
  (digest "MD2" message))

(defn md5
  "Encode the given message with the MD5 algorithm."
  {:arglists '([message])}
  [message]
  (digest "MD5" message))

(defn sha
  "Encode the given message with the SHA algorithm."
  {:arglists '([message])}
  [message]
  (digest "SHA" message))

(defn sha1
  "Encode the given message with the SHA1 algorithm."
  {:arglists '([message])}
  [message]
  (digest "SHA1" message))

(defn sha-1
  "Encode the given message with the SHA-1 algorithm."
  {:arglists '([message])}
  [message]
  (digest "SHA-1" message))

(defn sha-224
  "Encode the given message with the SHA-224 algorithm."
  {:arglists '([message])}
  [message]
  (digest "SHA-224" message))

(defn sha-256
  "Encode the given message with the SHA-256 algorithm."
  {:arglists '([message])}
  [message]
  (digest "SHA-256" message))

(defn sha-384
  "Encode the given message with the SHA-384 algorithm."
  {:arglists '([message])}
  [message]
  (digest "SHA-384" message))

(defn sha-512
  "Encode the given message with the SHA-512 algorithm."
  {:arglists '([message])}
  [message]
  (digest "SHA-512" message))

(defn sha3-224
  "Encode the given message with the SHA3-224 algorithm."
  {:arglists '([message])}
  [message]
  (digest "SHA3-224" message))

(defn sha3-256
  "Encode the given message with the SHA3-256 algorithm."
  {:arglists '([message])}
  [message]
  (digest "SHA3-256" message))

(defn sha3-384
  "Encode the given message with the SHA3-384 algorithm."
  {:arglists '([message])}
  [message]
  (digest "SHA3-384" message))

(defn sha3-512
  "Encode the given message with the SHA3-512 algorithm."
  {:arglists '([message])}
  [message]
  (digest "SHA3-512" message))
;; <<< end generated convenience fns <<<

(defn- create-missing-fns!
  "Intern convenience fns for any algorithms this JVM exposes beyond the
  generated standard set above (e.g. additional security providers), so every
  algorithm in `(algorithms)` has a matching var."
  []
  (doseq [algorithm (algorithms)
          :let  [fn-sym (symbol (lower-case algorithm))]
          :when (not (ns-resolve 'clj-commons.digest fn-sym))]
    (create-fn! algorithm)))

(create-missing-fns!)
