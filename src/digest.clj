(ns
  ^{:author "Miki Tebeka <miki.tebeka@gmail.com>"
    :doc    "Message digest algorithms for Clojure"
    ;; single segment namespace is deprecated, use clj-commons/digest
    :deprecated true
    :no-doc true}
  digest
  (:require [clojure.string :refer [join lower-case split]])
  (:import (java.io File FileInputStream InputStream)
           java.nio.charset.Charset
           (java.security MessageDigest Provider Security)
           (java.util Arrays Base64)
           javax.crypto.Mac
           javax.crypto.spec.SecretKeySpec))

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
  "Get hex signature for digest bytes."
  [^bytes digest]
  (let [size (* 2 (alength digest))
        sig (.toString (BigInteger. 1 digest) 16)
        padding (join (repeat (- size (count sig)) "0"))]
    (str padding sig)))

(defn- base64 [^bytes digest]
  (.encodeToString (Base64/getEncoder) digest))

(defn- string-bytes
  ([^String message]
   (string-bytes message "UTF-8"))
  ([^String message encoding]
   (.getBytes message (Charset/forName encoding))))

(defprotocol Digestible
  (-update-digest! [message algorithm encoding])
  (-update-mac! [message mac encoding]))

(extend-protocol Digestible
  (class (make-array Byte/TYPE 0))
  (-update-digest! [message algorithm encoding]
    (.update ^MessageDigest algorithm ^bytes message))
  (-update-mac! [message mac encoding]
    (.update ^Mac mac ^bytes message))

  java.util.Collection
  ;; Code "borrowed" from
  ;; * http://www.holygoat.co.uk/blog/entry/2009-03-26-1
  ;; * http://www.rgagnon.com/javadetails/java-0416.html
  (-update-digest! [message algorithm encoding]
    (doseq [b message]
      (-update-digest! b algorithm encoding)))
  (-update-mac! [message mac encoding]
    (doseq [b message]
      (-update-mac! b mac encoding)))

  String
  (-update-digest! [message algorithm encoding]
    (-update-digest! (string-bytes message encoding) algorithm encoding))
  (-update-mac! [message mac encoding]
    (-update-mac! (string-bytes message encoding) mac encoding))

  InputStream
  (-update-digest! [reader algorithm encoding]
    (-update-digest! (byte-seq reader) algorithm encoding))
  (-update-mac! [reader mac encoding]
    (-update-mac! (byte-seq reader) mac encoding))

  File
  (-update-digest! [file algorithm encoding]
    (with-open [f (FileInputStream. file)]
      (-update-digest! f algorithm encoding)))
  (-update-mac! [file mac encoding]
    (with-open [f (FileInputStream. file)]
      (-update-mac! f mac encoding)))

  nil
  (-update-digest! [message algorithm encoding]
    nil)
  (-update-mac! [message mac encoding]
    nil))

(def standard-algorithms
  "Standard digest algorithms with statically generated convenience functions."
  #{"MD2" "MD5" "SHA" "SHA1" "SHA-1" "SHA-224" "SHA-256" "SHA-384" "SHA-512"
    "SHA3-224" "SHA3-256" "SHA3-384" "SHA3-512"})

(defn digest-bytes
  "Returns digest bytes for message with given algorithm."
  ([algorithm message]
   (digest-bytes algorithm message "UTF-8"))
  ([algorithm message encoding]
   (when (some? message)
     (let [^MessageDigest algo (MessageDigest/getInstance algorithm)]
       (.reset algo)
       (-update-digest! message algo encoding)
       (.digest algo)))))

(defn digest
  "Returns digest for message with given algorithm."
  ([algorithm message]
   (digest algorithm message "UTF-8"))
  ([algorithm message encoding]
   (some-> (digest-bytes algorithm message encoding) signature)))

(defn digest-base64
  "Returns base64-encoded digest for message with given algorithm."
  ([algorithm message]
   (digest-base64 algorithm message "UTF-8"))
  ([algorithm message encoding]
   (some-> (digest-bytes algorithm message encoding) base64)))

(defn file-digest
  "Returns digest for file with given algorithm."
  [algorithm file]
  (digest algorithm file))

(defn file-sha-256
  "Returns SHA-256 digest for file."
  [file]
  (file-digest "SHA-256" file))

(defn hmac-bytes
  "Returns HMAC bytes for message with given HMAC algorithm and key."
  ([algorithm key message]
   (hmac-bytes algorithm key message "UTF-8"))
  ([algorithm key message encoding]
   (when (and (some? key) (some? message))
     (let [^Mac mac (Mac/getInstance algorithm)
           key-bytes (if (string? key) (string-bytes key encoding) key)]
       (.init mac (SecretKeySpec. key-bytes algorithm))
       (-update-mac! message mac encoding)
       (.doFinal mac)))))

(defn hmac
  "Returns hex-encoded HMAC for message with given HMAC algorithm and key."
  ([algorithm key message]
   (hmac algorithm key message "UTF-8"))
  ([algorithm key message encoding]
   (some-> (hmac-bytes algorithm key message encoding) signature)))

(defn hmac-base64
  "Returns base64-encoded HMAC for message with given HMAC algorithm and key."
  ([algorithm key message]
   (hmac-base64 algorithm key message "UTF-8"))
  ([algorithm key message encoding]
   (some-> (hmac-bytes algorithm key message encoding) base64)))

(defn hmac-sha-256
  "Returns hex-encoded HMAC-SHA-256 for message and key."
  [key message]
  (hmac "HmacSHA256" key message))

(defn secure-eq?
  "Constant-time equality for digest or HMAC byte arrays."
  [a b]
  (and (bytes? a)
       (bytes? b)
       (MessageDigest/isEqual a b)))

(defn algorithms
  "List support digest algorithms."
  []
  (let [providers (vec (Security/getProviders))
        names (mapcat (fn [^Provider p] (enumeration-seq (.keys p))) providers)
        digest-names (filter #(re-find #"MessageDigest\.[A-Z0-9-]+$" %) names)]
    (set (map #(last (split % #"\.")) digest-names))))

(defn algorithm?
  "Returns true if algorithm is supported by the current JVM."
  [algorithm]
  (contains? (algorithms) algorithm))

(defn create-fn!
  [algorithm-name]
  (let [update-meta (fn [meta]
                      (assoc meta
                             :doc (str "Encode the given message with the " algorithm-name " algorithm.")
                             :arglists '([message])))]
    (-> (intern 'digest
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
          :when (not (ns-resolve 'digest fn-sym))]
    (create-fn! algorithm)))

(create-missing-fns!)
