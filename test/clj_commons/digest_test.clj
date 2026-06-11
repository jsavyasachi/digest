(ns clj-commons.digest-test
  (:require [clj-commons.digest :as d]
            [clojure.string :refer [lower-case includes?]]
            [clojure.test :refer [deftest is]])
  (:import (java.io ByteArrayInputStream File)
           java.util.Base64
           (java.nio.charset StandardCharsets)
           java.security.NoSuchAlgorithmException))

(defn utf-8-bytes ^bytes [^String s]
  (.getBytes s StandardCharsets/UTF_8))

(deftest md5-test
  (is (= (d/digest "md5" "clojure") "32c0d97f82a20e67c6d184620f6bd322")))

(deftest sha-256-test
  (is (= (d/sha-256 "clojure")
         "4f3ea34e0a3a6196a18ec24b51c02b41d5f15bd04b4a94aa29e4f6badba0f5b0")))

(deftest byte-array-test
  (is (= (d/md5 (utf-8-bytes "clojure"))
         "32c0d97f82a20e67c6d184620f6bd322")))

(deftest digest-bytes-test
  (is (= (seq (d/digest-bytes "MD5" "clojure"))
         (seq (d/digest-bytes "MD5" (utf-8-bytes "clojure")))))
  (is (= (d/digest "MD5" "clojure")
         (format "%032x" (BigInteger. 1 ^bytes (d/digest-bytes "MD5" "clojure"))))))

(deftest digest-base64-test
  (is (= (d/digest-base64 "MD5" "clojure")
         (.encodeToString (Base64/getEncoder)
                          (d/digest-bytes "MD5" "clojure")))))

(deftest input-stream-test
  (is (= (d/md5 (ByteArrayInputStream. (utf-8-bytes "clojure")))
         "32c0d97f82a20e67c6d184620f6bd322")))

(deftest byte-array-sequence-test
  (is (= (d/md5 [(utf-8-bytes "clo")
                 (utf-8-bytes "jure")])
         "32c0d97f82a20e67c6d184620f6bd322")))

(deftest empty-input-test
  (is (= (d/md5 "") "d41d8cd98f00b204e9800998ecf8427e"))
  (is (= (d/md5 (byte-array 0)) "d41d8cd98f00b204e9800998ecf8427e"))
  (is (= (d/md5 []) "d41d8cd98f00b204e9800998ecf8427e"))
  (is (= (d/md5 (ByteArrayInputStream. (byte-array 0)))
         "d41d8cd98f00b204e9800998ecf8427e")))

(deftest input-stream-buffer-boundary-test
  (binding [d/*buffer-size* 3]
    (is (= (d/sha-256 (ByteArrayInputStream. (utf-8-bytes "clojure")))
           "4f3ea34e0a3a6196a18ec24b51c02b41d5f15bd04b4a94aa29e4f6badba0f5b0"))))

(deftest string-uses-utf-8-compatible-bytes-test
  (is (= (d/sha-256 "café")
         (d/sha-256 (utf-8-bytes "café"))))
  (is (= (d/digest "SHA-256" "café" "UTF-8")
         (d/sha-256 (utf-8-bytes "café")))))

(deftest file-digest-helper-test
  (let [f (File. "test/snail.png")]
    (is (= (d/file-digest "MD5" f) (d/md5 f)))
    (is (= (d/file-sha-256 f) (d/sha-256 f)))))

(deftest hmac-test
  (is (= (d/hmac "HmacSHA256" "secret" "message")
         "8b5f48702995c1598c573db1e21866a9b825d4a794d169d7060a03605796360b"))
  (is (= (d/hmac-sha-256 "secret" "message")
         (d/hmac "HmacSHA256" "secret" "message")))
  (is (= (d/hmac-base64 "HmacSHA256" "secret" "message")
         (.encodeToString (Base64/getEncoder)
                          (d/hmac-bytes "HmacSHA256" "secret" "message")))))

(deftest secure-eq-test
  (is (d/secure-eq? (d/digest-bytes "SHA-256" "a")
                    (d/digest-bytes "SHA-256" "a")))
  (is (not (d/secure-eq? (d/digest-bytes "SHA-256" "a")
                         (d/digest-bytes "SHA-256" "b")))))

(deftest algorithms-test
  (let [names (d/algorithms)]
    (is (seq names))
    (is (names "SHA-1"))
    (is (d/algorithm? "SHA-1"))
    (is (not (d/algorithm? "NOPE")))
    (is (contains? d/standard-algorithms "SHA-256"))))

(deftest utils-test
  ;; Every algorithm the JVM exposes must have a matching convenience fn -
  ;; statically generated for the standard set, interned by the fallback for
  ;; the rest. (Previously a lazy `for`, so these assertions never ran.)
  (doseq [name (d/algorithms)]
    (is (ns-resolve 'clj-commons.digest (symbol (lower-case name)))
        (str "missing convenience fn for " name))))

(deftest function-metadata-test
  (is (includes? (:doc (meta #'d/sha-256))
                 "SHA-256"))
  (is (= '([message])
         (:arglists (meta #'d/md5)))))

(def ^:dynamic *image-md5* "49c39580caf91363e4a4cacfa5564489")
(def ^:dynamic *image-sha1*
  "96f2328cf279b95ddb1dee36df0c91cd7821e741")

(deftest file-test
  (let [f (File. "test/snail.png")]
    (is (= (d/md5 f) *image-md5*))
    (is (= (d/sha-1 f) *image-sha1*))))

; Just making sure that we don't explode on nil
(deftest nil-test
  (is (nil? (d/md5 nil))))

(deftest length-test
  (is (= (d/sha (File. "test/quote.txt"))
         "dc93ad3c1e212bf598b9bf700914e832c9bdade5")))

(deftest invalid-algorithm-test
  (is (thrown? NoSuchAlgorithmException
               (d/digest "NOPE" "clojure"))))
