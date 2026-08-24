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

(deftest hmac-convenience-functions-test
  (doseq [[function algorithm expected] [[d/hmac-sha1 "HmacSHA1"
                                         "de7c9b85b8b78aa6bc8a7a36f70a90701c9db4d9"]
                                        [d/hmac-sha-256 "HmacSHA256"
                                         "f7bc83f430538424b13298e6aa6fb143ef4d59a14946175997479dbc2d1a3cd8"]
                                        [d/hmac-sha384 "HmacSHA384"
                                         "d7f4727e2c0b39ae0f1e40cc96f60242d5b7801841cea6fc592c5d3e1ae50700582a96cf35e1e554995fe4e03381c237"]
                                        [d/hmac-sha512 "HmacSHA512"
                                         "b42af09057bac1e2d41708e48a902e09b5ff7f12ab428a4fe86653c73dd248fb82f948a549f7b791a5b41915ee4d1ec3935357e4e2317250d0372afa2ebeeb3a"]
                                        [d/hmac-sha3-224 "HmacSHA3-224"
                                         "ff6fa8447ce10fb1efdccfe62caf8b640fe46c4fb1007912bf85100f"]
                                        [d/hmac-sha3-256 "HmacSHA3-256"
                                         "8c6e0683409427f8931711b10ca92a506eb1fafa48fadd66d76126f47ac2c333"]
                                        [d/hmac-sha3-384 "HmacSHA3-384"
                                         "aa739ad9fcdf9be4a04f06680ade7a1bd1e01a0af64accb04366234cf9f6934a0f8589772f857681fcde8acc256091a2"]
                                        [d/hmac-sha3-512 "HmacSHA3-512"
                                         "237a35049c40b3ef5ddd960b3dc893d8284953b9a4756611b1b61bffcf53edd979f93547db714b06ef0a692062c609b70208ab8d4a280ceee40ed8100f293063"]]]
    (is (= expected (function "key" "The quick brown fox jumps over the lazy dog")))
    (is (= expected (d/hmac algorithm "key" "The quick brown fox jumps over the lazy dog")))))

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
  ;; Every algorithm that the JVM supplies must have a matching convenience fn.
  ;; The standard set is statically generated. The fallback interns the rest.
  ;; (Previously a lazy `for`, so these assertions never ran.)
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

; Make sure that nil input does not cause an error
(deftest nil-test
  (is (nil? (d/md5 nil))))

(deftest length-test
  (is (= (d/sha (File. "test/quote.txt"))
         "dc93ad3c1e212bf598b9bf700914e832c9bdade5")))

(deftest invalid-algorithm-test
  (is (thrown? NoSuchAlgorithmException
               (d/digest "NOPE" "clojure"))))
