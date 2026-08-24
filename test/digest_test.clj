(ns digest-test
  (:refer-clojure :exclude [reset!])
  (:require [clj-commons.digest :as canonical]
            [clj-commons.digest-test :as shared]
            [clojure.string :refer [lower-case includes?]]
            [clojure.test :refer :all]
            [digest :refer :all])
  (:import (java.io ByteArrayInputStream File)
           java.nio.ByteBuffer
           java.nio.channels.Channels))

(deftest md5-test
  (is (= (digest "md5" "clojure") "32c0d97f82a20e67c6d184620f6bd322")))

(deftest sha-256-test
  (is (= (sha-256 "clojure")
         "4f3ea34e0a3a6196a18ec24b51c02b41d5f15bd04b4a94aa29e4f6badba0f5b0")))

(deftest legacy-namespace-parity-test
  (doseq [[algorithm legacy canonical] [["MD2" md2 canonical/md2]
                                        ["MD5" md5 canonical/md5]
                                        ["SHA" sha canonical/sha]
                                        ["SHA1" sha1 canonical/sha1]
                                        ["SHA-1" sha-1 canonical/sha-1]
                                        ["SHA-224" sha-224 canonical/sha-224]
                                        ["SHA-256" sha-256 canonical/sha-256]
                                        ["SHA-384" sha-384 canonical/sha-384]
                                        ["SHA-512" sha-512 canonical/sha-512]
                                        ["SHA3-224" sha3-224 canonical/sha3-224]
                                        ["SHA3-256" sha3-256 canonical/sha3-256]
                                        ["SHA3-384" sha3-384 canonical/sha3-384]
                                        ["SHA3-512" sha3-512 canonical/sha3-512]]
          :when ((canonical/algorithms) algorithm)]
    (is (= (legacy "clojure")
           (canonical "clojure")))))

(deftest legacy-helper-parity-test
  (is (= (seq (digest-bytes "MD5" "clojure"))
         (seq (canonical/digest-bytes "MD5" "clojure"))))
  (is (= (digest-base64 "MD5" "clojure")
         (canonical/digest-base64 "MD5" "clojure")))
  (is (= (hmac "HmacSHA256" "secret" "message")
         (canonical/hmac "HmacSHA256" "secret" "message")))
  (is (= (hmac-sha-256 "secret" "message")
         (canonical/hmac-sha-256 "secret" "message")))
  (is (= (algorithm? "SHA-256")
         (canonical/algorithm? "SHA-256"))))

(deftest legacy-incremental-context-parity-test
  (let [legacy (digest-context "SHA-256")
        canonical-context (canonical/digest-context "SHA-256")]
    (update! legacy "clo")
    (update! legacy "jure")
    (canonical/update! canonical-context "clo")
    (canonical/update! canonical-context "jure")
    (is (= (seq (digest! legacy))
           (seq (canonical/digest! canonical-context)))))
  (let [legacy (hmac-context "HmacSHA256" "secret")
        canonical-context (canonical/hmac-context "HmacSHA256" "secret")]
    (update! legacy "message")
    (canonical/update! canonical-context "message")
    (is (= (seq (finalize! legacy))
           (seq (canonical/finalize! canonical-context))))))

(deftest hmac-convenience-functions-test
  (doseq [[legacy canonical expected] [[hmac-sha1 canonical/hmac-sha1
                                       "de7c9b85b8b78aa6bc8a7a36f70a90701c9db4d9"]
                                      [hmac-sha-256 canonical/hmac-sha-256
                                       "f7bc83f430538424b13298e6aa6fb143ef4d59a14946175997479dbc2d1a3cd8"]
                                      [hmac-sha384 canonical/hmac-sha384
                                       "d7f4727e2c0b39ae0f1e40cc96f60242d5b7801841cea6fc592c5d3e1ae50700582a96cf35e1e554995fe4e03381c237"]
                                      [hmac-sha512 canonical/hmac-sha512
                                       "b42af09057bac1e2d41708e48a902e09b5ff7f12ab428a4fe86653c73dd248fb82f948a549f7b791a5b41915ee4d1ec3935357e4e2317250d0372afa2ebeeb3a"]
                                      [hmac-sha3-224 canonical/hmac-sha3-224
                                       "ff6fa8447ce10fb1efdccfe62caf8b640fe46c4fb1007912bf85100f"]
                                      [hmac-sha3-256 canonical/hmac-sha3-256
                                       "8c6e0683409427f8931711b10ca92a506eb1fafa48fadd66d76126f47ac2c333"]
                                      [hmac-sha3-384 canonical/hmac-sha3-384
                                       "aa739ad9fcdf9be4a04f06680ade7a1bd1e01a0af64accb04366234cf9f6934a0f8589772f857681fcde8acc256091a2"]
                                      [hmac-sha3-512 canonical/hmac-sha3-512
                                       "237a35049c40b3ef5ddd960b3dc893d8284953b9a4756611b1b61bffcf53edd979f93547db714b06ef0a692062c609b70208ab8d4a280ceee40ed8100f293063"]]]
    (is (= expected (legacy "key" "The quick brown fox jumps over the lazy dog")))
    (is (= expected (canonical "key" "The quick brown fox jumps over the lazy dog")))))

(deftest secure-encoded-eq-test
  (let [hex (sha-256 "clojure")
        base64 (digest-base64 "SHA-256" "clojure")]
    (is (secure-eq? hex hex :hex))
    (is (secure-eq? hex (.toUpperCase ^String hex) :hex))
    (is (not (secure-eq? hex (sha-256 "different") :hex)))
    (is (secure-eq? base64 base64 :base64))
    (is (not (secure-eq? base64 (digest-base64 "SHA-256" "different") :base64)))
    (is (not (secure-eq? "not-hex" "not-hex" :hex)))
    (is (not (secure-eq? "not-base64" "not-base64" :base64)))
    (is (not (secure-eq? hex hex :unknown)))))

(deftest secure-encoded-eq-parity-test
  (is (= (secure-eq? (sha-256 "clojure")
                     (.toUpperCase ^String (sha-256 "clojure"))
                     :hex)
         (canonical/secure-eq? (canonical/sha-256 "clojure")
                               (.toUpperCase ^String (canonical/sha-256 "clojure"))
                               :hex)))
  (is (= (secure-eq? (digest-base64 "SHA-256" "clojure")
                     (digest-base64 "SHA-256" "clojure")
                     :base64)
          (canonical/secure-eq? (canonical/digest-base64 "SHA-256" "clojure")
                                (canonical/digest-base64 "SHA-256" "clojure")
                                :base64))))

(deftest algorithms-test
  (let [names (algorithms)]
    (is (not (empty? names)))
    (is (names "SHA-1"))))

(deftest utils-test
  ;; Previously a lazy `for`, so these assertions never ran.
  (doseq [name (algorithms)]
    (is (ns-resolve 'digest (symbol (lower-case name)))
        (str "missing convenience fn for " name))))

(deftest function-metadata-test
  (is (includes? (:doc (meta #'sha-256))
                 "SHA-256"))
  (is (= '([message])
         (:arglists (meta #'md5)))))

(def ^:dynamic *image-md5* "49c39580caf91363e4a4cacfa5564489")
(def ^:dynamic *image-sha1*
  "96f2328cf279b95ddb1dee36df0c91cd7821e741")

(deftest file-test
  (let [f (File. "test/snail.png")]
    (is (= (md5 f) *image-md5*))
    (is (= (sha-1 f) *image-sha1*))))

; Make sure that nil input does not cause an error
(deftest nil-test
  (is (nil? (md5 nil))))

(deftest hex-encoding-test
  (let [bytes (byte-array [(byte 0) (byte 1) (byte 15) (byte 127)
                           (byte -128) (byte -1)])]
    (is (= "00010f7f80ff" (bytes->hex bytes)))
    (is (= (seq bytes) (seq (hex->bytes "00010F7F80FF"))))
    (is (= (seq bytes) (seq (hex->bytes "00010f7f80ff"))))
    (is (= "" (bytes->hex (byte-array 0))))
    (is (empty? (hex->bytes "")))
    (is (nil? (bytes->hex nil)))
    (is (nil? (hex->bytes nil)))
    (is (thrown? IllegalArgumentException (hex->bytes "abc")))
    (is (thrown? IllegalArgumentException (hex->bytes "00xz")))))

(deftest length-test
  (is (= (sha (File. "test/quote.txt"))
         "dc93ad3c1e212bf598b9bf700914e832c9bdade5")))

(deftest legacy-input-stream-reuses-buffer-test
  (let [buffers (atom [])
        input (shared/partial-input-stream
               (.getBytes "clojure streaming" "UTF-8") 2 buffers)]
    (is (= (sha-256 input)
           (sha-256 (.getBytes "clojure streaming" "UTF-8"))))
    (is (= 1 (count (distinct (map identity @buffers)))))))

(deftest nio-input-types-parity-test
  (let [bytes (.getBytes "clojure" "UTF-8")
        buffer (ByteBuffer/wrap bytes)
        channel (Channels/newChannel (ByteArrayInputStream. bytes))]
    (is (= (md5 buffer) (canonical/md5 (ByteBuffer/wrap bytes))))
    (is (= (md5 channel) (canonical/md5 (Channels/newChannel (ByteArrayInputStream. bytes)))))
    (is (= (hmac "HmacSHA256" "secret" (ByteBuffer/wrap bytes))
           (canonical/hmac "HmacSHA256" "secret" (ByteBuffer/wrap bytes))))))
