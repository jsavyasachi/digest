(ns digest-test
  (:refer-clojure :exclude [reset!])
  (:require [clj-commons.digest :as canonical]
            [clj-commons.digest-test :as shared]
            [clojure.string :refer [lower-case includes?]]
            [clojure.test :refer :all]
            [digest :refer :all])
  (:import (java.io ByteArrayInputStream File)
           java.nio.ByteBuffer
           java.nio.channels.Channels
           java.nio.charset.StandardCharsets
           java.security.NoSuchAlgorithmException))

(set! *warn-on-reflection* true)

(defn utf-8-bytes ^bytes [^String s]
  (.getBytes s StandardCharsets/UTF_8))

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

(deftest algorithm-resolution-test
  (is (true? (algorithm? "sha-256")))
  (is (true? (algorithm? "SHA256")))
  (is (false? (algorithm? nil)))
  (is (false? (algorithm? 256)))
  (is (false? (algorithm? "NOPE"))))

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

;; Published digest vectors: RFC 1319 (MD2), RFC 1321 (MD5), RFC 3174 and
;; FIPS 180-4 (SHA-1 and SHA-2), and FIPS 202 (SHA-3):
;; https://www.rfc-editor.org/rfc/rfc1319, https://www.rfc-editor.org/rfc/rfc1321,
;; https://www.rfc-editor.org/rfc/rfc3174, https://csrc.nist.gov/pubs/fips/180-4/final,
;; https://csrc.nist.gov/pubs/fips/202/final.
(deftest published-digest-vectors-test
  (doseq [[algorithm expected] [["MD2" "da853b0d3f88d99b30283a69e6ded6bb"]
                                ["MD5" "900150983cd24fb0d6963f7d28e17f72"]
                                ["SHA" "a9993e364706816aba3e25717850c26c9cd0d89d"]
                                ["SHA1" "a9993e364706816aba3e25717850c26c9cd0d89d"]
                                ["SHA-1" "a9993e364706816aba3e25717850c26c9cd0d89d"]
                                ["SHA-224" "23097d223405d8228642a477bda255b32aadbce4bda0b3f7e36c9da7"]
                                ["SHA-256" "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"]
                                ["SHA-384" "cb00753f45a35e8bb5a03d699ac65007272c32ab0eded1631a8b605a43ff5bed8086072ba1e7cc2358baeca134c825a7"]
                                ["SHA-512" "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f"]
                                ["SHA3-224" "e642824c3f8cf24ad09234ee7d3c766fc9a3a5168d0c94ad73b46fdf"]
                                ["SHA3-256" "3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532"]
                                ["SHA3-384" "ec01498288516fc926459f58e2c6ad8df9b473cb0fc08c2596da7cf0e49be4b298d88cea927ac7f539f1edf228376d25"]
                                ["SHA3-512" "b751850b1a57168a5693cd924b6b096e08f621827444f70d884f5d0240d2712e10e116e9192af3c91a7ec57647e3934057340b4cf408d5a56592f8274eec53f0"]]
          :when (algorithm? algorithm)]
    (is (= expected (digest algorithm "abc")) algorithm)))

;; HMAC vectors: RFC 2202 test case 1 and RFC 4231 test case 1,
;; https://www.rfc-editor.org/rfc/rfc2202 and https://www.rfc-editor.org/rfc/rfc4231.
(deftest published-hmac-vectors-test
  (let [key (byte-array (repeat 20 (unchecked-byte 0x0b)))]
    (doseq [[algorithm expected] [["HmacMD5" "9294727a3638bb1c13f48ef8158bfc9d"]
                                  ["HmacSHA1" "b617318655057264e28bc0b6fb378c8ef146be00"]
                                  ["HmacSHA224" "896fb1128abbdf196832107cd49df33f47b4b1169912ba4f53684b22"]
                                  ["HmacSHA256" "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7"]
                                  ["HmacSHA384" "afd03944d84895626b0825f4ab46907f15f9dadbe4101ec682aa034c7cebc59cfaea9ea9076ede7f4af152e8b2fa9cb6"]
                                  ["HmacSHA512" "87aa7cdea5ef619d4ff0b4241a1d6cb02379f4e2ce4ec2787ad0b30545e17cdedaa833b7d6b8a702038b274eaea3f4e4be9d914eeb61f1702e696c203a126854"]]
            :when (try (javax.crypto.Mac/getInstance algorithm) true
                       (catch NoSuchAlgorithmException _ false))]
      (is (= expected
             (hmac algorithm
                   (if (= algorithm "HmacMD5")
                     (byte-array (repeat 16 (unchecked-byte 0x0b)))
                     key)
                   "Hi There"))
          algorithm))
    (is (= "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7"
           (hmac-sha-256 key "Hi There")))))

(deftest large-stream-parity-test
  (let [large (byte-array (repeat 1048577 (unchecked-byte 0x5a)))]
    (is (= (sha-256 large)
           (sha-256 (ByteArrayInputStream. large))))
    (is (= (hmac "HmacSHA256" (utf-8-bytes "key") large)
           (hmac "HmacSHA256" (utf-8-bytes "key")
                 (ByteArrayInputStream. large))))))
