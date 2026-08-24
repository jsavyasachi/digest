(ns digest-test
  (:require [clj-commons.digest :as canonical]
            [clojure.string :refer [lower-case includes?]]
            [clojure.test :refer :all]
            [digest :refer :all])
  (:import (java.io ByteArrayInputStream File)
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

(deftest length-test
  (is (= (sha (File. "test/quote.txt"))
         "dc93ad3c1e212bf598b9bf700914e832c9bdade5")))

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
