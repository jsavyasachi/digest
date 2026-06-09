(ns digest-test
  (:require [clj-commons.digest :as canonical]
            [clojure.string :refer [lower-case includes?]]
            [clojure.test :refer :all]
            [digest :refer :all])
  (:import java.io.File))

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

; Just making sure that we don't explode on nil
(deftest nil-test
  (is (nil? (md5 nil))))

(deftest length-test
  (is (= (sha (File. "test/quote.txt"))
         "dc93ad3c1e212bf598b9bf700914e832c9bdade5")))
