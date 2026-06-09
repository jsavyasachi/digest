# digest

`net.clojars.savya/digest` - A message digest library for Clojure. Providing `md5`, `sha-256`, HMAC, raw bytes, and base64 output.

## Stack

<a href="https://clojure.org"><img src="https://img.shields.io/badge/Clojure-5881D8?style=flat&logo=clojure&logoColor=white" alt="Clojure" /></a>
<a href="https://github.com/features/actions"><img src="https://img.shields.io/badge/GitHub%20Actions-2088FF?style=flat&logo=githubactions&logoColor=white" alt="GitHub Actions" /></a>

[![Clojars Project](https://img.shields.io/clojars/v/net.clojars.savya/digest.svg)](https://clojars.org/net.clojars.savya/digest)
[![cljdoc badge](https://cljdoc.org/badge/net.clojars.savya/digest)](https://cljdoc.org/d/net.clojars.savya/digest)
[![CI](https://github.com/jsavyasachi/digest/actions/workflows/ci.yml/badge.svg)](https://github.com/jsavyasachi/digest/actions/workflows/ci.yml)

There are several digest functions (such as `md5`, `sha-256` ...) in this
namespace. Each can handle the following input types:

* `java.lang.String`
* `byte array`
* `java.io.File`
* `java.io.InputStream`
* Sequence of byte array

# Usage

``` clojure
user=> (require '[clj-commons.digest :as digest])
nil
; On a string
user=> (digest/md5 "clojure")
"32c0d97f82a20e67c6d184620f6bd322"
; On a file
user=> (require '[clojure.java.io :as io])
nil
user=> (digest/sha-256 (io/file "/tmp/hello.txt"))
"163883d3e0e3b0c028d35b626b98564be8d9d649ed8adb8b929cb8c94c735c59"
; Raw bytes
user=> (seq (digest/digest-bytes "MD5" "clojure"))
(50 -64 -39 127 -126 -94 14 103 -58 -47 -124 98 15 107 -45 34)
; Base64
user=> (digest/digest-base64 "MD5" "clojure")
"MsDZf4KiDmfG0YRiD2vTIg=="
; HMAC
user=> (digest/hmac-sha-256 "secret" "message")
"8b5f48702995c1598c573db1e21866a9b825d4a794d169d7060a03605796360b"
```

# Installation

## deps.edn

``` clojure
net.clojars.savya/digest {:mvn/version "1.5.0"}
```

## lein

``` clojure
[net.clojars.savya/digest "1.5.0"]
```

# Dev

Run `lein test` to run the test suite.

Run `bb dev/gen.clj` after changing the generated static digest convenience
functions.

# License
Copyright&copy; 2017 Miki Tebeka <miki.tebeka@gmail.com>

Maintenance fork Copyright&copy; 2026 Savyasachi.
Original: https://github.com/clj-commons/digest

Distributed under the Eclipse Public License (same as Clojure).

Snail image in `tests` is public domain by Miki Tebeka
