# clj-commons/digest

`clj-commons/digest` - A message digest library for Clojure. Providing `md5`, `sha-256`, ...

## Stack

<a href="https://clojure.org"><img src="https://img.shields.io/badge/Clojure-5881D8?style=flat&logo=clojure&logoColor=white" alt="Clojure" /></a>
<a href="https://github.com/features/actions"><img src="https://img.shields.io/badge/GitHub%20Actions-2088FF?style=flat&logo=githubactions&logoColor=white" alt="GitHub Actions" /></a>

[![Clojars Project](https://img.shields.io/clojars/v/org.clj-commons/digest.svg)](https://clojars.org/org.clj-commons/digest)
[![cljdoc badge](https://cljdoc.org/badge/org.clj-commons/digest)](https://cljdoc.org/d/org.clj-commons/digest)
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
```

# Installation

## deps.edn

``` clojure
org.clj-commons/digest {:mvn/version "1.4.100"}
```

## lein

``` clojure
[org.clj-commons/digest "1.4.100"]
```

# Dev

Run `lein test` to run the test suite.

Run `bb dev/gen.clj` after changing the generated static digest convenience
functions.

## Deployment

Run `bb deploy` to deploy using the clj-commons
[release](https://github.com/clj-commons/infra/blob/main/deployment/release.bb)
script or create a tag manually in the format `Release-1.4.<commit-count>` and
push it.

GitHub Actions deploys `Release-*` tags to Clojars. Configure repository secrets:
`CLOJARS_USERNAME`, `CLOJARS_PASSWORD`, and base64-encoded `GPG_KEY`.

# License
Copyright&copy; 2017 Miki Tebeka <miki.tebeka@gmail.com>

Distributed under the Eclipse Public License (same as Clojure).

Snail image in `tests` is public domain by Miki Tebeka
