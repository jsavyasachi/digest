(defproject net.clojars.savya/digest (or (System/getenv "PROJECT_VERSION") "1.5.3")
  :description "Digest algorithms (MD5, SHA ...) for Clojure"
  :author "Miki Tebeka <miki.tebeka@gmail.com>"
  :url "https://github.com/jsavyasachi/digest"
  :license {:name "Eclipse Public License 1.0"
            :url "https://www.eclipse.org/legal/epl-v10.html"}
  :dependencies [[org.clojure/clojure "1.12.5"]]
  :global-vars {*warn-on-reflection* true}
  :profiles {:clojure-1-10 {:dependencies [[org.clojure/clojure "1.10.3"]]}
             :clojure-1-11 {:dependencies [[org.clojure/clojure "1.11.4"]]}
             :clojure-1-12 {:dependencies [[org.clojure/clojure "1.12.5"]]}}
  :aliases {"all" ["with-profile" "+clojure-1-10:+clojure-1-11:+clojure-1-12"]}
  :deploy-repositories [["clojars" {:url "https://repo.clojars.org"
                                    :username :env/clojars_username
                                    :password :env/clojars_password
                                    :sign-releases false}]])
