(defproject net.clojars.savya/digest (or (System/getenv "PROJECT_VERSION") "1.5.0")
  :description "Digest algorithms (MD5, SHA ...) for Clojure"
  :author "Miki Tebeka <miki.tebeka@gmail.com>"
  :url "https://github.com/jsavyasachi/digest"
  :repositories [["clojars" {:url "https://repo.clojars.org"
                             :username :env/clojars_username
                             :password :env/clojars_password
                             :sign-releases false}]]
  :license {:name "Eclipse Public License"
            :url "http://www.eclipse.org/legal/epl-v10.html"}
  :dependencies [[org.clojure/clojure "1.10.1"]])
