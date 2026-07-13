(ns build
  "Build + Clojars deploy for jose-clj (tools.build + deps-deploy).

   Usage:
     clojure -T:build jar
     clojure -T:build deploy   ; needs CLOJARS_USERNAME / CLOJARS_PASSWORD"
  (:require [clojure.tools.build.api :as b]
            [deps-deploy.deps-deploy :as dd]))

(def lib 'net.clojars.savya/digest)
(def version "1.5.4")
(def class-dir "target/classes")
(def basis (delay (b/create-basis {:project "deps.edn"})))
(def jar-file (format "target/%s-%s.jar" (name lib) version))

(defn clean [_]
  (b/delete {:path "target"})
  (b/delete {:path "pom.xml"}))

(defn jar [_]
  (clean nil)
  (b/write-pom {:class-dir class-dir
                :lib lib
                :version version
                :basis @basis
                :src-dirs ["src"]
                :scm {:url "https://github.com/jsavyasachi/digest"
                      :connection "scm:git:https://github.com/jsavyasachi/digest.git"
                      :developerConnection "scm:git:ssh://git@github.com/jsavyasachi/digest.git"
                      :tag (str "v" version)}
                :pom-data [[:description "Digest algorithms (MD5, SHA ...) for Clojure"]
                           [:url "https://github.com/jsavyasachi/digest"]
                           [:licenses
                            [:license
                             [:name "Eclipse Public License 1.0"]
                             [:url "https://www.eclipse.org/legal/epl-v10.html"]
                             [:distribution "repo"]]]]})
  (b/copy-dir {:src-dirs ["src" "resources"] :target-dir class-dir})
  (b/jar {:class-dir class-dir :jar-file jar-file})
  (println "Wrote" jar-file))

(defn deploy [_]
  (jar nil)
  (dd/deploy {:installer :remote
              :artifact jar-file
              :pom-file (b/pom-path {:lib lib :class-dir class-dir})}))
