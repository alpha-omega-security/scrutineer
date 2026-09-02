# Scala scanning container

The repository under `./src` is a Scala project, built with sbt.

## Runtime

- **Temurin JDK 25** — `java`, `javac`. `JAVA_HOME=/opt/java`.
- **`sbt`** on PATH. The launcher reads `project/build.properties` and bootstraps whichever `sbt.version` the project
  pins (1.x or 2.x), so the first `sbt` invocation downloads that sbt and the Scala compiler into `/opt/sbt-home/boot`.
- **`mvn`**, **`gradle`** — inherited from the java base, for a Scala module inside a mixed Maven/Gradle build.

sbt's boot directory, ivy cache (`/opt/ivy2`), and coursier cache (`/opt/coursier`) are on an exec-capable path rather
than under `HOME`, which is a small noexec mount. `java.io.tmpdir` is `/opt/java-tmp` for the same reason.

## Operating procedure

### Code scanning preparations

```bash
cd src
sbt --batch compile          # or `sbt --batch Test/compile` to compile tests too
```

`--batch` runs sbt non-interactively (fails instead of prompting). The first run resolves the pinned sbt version, the
Scala compiler, and every library dependency; that can take a couple of minutes. If it fails with `Error downloading`
or `UnknownHostException` the scan is offline — work from the source already present and note which checks you had to
skip. For a multi-project build, `sbt --batch projects` lists the sub-projects; scope a task with
`sbt --batch <sub>/compile`.

### Scala-specific analysis

Scala interoperates with the whole JVM standard library, so every Java sink applies. Scala adds:

- **`scala.sys.process`** — the string forms (`"ls $x".!`, `"ls $x".!!`, `Process(s"cmd $x").run()`, `.lazyLines`) split
  on whitespace like `Runtime.exec(String)`; a value that is *substituted into the string* controls argv. The `Seq`
  form (`Seq("ls", x).!`) passes each element as its own argv entry.
- **`scala.xml.XML.load` / `XML.loadFile` / `XML.loadString`** — the default parser resolves external entities (XXE)
  unless the caller supplies a hardened `SAXParser`.
- **`scala.io.Source.fromURL`** — SSRF when the URL is user-supplied. `Source.fromFile` on a user path is traversal.
- **`scala.util.Random`** — wraps `java.util.Random` (predictable); a token or nonce needs `java.security.SecureRandom`.
- **Java interop** — `ObjectInputStream.readObject`, `Runtime.getRuntime().exec`, `ScriptEngine.eval`,
  `Class.forName(x).newInstance()`, JDBC string concatenation: all reachable from Scala unchanged.

### Creating reproducers

Every finding ships with a reproducer — code that, when run in this container, actually triggers the issue. Paste the
exact command you ran and the verbatim output into the finding. Reasoning-only or "this would" reproducers do not
count; if you couldn't run it here, say so explicitly instead of inventing one.

- **A focused test**: add a spec under the project's `src/test/scala` and run only that one:
  ```bash
  sbt --batch "testOnly *ReproSpec"
  ```
  ScalaTest, MUnit, and specs2 all wire through `testOnly`. The test output is the evidence.
- **The sbt console**: `sbt --batch "runMain com.example.Repro arg"` if you drop a small `object Repro { def main... }`
  under `src/main/scala`; or `sbt --batch console <<'EOF' ... EOF` for a REPL one-liner against the compiled classpath.
- **Standalone**: sbt writes classes to `target/scala-<v>/classes`; `sbt --batch "export Runtime/fullClasspath"` prints
  a colon-separated classpath you can pass to `java -cp` or `scala -cp` for a script that drives the vulnerable method
  directly with the malicious input (a crafted string, a hostile serialized blob, an XXE payload).

## Out of scope

- Dependencies under `/opt/ivy2`, `/opt/coursier`, `/opt/m2/repo`, and `/opt/gradle-home` — third-party code, not the
  target of this scan unless a finding specifically pivots through one.
