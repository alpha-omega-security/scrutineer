# Java/JVM scanning container

The repository under `./src` is a JVM project, built with Maven or Gradle.

## Runtime

- **Temurin JDK 21** — `java`, `javac`. `JAVA_HOME=/opt/java`.
- **`mvn`** (Maven 3.9) on PATH for `pom.xml` projects.
- **`gradle`** (Gradle 9) on PATH for `build.gradle` / `build.gradle.kts` projects.

The Maven local repository (`/opt/m2/repo`) and Gradle home (`/opt/gradle-home`) live on an exec-capable path rather
than under `HOME`, which is a small noexec mount. `mvn` and `gradle` already run with `java.io.tmpdir=/opt/java-tmp` so
JVM libraries that unpack native `.so` files can load them; a standalone `java` reproducer that loads a native library
should pass `-Djava.io.tmpdir=/opt/java-tmp` too.

## Operating procedure

### Code scanning preparations

Resolve dependencies and compile with the tool that matches the project.

For Gradle projects, prefer the project's own wrapper when present, so the build uses the version it pins:

```bash
cd src
./gradlew assemble --offline 2>/dev/null || ./gradlew assemble || gradle assemble   # build.gradle(.kts)
mvn -B -o compile 2>/dev/null || mvn -B compile                                     # pom.xml
```

`-B` runs Maven in batch (non-interactive) mode. Try an offline pass first; if it fails because dependencies aren't
cached yet, run online. If that fails with a network error the scan is offline — work from the source already present
and note which checks you had to skip. A Gradle wrapper download (`gradlew`) also needs the network on first use; fall
back to the image's `gradle` when it can't fetch.

### Creating reproducers

Every finding ships with a reproducer — a small piece of code that, when run in this container, actually triggers the
issue. Paste the exact command you ran and the verbatim output (error message, return value, observable side effect)
into the finding. Reasoning-only or "this would" reproducers do not count; if you couldn't run it here, say so
explicitly instead of inventing one.

- A focused test: add a JUnit test under the project's `src/test/java` and run it with `mvn -B -Dtest=ClassName#method test`
  or `gradle test --tests 'ClassName.method'`. The test output is the evidence.
- A standalone program: drop a small `Main.java` with a `main` method, compile it against the project's classpath, and
  run it — e.g. `javac -cp "$(mvn -q dependency:build-classpath -Dmdep.outputFile=/dev/stdout)" Main.java`.
- Drive the vulnerable method directly with the malicious input (a crafted string, a hostile serialized blob, an XML
  payload for an XXE sink) rather than booting the whole application — keeps the reproducer minimal and the evidence
  trivial to verify.

## Out of scope

- Dependencies in the Maven/Gradle caches — third-party code, not the target of this scan unless a finding
  specifically pivots through one.
