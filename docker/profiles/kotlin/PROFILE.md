# Kotlin scanning container

The repository under `./src` is a Kotlin project, built with Gradle (occasionally Maven).

## Runtime

- **Temurin JDK 25** — `java`, `javac`. `JAVA_HOME=/opt/java`.
- **`gradle`**, **`mvn`** — inherited from the java base. Prefer the project's `./gradlew` when present so the build
  uses the Gradle version it pins.
- **`kotlinc`**, **`kotlin`** on PATH (`KOTLIN_HOME=/opt/kotlinc`) for standalone compilation and `.kts` scripts.

The Gradle home (`/opt/gradle-home`), Maven local repo (`/opt/m2/repo`), and Kotlin/Native cache
(`KONAN_DATA_DIR=/opt/konan`) are on an exec-capable path rather than under `HOME`, which is a small noexec mount.
`java.io.tmpdir` is `/opt/java-tmp` for the same reason; `JAVA_OPTS` carries that into `kotlinc`.

## Operating procedure

### Code scanning preparations

```bash
cd src
./gradlew assemble --offline 2>/dev/null || ./gradlew assemble || gradle assemble
```

The first run resolves the Kotlin Gradle plugin, the Kotlin compiler for the version the project pins, and every
library dependency; that can take a couple of minutes. `./gradlew projects` lists sub-projects in a multi-module
build; scope a task with `./gradlew :<sub>:assemble`. A Kotlin Multiplatform build with native targets will try to
download an LLVM toolchain to `/opt/konan`, which is large; if that fails or the scan is offline, restrict to the JVM
target with `./gradlew jvmMainClasses` and note which targets you skipped.

### Kotlin-specific analysis

Kotlin interoperates with the whole JVM standard library, so every Java sink applies. Kotlin adds:

- **`kotlin.io` extensions** — `File(x).readText()`, `File(x).writeText()`, `File(x).readBytes()`, and the
  `kotlin.io.path` equivalents `Path(x).readText()` etc. are traversal when `x` is caller-supplied and not resolved
  against a trusted root.
- **`URL(x).readText()` / `readBytes()` / `openStream()`** — SSRF when the URL string is caller-supplied.
- **Ktor client** — `HttpClient().get(user)`, `.request(user)`, `.post(user)` are SSRF; the default engine follows
  redirects. Ktor server: `call.respondText(user, ContentType.Text.Html)` is XSS; `call.receive<T>()` binds request
  bodies via kotlinx.serialization or Jackson depending on `ContentNegotiation` config.
- **kotlinx.serialization** — polymorphism requires an explicit `SerializersModule` registering each subclass, so
  arbitrary-class deserialization (Jackson-style) is not the default. The reportable pattern is a `SerializersModule`
  that maps a caller-controlled discriminator to security-sensitive subclasses, or a project that plugs Jackson in
  via `ContentNegotiation` and inherits Jackson's polymorphic-typing rules.
- **Exposed** — `Transaction.exec("... $x ...")` and `exec(sql)` run raw SQL; the DSL (`Table.select { col eq x }`)
  parameterises.
- **`kotlin.random.Random`** — wraps a non-cryptographic PRNG; a token or nonce needs `java.security.SecureRandom`.
- **Java interop** — `Runtime.getRuntime().exec`, `ProcessBuilder`, `ObjectInputStream.readObject`,
  `ScriptEngine.eval`, `Class.forName(x)`, JDBC string concatenation: all reachable from Kotlin unchanged.

### Creating reproducers

Every finding ships with a reproducer — code that, when run in this container, actually triggers the issue. Paste the
exact command you ran and the verbatim output into the finding. Reasoning-only or "this would" reproducers do not
count; if you couldn't run it here, say so explicitly instead of inventing one.

- **A focused test**: add a test class under the project's `src/test/kotlin` (or `src/jvmTest/kotlin` for KMP) and run
  only that one:
  ```bash
  ./gradlew test --tests "*ReproTest"
  ```
  For KMP, `./gradlew jvmTest --tests "*ReproTest"`. The test output is the evidence.
- **A `.kts` script**: `kotlinc -script repro.main.kts` runs a standalone script with `@file:DependsOn("g:a:v")` at the
  top to pull the vulnerable library from Maven Central, then calls the sink with the malicious input directly.
- **Against the compiled classpath**: `./gradlew build` writes classes to `build/classes/kotlin/main`;
  `./gradlew -q printRuntimeClasspath` (add a one-line task if the project lacks one) or the `build/libs/*.jar` gives
  a classpath you can pass to `kotlin -cp <cp> com.example.ReproKt` or `java -cp <cp> com.example.ReproKt` to drive
  the vulnerable method with a crafted string, hostile serialized blob, or SSRF URL.

## Out of scope

- Dependencies under `/opt/gradle-home`, `/opt/m2/repo`, and `/opt/konan` — third-party code, not the target of this
  scan unless a finding specifically pivots through one.
