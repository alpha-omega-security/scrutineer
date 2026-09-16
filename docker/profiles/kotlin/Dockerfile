# Kotlin profile.
#
# The `java` profile image + the Kotlin command-line compiler, so scans of
# Kotlin projects can compile standalone reproducers without a full Gradle
# build. Chained on `java` (BASE_IMAGE) rather than the runner so the JDK,
# Maven, and Gradle are the same builds the java profile uses, downloaded
# once.
#
# Gradle projects fetch the Kotlin Gradle plugin and compiler jars into
# /opt/gradle-home on first build; the CLI compiler here is for
# `kotlinc -script repro.main.kts` or `kotlin -cp ... ReproKt` reproducers
# that drive a vulnerable method directly.
#
# KONAN_DATA_DIR redirects Kotlin/Native's toolchain cache off the noexec
# HOME=/tmp mount. Nothing is pre-downloaded; a KMP native target fetches
# its LLVM toolchain there on demand (large; may exceed disk in hardened
# mode).
#
# Auto-selected when brief reports Kotlin as the dominant language; also
# selectable via ?profile=kotlin.
#
# Built on demand by the worker (EnsureImage): it builds the `java` profile
# first and passes its content-addressed tag as BASE_IMAGE, then tags this
# image scrutineer-profile-kotlin:<sha>. To build it manually:
#
#   docker build -t scrutineer-runner:local -f Dockerfile.runner .
#   docker build -t scrutineer-profile-java \
#       -f docker/profiles/java/Dockerfile \
#       --build-arg RUNNER_IMAGE=scrutineer-runner:local \
#       docker/profiles/java
#   docker build -t scrutineer-profile-kotlin \
#       -f docker/profiles/kotlin/Dockerfile \
#       --build-arg BASE_IMAGE=scrutineer-profile-java \
#       docker/profiles/kotlin
#   docker run --rm --entrypoint sh scrutineer-profile-kotlin \
#       -c 'java -version && kotlinc -version && gradle --version'

ARG BASE_IMAGE=ghcr.io/alpha-omega-security/scrutineer-runner:latest
FROM ${BASE_IMAGE}

ARG KOTLIN_VERSION=2.4.20
ARG KOTLIN_SHA256=59e9ca74c7904ef2c122b12114937673ccce68de820a663f0ed66ccf8799e0b7

USER root

# KONAN_DATA_DIR (Kotlin/Native toolchain cache) is redirected off
# HOME=/tmp, which the worker mounts noexec and caps at 256m -- far too
# small for an LLVM toolchain. 1777 so the host uid the scan runs as can
# write. The kotlinc launcher passes JAVA_OPTS through to the JVM;
# java.io.tmpdir already points at /opt/java-tmp via the base image's
# GRADLE_OPTS/MAVEN_OPTS, so JAVA_OPTS repeats it for standalone kotlinc.
ENV KOTLIN_HOME=/opt/kotlinc \
    KONAN_DATA_DIR=/opt/konan \
    JAVA_OPTS=-Djava.io.tmpdir=/opt/java-tmp \
    PATH=/opt/kotlinc/bin:$PATH

RUN curl -fsSL -o /tmp/kotlinc.zip \
        "https://github.com/JetBrains/kotlin/releases/download/v${KOTLIN_VERSION}/kotlin-compiler-${KOTLIN_VERSION}.zip" \
 && echo "${KOTLIN_SHA256}  /tmp/kotlinc.zip" | sha256sum -c - \
 # unzip is inherited from the java base. The archive extracts as kotlinc/,
 # so /opt/kotlinc/bin lands on PATH directly.
 && unzip -q /tmp/kotlinc.zip -d /opt \
 && rm /tmp/kotlinc.zip \
 && install -d -m 1777 /opt/konan \
 # Smoke-test with a throwaway java.io.tmpdir so the build does not seed
 # /opt/java-tmp with root-owned files the scan uid could not write beside.
 && JAVA_OPTS=-Djava.io.tmpdir=/tmp kotlinc -version \
 && JAVA_OPTS=-Djava.io.tmpdir=/tmp kotlin -version

USER runner
