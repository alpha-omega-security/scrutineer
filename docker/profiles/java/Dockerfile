# Java/JVM profile. Extends the scrutineer runner with a pinned Temurin
# JDK plus Maven and Gradle so scans of Maven or Gradle projects can
# resolve dependencies, build, test, and reproduce findings in-place.
#
# The JDK, Maven, and Gradle are all fetched as official, checksum-verified
# archives (JDK + Gradle by sha256, Maven by sha512 as Apache publishes),
# the same way the runner installs claude -- not from a moving apt repo.
# Bump a version and its checksum together; the content-addressed image
# tag invalidates the cache on any edit to this file.
#
# At runtime the worker builds this on demand (see internal/worker/profile.go:
# EnsureImage), tagging the result scrutineer-profile-java:<dockerfile-sha>
# and passing the configured runner image via --build-arg RUNNER_IMAGE.
#
# To build it manually the way the project does, from the repo root:
#
#   # 1. Build the base runner image locally (Debian/glibc, ships brief etc.):
#   docker build -t scrutineer-runner:local -f Dockerfile.runner .
#
#   # 2. Build this Java profile on top of that local runner:
#   docker build -t scrutineer-profile-java \
#       -f docker/profiles/java/Dockerfile \
#       --build-arg RUNNER_IMAGE=scrutineer-runner:local \
#       docker/profiles/java
#
#   # 3. Smoke-test it:
#   docker run --rm --entrypoint sh scrutineer-profile-java \
#       -c 'java -version && mvn -version && gradle --version'

ARG RUNNER_IMAGE=ghcr.io/alpha-omega-security/scrutineer-runner:latest

FROM ${RUNNER_IMAGE}

# Temurin 21 LTS, the current long-term-support JDK. Both arches are listed
# because the worker may build this on an amd64 or arm64 host.
ARG JDK_VERSION=21.0.11_10
ARG JDK_PATH_VERSION=jdk-21.0.11%2B10
ARG JDK_SHA256_X64=4b2220e232a97997b436ca6ab15cbf70171ecff52958a46159dfa5a8c44ca4de
ARG JDK_SHA256_ARM64=8d498ec88e1c1989fab95c6784240ab92d011e29c54d20a3f9c324b13476f9ad
# Maven publishes a sha512 alongside each binary; Gradle a sha256.
ARG MAVEN_VERSION=3.9.16
ARG MAVEN_SHA512=831a8591fe20c8243b1dbe7d71e3244f31d1665b0804b2e825e38cbbe5ce0cafb8338851f90780735568773e0a6cd07bbec107cda0b896b008b861075358b6f6
ARG GRADLE_VERSION=9.5.1
ARG GRADLE_SHA256=bafc141b619ad6350fd975fc903156dd5c151998cc8b058e8c1044ab5f7b031f

USER root

# Build caches live under /opt (a real image dir) rather than $HOME=/tmp,
# which the worker mounts noexec and caps at 256m -- too small for a
# resolved dependency set. 1777 so the host uid the scan runs as can write;
# the container is --rm'd after. (Hardened mode mounts the rootfs
# read-only, leaving only /work and /tmp writable, so in that mode the
# 256m cap applies and a large build may not fit.)
# java.io.tmpdir is redirected off $HOME=/tmp (noexec): Maven's jansi and
# other JVM libs extract native .so files to the JVM temp dir and dlopen
# them, which fails on a noexec mount. Pointing it at an exec-capable /opt
# dir fixes mvn and gradle; a standalone `java` reproducer that loads a
# native lib should pass -Djava.io.tmpdir=/opt/java-tmp too.
ENV JAVA_HOME=/opt/java \
    GRADLE_USER_HOME=/opt/gradle-home \
    MAVEN_OPTS=-Djava.io.tmpdir=/opt/java-tmp \
    GRADLE_OPTS=-Djava.io.tmpdir=/opt/java-tmp \
    PATH=/opt/java/bin:/opt/maven/bin:/opt/gradle/bin:$PATH

RUN apt-get update \
 && apt-get install -y --no-install-recommends unzip \
 && rm -rf /var/lib/apt/lists/* \
 && case "$(dpkg --print-architecture)" in \
        amd64) jdkarch=x64;     jdksha="${JDK_SHA256_X64}" ;; \
        arm64) jdkarch=aarch64; jdksha="${JDK_SHA256_ARM64}" ;; \
        *) echo "unsupported architecture: $(dpkg --print-architecture)" >&2; exit 1 ;; \
    esac \
 # JDK
 && curl -fsSL -o /tmp/jdk.tar.gz \
        "https://github.com/adoptium/temurin21-binaries/releases/download/${JDK_PATH_VERSION}/OpenJDK21U-jdk_${jdkarch}_linux_hotspot_${JDK_VERSION}.tar.gz" \
 && echo "${jdksha}  /tmp/jdk.tar.gz" | sha256sum -c - \
 && mkdir -p /opt/java \
 && tar -xzf /tmp/jdk.tar.gz -C /opt/java --strip-components=1 \
 && rm /tmp/jdk.tar.gz \
 # Maven
 && curl -fsSL -o /tmp/maven.tar.gz \
        "https://dlcdn.apache.org/maven/maven-3/${MAVEN_VERSION}/binaries/apache-maven-${MAVEN_VERSION}-bin.tar.gz" \
 && echo "${MAVEN_SHA512}  /tmp/maven.tar.gz" | sha512sum -c - \
 && mkdir -p /opt/maven \
 && tar -xzf /tmp/maven.tar.gz -C /opt/maven --strip-components=1 \
 && rm /tmp/maven.tar.gz \
 # Gradle
 && curl -fsSL -o /tmp/gradle.zip \
        "https://services.gradle.org/distributions/gradle-${GRADLE_VERSION}-bin.zip" \
 && echo "${GRADLE_SHA256}  /tmp/gradle.zip" | sha256sum -c - \
 && unzip -q /tmp/gradle.zip -d /opt \
 && mv "/opt/gradle-${GRADLE_VERSION}" /opt/gradle \
 && rm /tmp/gradle.zip \
 # Maven local repo and Gradle home, writable by the scan uid
 && sed -i 's#</settings>#  <localRepository>/opt/m2/repo</localRepository>\n</settings>#' /opt/maven/conf/settings.xml \
 && install -d -m 1777 /opt/m2/repo /opt/gradle-home /opt/java-tmp \
 # Gradle forks a daemon JVM that does not inherit GRADLE_OPTS, so it would
 # extract libnative-platform.so to the noexec $HOME=/tmp and fail. A
 # gradle.properties in GRADLE_USER_HOME fixes the daemon's java.io.tmpdir
 # and disables the daemon (scans are one-shot, so a daemon only adds risk).
 && printf 'org.gradle.daemon=false\norg.gradle.jvmargs=-Djava.io.tmpdir=/opt/java-tmp\n' \
        > /opt/gradle-home/gradle.properties \
 && chmod 0666 /opt/gradle-home/gradle.properties \
 && java -version \
 && javac -version \
 && mvn -version \
 && gradle --version \
 # `gradle --version` (run as root here) extracts its native libraries
 # into GRADLE_USER_HOME/native owned by root; the scan runs as the host
 # uid and must be able to write the .lock files beside them, so open up
 # the pre-populated caches. Ephemeral container, --rm'd after the scan.
 && chmod -R a+rwX /opt/gradle-home /opt/m2/repo

USER runner
