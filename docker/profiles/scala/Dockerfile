# Scala/sbt profile.
#
# The `java` profile image + sbt, so scans of Scala projects can resolve
# dependencies, compile, run tests, and reproduce findings. Chained on `java`
# (BASE_IMAGE) rather than the runner so the JDK is the same Temurin build the
# Maven/Gradle profile uses, downloaded once.
#
# sbt is a launcher: it reads project/build.properties and bootstraps
# whichever sbt.version the project pins (1.x or 2.x), so the SBT_VERSION
# below is only the launcher's own default for projects that omit the pin.
#
# Auto-selected when brief reports sbt in package_managers or Scala as the
# dominant language; also selectable via ?profile=scala.
#
# Built on demand by the worker (EnsureImage): it builds the `java` profile
# first and passes its content-addressed tag as BASE_IMAGE, then tags this
# image scrutineer-profile-scala:<sha>. To build it manually:
#
#   docker build -t scrutineer-runner:local -f Dockerfile.runner .
#   docker build -t scrutineer-profile-java \
#       -f docker/profiles/java/Dockerfile \
#       --build-arg RUNNER_IMAGE=scrutineer-runner:local \
#       docker/profiles/java
#   docker build -t scrutineer-profile-scala \
#       -f docker/profiles/scala/Dockerfile \
#       --build-arg BASE_IMAGE=scrutineer-profile-java \
#       docker/profiles/scala
#   docker run --rm --entrypoint sh scrutineer-profile-scala \
#       -c 'java -version && sbt --script-version'

ARG BASE_IMAGE=ghcr.io/alpha-omega-security/scrutineer-runner:latest
FROM ${BASE_IMAGE}

ARG SBT_VERSION=1.13.0
ARG SBT_SHA256=06806805ffd26232727326216766ed4793b549f8c1e6ffeef2e610db7245b698

USER root

# sbt's boot dir (the launcher downloads the pinned sbt.version + scala-library
# there), the ivy2 cache, and the coursier cache all default under $HOME=/tmp,
# which the worker mounts noexec and caps at 256m -- far too small once the
# scala-compiler and a project's dependency set are written there. Redirect
# them to /opt, 1777 so the host uid the scan runs as can write. java.io.tmpdir
# already points at /opt/java-tmp via the base image; SBT_OPTS repeats it
# because sbt ignores MAVEN_OPTS/GRADLE_OPTS. The sbt server is disabled
# (scans are one-shot).
ENV COURSIER_CACHE=/opt/coursier \
    SBT_OPTS="-Dsbt.global.base=/opt/sbt-home -Dsbt.boot.directory=/opt/sbt-home/boot -Dsbt.ivy.home=/opt/ivy2 -Dsbt.server.autostart=false -Djava.io.tmpdir=/opt/java-tmp" \
    PATH=/opt/sbt/bin:$PATH

RUN curl -fsSL -o /tmp/sbt.tgz \
        "https://github.com/sbt/sbt/releases/download/v${SBT_VERSION}/sbt-${SBT_VERSION}.tgz" \
 && echo "${SBT_SHA256}  /tmp/sbt.tgz" | sha256sum -c - \
 && tar -xzf /tmp/sbt.tgz -C /opt \
 && rm /tmp/sbt.tgz \
 # sbtn-* are per-arch native thin clients for the sbt server; scans are
 # one-shot so they are unused. -f so a future sbt tgz that drops them still
 # builds instead of failing on an unexpanded glob.
 && rm -f /opt/sbt/bin/sbtn-* \
 && install -d -m 1777 /opt/sbt-home /opt/sbt-home/boot /opt/ivy2 /opt/coursier \
 # Smoke-test with throwaway home/boot/cache dirs so the build does not seed
 # /opt/{sbt-home,ivy2,coursier} with root-owned files the scan uid could not
 # then write beside; the scan populates them fresh as that uid.
 && BOOT=/tmp/sbt-bootstrap \
 && mkdir -p "$BOOT/home" "$BOOT/boot" "$BOOT/ivy2" "$BOOT/coursier" \
 && COURSIER_CACHE="$BOOT/coursier" \
    SBT_OPTS="-Dsbt.global.base=$BOOT/home -Dsbt.boot.directory=$BOOT/boot -Dsbt.ivy.home=$BOOT/ivy2 -Djava.io.tmpdir=/opt/java-tmp" \
    sbt --script-version \
 && rm -rf "$BOOT"

USER runner
