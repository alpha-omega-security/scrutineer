ARG crs_version=dev
FROM scrutineer-oss-crs-base:${crs_version}

# Root because libCRS writes to the framework mounts. The entrypoint drops to
# the runner user for the audit itself.
USER root

# --cli only: the entrypoint just runs the libCRS command. Debian's system
# Python refuses the package install that the default --all adds (PEP 668).
COPY --from=libcrs . /opt/libCRS
RUN /opt/libCRS/install.sh --cli

COPY --chmod=0755 oss-crs/run-auditor.sh /usr/local/bin/scrutineer-oss-crs-auditor

CMD ["/usr/local/bin/scrutineer-oss-crs-auditor"]
