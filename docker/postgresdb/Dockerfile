FROM postgres:16-alpine

ENV POSTGRES_USER=scrutineer \
    POSTGRES_DB=scrutineer

# Pre-provision the schema on first initialisation.
COPY initdb/ /docker-entrypoint-initdb.d/
