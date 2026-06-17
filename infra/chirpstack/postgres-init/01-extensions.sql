-- ChirpStack v4 requires the pg_trgm extension for its database migrations
-- (trigram indexes / gin_trgm_ops). Without it, the chirpstack container fails
-- its migrations and restarts in a loop.
--
-- This script is executed automatically by the postgres image on the FIRST
-- start of an empty data directory, when this directory is mounted at
-- /docker-entrypoint-initdb.d (see infra/docker-compose.yml, service
-- chirpstack-postgres).
--
-- If the database was created before this file was mounted, create the
-- extension manually:
--   docker exec -it srt-chirpstack-postgres \
--     psql -U chirpstack -d chirpstack -c "CREATE EXTENSION IF NOT EXISTS pg_trgm;"

CREATE EXTENSION IF NOT EXISTS pg_trgm;
