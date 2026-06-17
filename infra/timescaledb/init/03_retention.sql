-- Compression and retention policies for sniffer-rt
-- Requires: 01_schema.sql (headers hypertable)
--
-- Strategy:
--   * Raw headers kept for 30 days (then auto-dropped)
--   * Chunks older than 7 days are compressed (10-20x space reduction)
--   * Continuous aggregates (mv_*) are kept indefinitely for trend analysis

-- Enable native compression on the headers hypertable
ALTER TABLE headers SET (
    timescaledb.compress,
    timescaledb.compress_segmentby = 'protocol',
    timescaledb.compress_orderby   = 'ts DESC'
);

-- Compress chunks older than 7 days
SELECT add_compression_policy('headers', INTERVAL '7 days', if_not_exists => TRUE);

-- Drop raw chunks older than 30 days
SELECT add_retention_policy('headers', INTERVAL '30 days', if_not_exists => TRUE);
