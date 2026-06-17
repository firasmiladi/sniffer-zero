-- Continuous aggregates for sniffer-rt
-- Requires: 01_schema.sql (headers hypertable)

-- Device activity: 5-minute buckets per protocol/source
CREATE MATERIALIZED VIEW IF NOT EXISTS mv_device_activity
WITH (timescaledb.continuous) AS
SELECT
    time_bucket('5 minutes', ts) AS bucket,
    protocol,
    src                          AS identifier,
    COUNT(*)                     AS frame_count,
    AVG(rssi_dbm)                AS avg_rssi,
    MIN(rssi_dbm)                AS min_rssi,
    MAX(rssi_dbm)                AS max_rssi
FROM headers
GROUP BY bucket, protocol, src
WITH NO DATA;

SELECT add_continuous_aggregate_policy('mv_device_activity',
    start_offset  => INTERVAL '1 hour',
    end_offset    => INTERVAL '5 minutes',
    schedule_interval => INTERVAL '5 minutes',
    if_not_exists => TRUE
);

-- Protocol frame rates: 1-minute buckets per protocol
CREATE MATERIALIZED VIEW IF NOT EXISTS mv_protocol_rates
WITH (timescaledb.continuous) AS
SELECT
    time_bucket('1 minute', ts) AS bucket,
    protocol,
    COUNT(*)                    AS frames_per_min
FROM headers
GROUP BY bucket, protocol
WITH NO DATA;

SELECT add_continuous_aggregate_policy('mv_protocol_rates',
    start_offset  => INTERVAL '1 hour',
    end_offset    => INTERVAL '1 minute',
    schedule_interval => INTERVAL '1 minute',
    if_not_exists => TRUE
);
