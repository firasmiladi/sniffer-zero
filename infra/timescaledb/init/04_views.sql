-- Analytical views for sniffer-rt
-- Requires: 01_schema.sql (headers, module_results, secrets tables)

-- Flow matrix: cross-protocol source/destination summary for the last hour
CREATE OR REPLACE VIEW v_flow_matrix AS
SELECT
    protocol,
    src                                     AS source,
    dst                                     AS destination,
    COUNT(*)                                AS frame_count,
    MIN(ts)                                 AS first_seen,
    MAX(ts)                                 AS last_seen,
    AVG(rssi_dbm)                           AS avg_rssi,
    COUNT(DISTINCT channel)                 AS channels_used,
    jsonb_agg(DISTINCT fields->>'ssid')
        FILTER (WHERE fields->>'ssid' IS NOT NULL) AS ssids,
    jsonb_agg(DISTINCT fields->>'mtype')
        FILTER (WHERE fields->>'mtype' IS NOT NULL) AS frame_types
FROM headers
WHERE ts > NOW() - INTERVAL '1 hour'
GROUP BY protocol, src, dst
ORDER BY frame_count DESC;

-- Device timeline: hourly first/last seen per device
CREATE OR REPLACE VIEW v_device_timeline AS
SELECT
    time_bucket('1 hour', ts)   AS hour,
    protocol,
    src                         AS identifier,
    COUNT(*)                    AS frame_count,
    MIN(ts)                     AS first_seen,
    MAX(ts)                     AS last_seen,
    AVG(rssi_dbm)               AS avg_rssi
FROM headers
WHERE ts > NOW() - INTERVAL '24 hours'
GROUP BY hour, protocol, src
ORDER BY hour DESC, frame_count DESC;

-- Attack summary: module results aggregation
CREATE OR REPLACE VIEW v_attack_summary AS
SELECT
    module_name,
    protocol,
    COUNT(*)                                              AS total_runs,
    COUNT(*) FILTER (WHERE status = 'ok')                 AS success_count,
    COUNT(*) FILTER (WHERE status = 'fail')               AS fail_count,
    COUNT(*) FILTER (WHERE status = 'aborted')            AS aborted_count,
    COUNT(*) FILTER (WHERE status = 'refused')            AS refused_count,
    MIN(started_at)                                       AS first_run,
    MAX(started_at)                                       AS last_run,
    array_agg(DISTINCT unnested_ttp) FILTER (WHERE unnested_ttp IS NOT NULL) AS mitre_ttps
FROM module_results
LEFT JOIN LATERAL unnest(mitre_ttp) AS unnested_ttp ON TRUE
GROUP BY module_name, protocol
ORDER BY last_run DESC;
