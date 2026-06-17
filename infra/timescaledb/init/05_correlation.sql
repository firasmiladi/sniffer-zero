-- 05_correlation.sql
-- Cross-protocol correlation views for sniffer-rt.
-- These views enable the "killer feature": linking devices across protocols.

-- --------------------------------------------------------------------------
-- v_cross_protocol_correlation
-- Correlate WiFi and BLE devices by OUI (first 3 bytes = 8 chars of MAC)
-- and time proximity (within 5 seconds).
-- --------------------------------------------------------------------------
CREATE OR REPLACE VIEW v_cross_protocol_correlation AS
SELECT
    w.src                                        AS wifi_mac,
    b.src                                        AS ble_mac,
    w.fields->>'ssid'                            AS wifi_ssid,
    b.fields->>'name'                            AS ble_name,
    ABS(EXTRACT(EPOCH FROM w.ts - b.ts))         AS time_delta,
    AVG(w.rssi_dbm)                              AS avg_wifi_rssi,
    AVG(b.rssi_dbm)                              AS avg_ble_rssi
FROM headers w
JOIN headers b
    ON SUBSTRING(w.src, 1, 8) = SUBSTRING(b.src, 1, 8)
    AND ABS(EXTRACT(EPOCH FROM w.ts - b.ts)) < 5
WHERE w.protocol = 'wifi'
  AND b.protocol = 'ble'
GROUP BY w.src, b.src, w.fields->>'ssid', b.fields->>'name',
         ABS(EXTRACT(EPOCH FROM w.ts - b.ts));


-- --------------------------------------------------------------------------
-- v_device_presence
-- Timeline of device presence per protocol: first/last seen, frame count,
-- signal strength, and active duration.
-- --------------------------------------------------------------------------
CREATE OR REPLACE VIEW v_device_presence AS
SELECT
    protocol,
    src                                          AS device_id,
    MIN(ts)                                      AS first_seen,
    MAX(ts)                                      AS last_seen,
    COUNT(*)                                     AS total_frames,
    AVG(rssi_dbm)                                AS avg_rssi,
    EXTRACT(EPOCH FROM MAX(ts) - MIN(ts))        AS time_active_s
FROM headers
WHERE src IS NOT NULL
GROUP BY protocol, src
ORDER BY last_seen DESC;


-- --------------------------------------------------------------------------
-- v_protocol_cooccurrence
-- Which protocols are seen in the same time window (10s buckets),
-- correlated by device OUI (first 8 chars of MAC/identifier).
-- --------------------------------------------------------------------------
CREATE OR REPLACE VIEW v_protocol_cooccurrence AS
SELECT
    a.protocol                                   AS protocol_a,
    b.protocol                                   AS protocol_b,
    SUBSTRING(a.src, 1, 8)                       AS oui,
    COUNT(*)                                     AS co_occurrences,
    MIN(a.ts)                                    AS first_co_seen,
    MAX(a.ts)                                    AS last_co_seen
FROM headers a
JOIN headers b
    ON SUBSTRING(a.src, 1, 8) = SUBSTRING(b.src, 1, 8)
    AND a.protocol < b.protocol
    AND ABS(EXTRACT(EPOCH FROM a.ts - b.ts)) < 10
WHERE a.src IS NOT NULL
  AND b.src IS NOT NULL
GROUP BY a.protocol, b.protocol, SUBSTRING(a.src, 1, 8)
ORDER BY co_occurrences DESC;


-- --------------------------------------------------------------------------
-- v_device_inventory
-- Unified device inventory across all protocols, deduplicated by OUI.
-- Shows all known identifiers per OUI group.
-- --------------------------------------------------------------------------
CREATE OR REPLACE VIEW v_device_inventory AS
SELECT
    SUBSTRING(src, 1, 8)                         AS oui,
    ARRAY_AGG(DISTINCT protocol)                 AS protocols,
    ARRAY_AGG(DISTINCT src)                      AS identifiers,
    COUNT(*)                                     AS total_frames,
    MIN(ts)                                      AS first_seen,
    MAX(ts)                                      AS last_seen,
    AVG(rssi_dbm)                                AS avg_rssi
FROM headers
WHERE src IS NOT NULL
GROUP BY SUBSTRING(src, 1, 8)
ORDER BY total_frames DESC;
