-- sniffer-rt initial schema
-- Idempotent: safe to re-run.

CREATE EXTENSION IF NOT EXISTS timescaledb;
CREATE EXTENSION IF NOT EXISTS pgcrypto;

-- Sessions: one row per `srt run ...` invocation
CREATE TABLE IF NOT EXISTS sessions (
    id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    started_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    ended_at     TIMESTAMPTZ,
    operator     TEXT NOT NULL,
    scenario     TEXT,
    auth_doc_sha TEXT,
    notes        TEXT
);

-- Captures: one row per pcap/cfile artifact
CREATE TABLE IF NOT EXISTS captures (
    id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    session_id   UUID REFERENCES sessions(id) ON DELETE CASCADE,
    started_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    protocol     TEXT NOT NULL,
    path         TEXT NOT NULL,
    bytes        BIGINT,
    sha256       TEXT
);

-- Headers (time-series hypertable). Payload-free by design.
CREATE TABLE IF NOT EXISTS headers (
    ts           TIMESTAMPTZ NOT NULL,
    session_id   UUID,
    protocol     TEXT NOT NULL,
    src          TEXT,
    dst          TEXT,
    channel      INTEGER,
    freq_hz      BIGINT,
    rssi_dbm     SMALLINT,
    snr_db       REAL,
    fields       JSONB NOT NULL DEFAULT '{}'::jsonb
);

SELECT create_hypertable('headers', 'ts', if_not_exists => TRUE, chunk_time_interval => INTERVAL '1 day');

CREATE INDEX IF NOT EXISTS idx_headers_protocol_ts ON headers (protocol, ts DESC);
CREATE INDEX IF NOT EXISTS idx_headers_session_ts  ON headers (session_id, ts DESC);
CREATE INDEX IF NOT EXISTS idx_headers_src         ON headers (src);
CREATE INDEX IF NOT EXISTS idx_headers_fields_gin  ON headers USING GIN (fields);

-- Module results: one row per AttackModule.run() return
CREATE TABLE IF NOT EXISTS module_results (
    id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    session_id   UUID REFERENCES sessions(id) ON DELETE CASCADE,
    module_name  TEXT NOT NULL,
    protocol     TEXT NOT NULL,
    risk         TEXT NOT NULL,
    started_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    ended_at     TIMESTAMPTZ,
    status       TEXT NOT NULL,        -- ok | fail | aborted | refused
    mitre_ttp    TEXT[],
    cve          TEXT[],
    summary      TEXT,
    artifacts    JSONB NOT NULL DEFAULT '[]'::jsonb,
    metrics      JSONB NOT NULL DEFAULT '{}'::jsonb
);

CREATE INDEX IF NOT EXISTS idx_results_session   ON module_results (session_id);
CREATE INDEX IF NOT EXISTS idx_results_protocol  ON module_results (protocol);

-- Cracked secrets: hashes / keys captured in the lab.
CREATE TABLE IF NOT EXISTS secrets (
    id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    session_id   UUID REFERENCES sessions(id) ON DELETE CASCADE,
    discovered_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    kind         TEXT NOT NULL,        -- pmkid | eapol | ltk | psk | appkey ...
    target       TEXT,                 -- BSSID / DevEUI / ...
    state        TEXT NOT NULL,        -- captured | cracked | failed
    value_enc    BYTEA,                -- encrypted at rest in production
    notes        TEXT
);

-- Convenience views
CREATE OR REPLACE VIEW v_recent_devices AS
SELECT
    protocol,
    src           AS identifier,
    COUNT(*)      AS frames,
    MAX(ts)       AS last_seen,
    MIN(ts)       AS first_seen,
    AVG(rssi_dbm) AS avg_rssi
FROM headers
WHERE ts > NOW() - INTERVAL '24 hours'
GROUP BY protocol, src
ORDER BY last_seen DESC;
