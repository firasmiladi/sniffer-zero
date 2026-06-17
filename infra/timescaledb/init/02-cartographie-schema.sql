-- Schema de base de données pour la Cartographie RF
-- Ministère de la Défense - Projet DEF-RF-2024-001
-- Classification: DEFENSE SECRET

CREATE SCHEMA IF NOT EXISTS cartographie;

-- Table principale des émetteurs détectés
CREATE TABLE IF NOT EXISTS cartographie.emetteurs (
    id_unique TEXT PRIMARY KEY,
    adresse_mac TEXT,
    ssid TEXT,
    nom TEXT NOT NULL,
    type_emetteur TEXT NOT NULL DEFAULT 'inconnu',
    priorite INTEGER DEFAULT 50,
    affiliation TEXT DEFAULT 'inconnu',
    niveau_menace INTEGER DEFAULT 0,
    premiere_detection TIMESTAMPTZ NOT NULL,
    derniere_detection TIMESTAMPTZ NOT NULL,
    duree_activite_minutes FLOAT DEFAULT 0,
    couleur TEXT DEFAULT '#808080',
    icone TEXT DEFAULT 'radio',
    metadata JSONB DEFAULT '{}',
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW()
);

-- Table des signaux détectés (time-series)
CREATE TABLE IF NOT EXISTS cartographie.signaux (
    timestamp TIMESTAMPTZ NOT NULL,
    emetteur_id TEXT REFERENCES cartographie.emetteurs(id_unique),
    frequence_centre_mhz FLOAT NOT NULL,
    bande_passante_khz FLOAT,
    puissance_dbm FLOAT NOT NULL,
    snr_db FLOAT,
    modulation TEXT,
    bande_ism TEXT,
    protocole_estime TEXT,
    empreinte_spectrale TEXT,
    metadata JSONB DEFAULT '{}'
);


-- Convertir en hypertable TimescaleDB
SELECT create_hypertable('cartographie.signaux', 'timestamp',
    if_not_exists => TRUE);

-- Table des positions (time-series pour le tracking)
CREATE TABLE IF NOT EXISTS cartographie.positions (
    timestamp TIMESTAMPTZ NOT NULL,
    emetteur_id TEXT REFERENCES cartographie.emetteurs(id_unique),
    x FLOAT,
    y FLOAT,
    z FLOAT,
    latitude FLOAT,
    longitude FLOAT,
    altitude FLOAT,
    incertitude_m FLOAT DEFAULT 10.0,
    methode_localisation TEXT DEFAULT 'rssi'
);

SELECT create_hypertable('cartographie.positions', 'timestamp',
    if_not_exists => TRUE);

-- Table des alertes
CREATE TABLE IF NOT EXISTS cartographie.alertes (
    timestamp TIMESTAMPTZ NOT NULL,
    emetteur_id TEXT,
    type_alerte TEXT NOT NULL,
    niveau_menace INTEGER NOT NULL,
    description TEXT,
    action_requise TEXT,
    statut TEXT DEFAULT 'active',
    metadata JSONB DEFAULT '{}'
);

SELECT create_hypertable('cartographie.alertes', 'timestamp',
    if_not_exists => TRUE);

-- Table des balayages spectraux
CREATE TABLE IF NOT EXISTS cartographie.balayages (
    timestamp TIMESTAMPTZ NOT NULL,
    freq_debut_mhz FLOAT NOT NULL,
    freq_fin_mhz FLOAT NOT NULL,
    nb_signaux_detectes INTEGER DEFAULT 0,
    nb_nouveaux_emetteurs INTEGER DEFAULT 0,
    duree_ms FLOAT,
    metadata JSONB DEFAULT '{}'
);

SELECT create_hypertable('cartographie.balayages', 'timestamp',
    if_not_exists => TRUE);

-- Index pour requêtes rapides
CREATE INDEX IF NOT EXISTS idx_signaux_emetteur
    ON cartographie.signaux (emetteur_id, timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_signaux_freq
    ON cartographie.signaux (frequence_centre_mhz);
CREATE INDEX IF NOT EXISTS idx_positions_emetteur
    ON cartographie.positions (emetteur_id, timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_emetteurs_type
    ON cartographie.emetteurs (type_emetteur);
CREATE INDEX IF NOT EXISTS idx_emetteurs_menace
    ON cartographie.emetteurs (niveau_menace DESC);
CREATE INDEX IF NOT EXISTS idx_alertes_statut
    ON cartographie.alertes (statut, timestamp DESC);

-- Vue matérialisée: résumé par bande
CREATE MATERIALIZED VIEW IF NOT EXISTS cartographie.resume_bandes AS
SELECT
    bande_ism,
    count(DISTINCT emetteur_id) as nb_emetteurs,
    count(*) as nb_signaux,
    avg(puissance_dbm) as puissance_moyenne,
    max(puissance_dbm) as puissance_max,
    min(puissance_dbm) as puissance_min
FROM cartographie.signaux
WHERE timestamp > NOW() - INTERVAL '1 hour'
GROUP BY bande_ism;

-- Vue: émetteurs actifs avec dernière position
CREATE OR REPLACE VIEW cartographie.emetteurs_actifs AS
SELECT
    e.*,
    p.x as derniere_x,
    p.y as derniere_y,
    p.z as derniere_z,
    p.incertitude_m as derniere_incertitude,
    s.frequence_centre_mhz as derniere_frequence,
    s.puissance_dbm as derniere_puissance
FROM cartographie.emetteurs e
LEFT JOIN LATERAL (
    SELECT * FROM cartographie.positions
    WHERE emetteur_id = e.id_unique
    ORDER BY timestamp DESC LIMIT 1
) p ON true
LEFT JOIN LATERAL (
    SELECT * FROM cartographie.signaux
    WHERE emetteur_id = e.id_unique
    ORDER BY timestamp DESC LIMIT 1
) s ON true
WHERE e.derniere_detection > NOW() - INTERVAL '30 minutes';

-- Fonction: mise à jour automatique du niveau de menace
CREATE OR REPLACE FUNCTION cartographie.update_menace_niveau()
RETURNS TRIGGER AS $$
BEGIN
    UPDATE cartographie.emetteurs
    SET niveau_menace = CASE
        WHEN type_emetteur IN ('brouilleur', 'drone_militaire') THEN 90
        WHEN type_emetteur = 'inconnu' AND NEW.puissance_dbm > -30 THEN 75
        WHEN type_emetteur = 'drone_commercial' THEN 60
        ELSE niveau_menace
    END,
    updated_at = NOW()
    WHERE id_unique = NEW.emetteur_id;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trigger_update_menace
    AFTER INSERT ON cartographie.signaux
    FOR EACH ROW
    EXECUTE FUNCTION cartographie.update_menace_niveau();
