-- Schéma du soc-agent, phase 1 (ingest + corrélation, sans LLM).

-- Curseur d'ingestion. Une seule ligne.
--
-- Le couple (timestamp, id) sert de position de reprise : trier sur le seul
-- timestamp ne suffit pas, plusieurs alertes partagent la même milliseconde
-- (les 25 alertes canari ont toutes le même @timestamp). Sans le second
-- critère, une reprise saute ou rejoue une partie du lot.
CREATE TABLE IF NOT EXISTS ingest_cursor (
    id            boolean PRIMARY KEY DEFAULT true CHECK (id),
    last_ts       timestamptz,
    last_alert_id text,
    updated_at    timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS incidents (
    id             bigserial PRIMARY KEY,
    agent_id       text NOT NULL,
    agent_name     text,
    first_seen     timestamptz NOT NULL,
    last_seen      timestamptz NOT NULL,
    alert_count    integer NOT NULL DEFAULT 0,
    max_level      integer NOT NULL DEFAULT 0,
    rule_ids       text[] NOT NULL DEFAULT '{}',
    mitre_tactics  text[] NOT NULL DEFAULT '{}',
    entities       text[] NOT NULL DEFAULT '{}',
    -- 'new' tant que la phase 2 (triage LLM) n'y a pas touché.
    status         text NOT NULL DEFAULT 'new',
    created_at     timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS incidents_agent_last_seen
    ON incidents (agent_id, last_seen DESC);
CREATE INDEX IF NOT EXISTS incidents_status ON incidents (status);

CREATE TABLE IF NOT EXISTS alerts (
    -- Identifiant natif Wazuh (champ « id », p.ex. 1784709916.5500471). Clé
    -- primaire plutôt que l'_id de l'indexer : il est stable si l'alerte est
    -- réindexée, ce qui rend l'ingestion idempotente et permet de rejouer une
    -- fenêtre sans créer de doublons.
    id            text PRIMARY KEY,
    ts            timestamptz NOT NULL,
    agent_id      text NOT NULL,
    agent_name    text,
    rule_id       text NOT NULL,
    rule_level    integer NOT NULL,
    rule_desc     text,
    rule_groups   text[] NOT NULL DEFAULT '{}',
    mitre_ids     text[] NOT NULL DEFAULT '{}',
    mitre_tactics text[] NOT NULL DEFAULT '{}',
    srcip         text,
    srcuser       text,
    -- Objet concerné : chemin de fichier, processus, hash… Sert de critère de
    -- rapprochement entre alertes de règles différentes.
    entity        text,
    raw           jsonb NOT NULL,
    incident_id   bigint REFERENCES incidents(id) ON DELETE SET NULL,
    ingested_at   timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS alerts_ts ON alerts (ts DESC);
CREATE INDEX IF NOT EXISTS alerts_incident ON alerts (incident_id);
-- Index de travail de la corrélation : elle balaye les alertes non rattachées
-- d'un agent par ordre chronologique.
CREATE INDEX IF NOT EXISTS alerts_unlinked
    ON alerts (agent_id, ts) WHERE incident_id IS NULL;

-- ---------------------------------------------------------------------------
-- Phase 2 : triage LLM
-- ---------------------------------------------------------------------------

-- Un verdict rendu par le modèle sur un incident.
--
-- Table à part et non colonnes sur `incidents` : on veut pouvoir rejouer le
-- même incident après un changement de prompt ou de modèle et COMPARER, pas
-- écraser. C'est la seule façon de savoir si une modification améliore ou
-- dégrade.
CREATE TABLE IF NOT EXISTS triages (
    id            bigserial PRIMARY KEY,
    incident_id   bigint NOT NULL REFERENCES incidents(id) ON DELETE CASCADE,
    verdict       text NOT NULL,
    confidence    text NOT NULL,
    mitre         text,
    actions       text[] NOT NULL DEFAULT '{}',
    reason        text NOT NULL,
    -- Traçabilité : sans le modèle et l'empreinte du prompt, un écart entre
    -- deux passages est ininterprétable.
    modele        text NOT NULL,
    prompt_sha    text NOT NULL,
    prompt_tokens integer,
    duree_ms      integer,
    -- 'shadow' : le verdict est enregistré, rien n'est déclenché. Tant que la
    -- justesse n'est pas mesurée sur un jeu labellisé, on n'agit pas.
    mode          text NOT NULL DEFAULT 'shadow',
    created_at    timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS triages_incident ON triages (incident_id, created_at DESC);

-- Vérité terrain, saisie par un analyste humain.
--
-- Sans elle, on sait seulement que le modèle répond, pas s'il a raison. C'est
-- le prérequis à toute sortie du mode shadow.
CREATE TABLE IF NOT EXISTS labels (
    incident_id     bigint PRIMARY KEY REFERENCES incidents(id) ON DELETE CASCADE,
    verdict         text NOT NULL
        CHECK (verdict IN ('true_positive', 'false_positive', 'needs_investigation')),
    actions         text[] NOT NULL DEFAULT '{}',
    commentaire     text,
    -- 'humain' vs 'synthetique' : un jeu d'amorçage fabriqué ne doit jamais
    -- être confondu avec des cas réellement observés et jugés.
    origine         text NOT NULL DEFAULT 'humain',
    labellise_par   text,
    created_at      timestamptz NOT NULL DEFAULT now()
);

-- Incohérences verdict/actions relevées par coherence.py. Colonne et non
-- table : c'est une propriété du triage, pas une entité. Un taux qui monte
-- signale un prompt dégradé, et se mesure sans jeu labellisé.
ALTER TABLE triages ADD COLUMN IF NOT EXISTS incoherences text[] NOT NULL DEFAULT '{}';

-- Motifs d'injection repérés dans les données de l'incident, et interventions
-- des garde-fous déterministes. Mesuré : 3 charges d'injection sur 4
-- retournent le verdict du modèle. On trace donc à la fois ce qu'on a vu
-- passer et ce qu'on a refusé.
ALTER TABLE triages ADD COLUMN IF NOT EXISTS injection_motifs text[] NOT NULL DEFAULT '{}';
ALTER TABLE triages ADD COLUMN IF NOT EXISTS garde_fous text[] NOT NULL DEFAULT '{}';
