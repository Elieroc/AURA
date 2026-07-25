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
    -- Suppression post-retrieval du noise filter (query_level: false). L'alerte
    -- est ingérée et conservée pour l'audit, mais exclue de la corrélation. Les
    -- entrées query_level: true, elles, ne sont jamais ingérées (must_not
    -- OpenSearch) et n'apparaissent donc pas ici.
    suppressed     boolean NOT NULL DEFAULT false,
    suppress_reason text,
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

-- ---------------------------------------------------------------------------
-- Whitelist automatique
-- ---------------------------------------------------------------------------

-- Exceptions générées par l'IA à partir des faux positifs récurrents.
--
-- Table distincte du noise_filter.yaml (édité par un humain) : on ne veut pas
-- qu'un processus automatique réécrive un fichier versionné que l'analyste
-- édite aussi. noise.py lit les DEUX sources. Une exception auto reste
-- traçable (incidents d'origine, compte de FP) et désactivable sans toucher au
-- code.
--
-- match_all : conjonction de champs (mêmes clés que le noise filter —
-- rule_id, src_user, dst_user, command, agent_name, agent_id). Toujours
-- post-retrieval : l'alerte est ingérée et conservée pour l'audit, jamais
-- écartée en silence côté indexer. Une whitelist auto trop large doit rester
-- rattrapable.
CREATE TABLE IF NOT EXISTS whitelist_rules (
    id               bigserial PRIMARY KEY,
    signature        text UNIQUE NOT NULL,   -- forme canonique de match_all, anti-doublon
    match_all        jsonb NOT NULL,
    reason           text NOT NULL,
    source           text NOT NULL DEFAULT 'auto',   -- 'auto' | 'analyste' | 'humain'
    active           boolean NOT NULL DEFAULT true,
    origin_incidents bigint[] NOT NULL DEFAULT '{}',
    fp_count         integer NOT NULL DEFAULT 0,
    created_at       timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS whitelist_active ON whitelist_rules (active);

-- Case IRIS créé pour l'incident (un par incident trié). NULL tant que non
-- créé ; sert de garde anti-doublon au cycle.
ALTER TABLE incidents ADD COLUMN IF NOT EXISTS iris_case_id bigint;

-- Marqueur « l'incident a gagné de nouvelles alertes depuis son dernier
-- traitement ». Posé par la corrélation quand une salve d'une intrusion EN
-- COURS est rattachée à un incident déjà formé (le découpage en lots du cycle
-- ne doit pas rouvrir un incident neuf par salve). Consommé par le triage (on
-- rejoue le verdict) puis par IRIS (on MET À JOUR le case existant au lieu
-- d'en créer un doublon), qui le remet à false.
ALTER TABLE incidents ADD COLUMN IF NOT EXISTS needs_refresh boolean NOT NULL DEFAULT false;
CREATE INDEX IF NOT EXISTS incidents_needs_refresh
    ON incidents (needs_refresh) WHERE needs_refresh;

-- ---------------------------------------------------------------------------
-- Pseudonymisation avant envoi au LLM cloud (DeepSeek)
-- ---------------------------------------------------------------------------

-- Correspondance jeton -> valeur réelle, par incident. Les données SOC partent
-- vers le cloud pseudonymisées ; cette table permet de RÉHYDRATER la réponse du
-- modèle (l'analyste voit les vraies valeurs dans IRIS) et garantit des jetons
-- STABLES au re-triage (comparabilité entre passages).
--
-- Contient des valeurs sensibles en clair — mais les mêmes que `alerts.raw`, et
-- au même endroit (Postgres loopback) : aucune nouvelle exposition. Ne doit
-- jamais quitter l'hôte.
CREATE TABLE IF NOT EXISTS anonymization_map (
    incident_id bigint PRIMARY KEY REFERENCES incidents(id) ON DELETE CASCADE,
    mapping     jsonb NOT NULL DEFAULT '{}',
    updated_at  timestamptz NOT NULL DEFAULT now()
);

-- ---------------------------------------------------------------------------
-- Remédiation exécutée (mitigate.py)
-- ---------------------------------------------------------------------------

-- Trace de chaque action de remédiation tentée sur un incident. Sert à
-- l'audit (qui/quoi/quand), à l'idempotence (ne pas ré-isoler un hôte déjà
-- isolé) et à porter la procédure d'ANNULATION — chaque mitigation doit
-- pouvoir être défaite.
--
-- Le couple (incident, action, cible) est unique : rejouer le cycle ne
-- réapplique pas une remédiation déjà passée.
CREATE TABLE IF NOT EXISTS mitigations (
    id           bigserial PRIMARY KEY,
    incident_id  bigint NOT NULL REFERENCES incidents(id) ON DELETE CASCADE,
    action       text NOT NULL,
    cible        text,            -- agent_id, IP ou compte visé
    statut       text NOT NULL,   -- exécuté | dry_run | échec | annulé |
                                  -- annulation_impossible | suspendu
                                  -- 'annulé' : action défaite (tâche IRIS passée
                                  -- en Canceled → reverse rejoué, cf. reconcilier).
    details      text,
    undo         text,            -- commande / procédure d'annulation
    iris_note_id bigint,          -- legacy : remédiations autrefois en notes
    -- Tâche IRIS (onglet Tasks) portant cette remédiation. Les remédiations ne
    -- sont plus des notes : chaque action est une task, ses cibles des assets.
    iris_task_id bigint,
    executed_at  timestamptz NOT NULL DEFAULT now(),
    UNIQUE (incident_id, action, cible)
);

CREATE INDEX IF NOT EXISTS mitigations_incident ON mitigations (incident_id);
