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
    -- Conteneur LXC d'origine quand l'alerte vient de l'auditd de l'hôte pve
    -- (cf. ingest._aplatir). Réattribuée à l'agent propre du conteneur quand il
    -- en a un ; cette colonne trace le conteneur dans tous les cas.
    container     text,
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
    -- audit.uid Linux (pas forcément numérique en JSON audit, d'où text) :
    -- lien de corrélation fort entre alertes auditd du même compte.
    audit_uid     text,
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
    source           text NOT NULL DEFAULT 'auto',   -- 'auto' | 'analyste' | 'humain' | 'training'
    active           boolean NOT NULL DEFAULT true,
    origin_incidents bigint[] NOT NULL DEFAULT '{}',
    fp_count         integer NOT NULL DEFAULT 0,
    created_at       timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS whitelist_active ON whitelist_rules (active);

-- Réputation VirusTotal d'un hash de fichier, mise en cache. La réputation VT
-- d'un exécutable sert de FILTRE déterministe avant corrélation : un exe jugé
-- légitime (aucun moteur positif, hash connu de VT) fait suppress l'alerte qui
-- le porte, pour qu'un binaire propre n'ouvre pas de case (cf. vt.py). Cache
-- indispensable : l'API publique VT est plafonnée (4 req/min, 500/jour). TTL
-- géré côté code (re-vérification au-delà de VT_CACHE_TTL_DAYS) — un hash peut
-- passer de « inconnu » à « malveillant » avec le temps.
CREATE TABLE IF NOT EXISTS vt_file_reputation (
    sha256      text PRIMARY KEY,      -- hash normalisé en minuscules
    malicious   integer NOT NULL DEFAULT 0,
    suspicious  integer NOT NULL DEFAULT 0,
    harmless    integer NOT NULL DEFAULT 0,
    undetected  integer NOT NULL DEFAULT 0,
    total       integer NOT NULL DEFAULT 0,   -- moteurs ayant analysé
    verdict     text NOT NULL,          -- 'legit' | 'malicious' | 'unknown' | 'error'
    permalink   text,
    checked_at  timestamptz NOT NULL DEFAULT now()
);

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

-- ---------------------------------------------------------------------------
-- Rattrapage des alertes indexées en retard
-- ---------------------------------------------------------------------------

-- Date du dernier balayage complet de rattrapage (cf. ingest._sweep_du). Le
-- curseur avance sur la date de l'ÉVÉNEMENT, pas sur celle de son indexation :
-- une alerte rejouée par un agent reconnecté porte un horodatage que le curseur
-- a déjà dépassé, donc `search_after` ne la renverra jamais. Le balayage
-- périodique la récupère ; cette colonne en porte la cadence.
ALTER TABLE ingest_cursor ADD COLUMN IF NOT EXISTS last_sweep_at timestamptz;

-- ---------------------------------------------------------------------------
-- Métriques d'utilisation du modèle
-- ---------------------------------------------------------------------------

-- UN appel LLM = UNE ligne, quel que soit l'appelant.
--
-- Table à part et non colonnes sur `triages` : le triage n'est qu'un des
-- consommateurs du modèle. Le rapport IRIS, le nommage de case et le traitement
-- des tâches de whitelist appellent DeepSeek eux aussi, et leurs tokens
-- n'étaient comptés nulle part — `triages.prompt_tokens` ne voyait ni les
-- tokens de sortie ni les autres appels. Impossible d'estimer un coût réel avec
-- ça.
--
-- L'écriture est faite dans `llm.completion` lui-même, point de passage unique :
-- un nouvel appelant est instrumenté sans qu'on ait à y penser. L'échec
-- d'écriture n'interrompt jamais l'appel (métrique perdue > verdict perdu).
CREATE TABLE IF NOT EXISTS llm_calls (
    id                bigserial PRIMARY KEY,
    ts                timestamptz NOT NULL DEFAULT now(),
    -- Appelant : 'triage', 'report', 'case_name', 'whitelist_task'…
    usage             text NOT NULL,
    modele            text NOT NULL,
    prompt_tokens     integer,
    completion_tokens integer,
    -- Budget demandé. Un `completion_tokens` qui le talonne explique un
    -- finish_reason=length (content vide sur les modèles raisonnants).
    max_tokens        integer,
    duree_ms          integer,
    incident_id       bigint,
    ok                boolean NOT NULL DEFAULT true,
    erreur            text
);

CREATE INDEX IF NOT EXISTS llm_calls_ts ON llm_calls (ts DESC);

-- Ventilation de l'entrée renvoyée par DeepSeek. Le cache hit est facturé 50x
-- moins cher que le cache miss : sans ces deux colonnes, le coût est surestimé,
-- puisque le prompt système est constant d'un incident à l'autre et donc servi
-- par le cache la plupart du temps. NULL sur les appels antérieurs, et sur toute
-- API qui ne fournit pas la ventilation — le calcul retombe alors sur « tout en
-- cache miss », soit une estimation haute.
ALTER TABLE llm_calls ADD COLUMN IF NOT EXISTS cache_hit_tokens integer;
ALTER TABLE llm_calls ADD COLUMN IF NOT EXISTS cache_miss_tokens integer;

-- Machine sur laquelle une remédiation s'applique réellement. Un incident peut
-- désormais couvrir PLUSIEURS agents (fusion campagne, approche A) : la cible
-- (compte, IP, process) ne suffit plus à identifier une action — le même compte
-- peut exister sur deux hôtes. On ancre donc chaque remédiation à son agent, et
-- l'unicité passe de (incident, action, cible) à (incident, action, cible,
-- agent). Défaut '' pour rétro-compat des lignes existantes.
ALTER TABLE mitigations ADD COLUMN IF NOT EXISTS agent_id text NOT NULL DEFAULT '';
ALTER TABLE mitigations DROP CONSTRAINT IF EXISTS mitigations_incident_id_action_cible_key;
CREATE UNIQUE INDEX IF NOT EXISTS mitigations_uniq
    ON mitigations (incident_id, action, cible, agent_id);

-- Compteur d'émissions d'une même remédiation. Une action restée 'émis' (la
-- commande est partie mais aucun `ar-result` n'a confirmé l'effet) n'est PAS
-- terminale : elle doit être réémise au cycle suivant, sinon un compte
-- attaquant recréé n'est jamais désactivé (purple-team #2/#3 : `art-backdoor`
-- figé sur un enregistrement 'émis' hérité, disable_user jamais rejoué). Mais
-- une réémission sans borne inonderait un canal fire-and-forget qui ne confirme
-- jamais : on plafonne à MITIGATE_MAX_TENTATIVES. Le job reconcile (1 min) fait
-- passer 'émis' -> 'confirmé'/'sans_effet' bien avant le cycle suivant (5 min)
-- quand le canal répond ; ne restent 'émis' que les actions réellement sans
-- retour, qu'on retente jusqu'au plafond.
ALTER TABLE mitigations ADD COLUMN IF NOT EXISTS tentatives int NOT NULL DEFAULT 1;

-- Fenêtre d'apprentissage du bruit ambiant (mode « training », cf.
-- training.py). Ouverte au lancement du SOC par l'administrateur, elle dure
-- TRAINING_DAYS jours pendant lesquels le pipeline d'analyse est SUSPENDU
-- (cycle.py teste training.en_cours) et toute alerte HIGH/CRITICAL devient une
-- exception de whitelist.
--
-- `status` seul gouverne la suspension du pipeline : entre l'expiration de
-- `ends_at` et la clôture effective (réapplication du noise filter + case
-- IRIS), la fenêtre reste 'running'. Sinon un cycle passant dans cet
-- intervalle corrélerait le backlog avant que le bruit appris ne soit marqué.
CREATE TABLE IF NOT EXISTS training_runs (
    id            bigserial PRIMARY KEY,
    started_at    timestamptz NOT NULL DEFAULT now(),
    ends_at       timestamptz NOT NULL,
    jours         integer NOT NULL,
    status        text NOT NULL DEFAULT 'running',   -- 'running' | 'finished'
    iris_case_id  bigint,
    finished_at   timestamptz
);

-- Une seule fenêtre ouverte à la fois : deux fenêtres concurrentes rendraient
-- la clôture de l'une insuffisante pour débloquer le pipeline.
CREATE UNIQUE INDEX IF NOT EXISTS training_un_seul_run_actif
    ON training_runs ((status)) WHERE status = 'running';

-- Rattachement d'une exception à sa fenêtre de training et à la tâche IRIS qui
-- la représente dans le case TRAINING. `iris_task_id` est la clé de révocation :
-- la tâche passée en 'Canceled' par l'analyste désactive l'exception
-- (training.reconcilier).
ALTER TABLE whitelist_rules ADD COLUMN IF NOT EXISTS training_run_id bigint
    REFERENCES training_runs(id) ON DELETE SET NULL;
ALTER TABLE whitelist_rules ADD COLUMN IF NOT EXISTS iris_task_id bigint;

-- ---------------------------------------------------------------------------
-- UEBA — analyse comportementale des alertes LOW/MEDIUM (cf. ueba.py)
-- ---------------------------------------------------------------------------
--
-- Le pipeline n'ouvre un incident qu'à partir du niveau 12. En dessous tout est
-- ingéré mais rien ne graine : une intrusion discrète (énumération, binaire
-- déposé, login depuis un pays jamais vu) est invisible. UEBA construit une
-- baseline du comportement normal, score la RARETÉ de ce qui arrive, et promeut
-- en graine les concentrations les mieux notées — dans la limite d'un budget.
--
-- Aucune ingestion nouvelle : tout se calcule sur `alerts` et `alerts.raw`.

-- Fait brut agrégé par jour. Une ligne = (qui, quel trait, quelle valeur, quel
-- jour, combien de fois). C'est la SEULE source de vérité : `ueba_profiles` en
-- est un résumé recalculable, ce qui permet de faire vieillir la baseline en
-- supprimant des jours plutôt qu'en décrémentant des compteurs à l'aveugle.
CREATE TABLE IF NOT EXISTS ueba_observations (
    scope     text NOT NULL,   -- 'host' | 'user@host'
    scope_key text NOT NULL,   -- '002' | 'wazuh-admin@002'
    trait     text NOT NULL,   -- 'exe' | 'parent_child' | 'srcip' | 'pays'…
    valeur    text NOT NULL,
    jour      date NOT NULL,
    nb        integer NOT NULL DEFAULT 0,
    PRIMARY KEY (scope, scope_key, trait, valeur, jour)
);
CREATE INDEX IF NOT EXISTS ueba_obs_jour ON ueba_observations (jour);

-- Résumé roulant par valeur observée.
--
-- `days_seen` (nombre de jours DISTINCTS) porte plus d'information que `total` :
-- 500 exécutions en un seul jour est un incident, 5 exécutions sur 5 jours est
-- une habitude. C'est ce qui décide qu'une valeur cesse d'être scorée.
--
-- `seen_in_tp` : le trait a été impliqué dans un vrai positif. Il ne peut plus
-- JAMAIS devenir une habitude — sans quoi un attaquant patient normalise son
-- propre outillage en le lançant tous les jours. Même garde-fou que la
-- whitelist automatique, qui refuse toute signature déjà vue en TP.
CREATE TABLE IF NOT EXISTS ueba_profiles (
    scope      text NOT NULL,
    scope_key  text NOT NULL,
    trait      text NOT NULL,
    valeur     text NOT NULL,
    total      bigint NOT NULL DEFAULT 0,
    days_seen  integer NOT NULL DEFAULT 0,
    first_seen timestamptz,
    last_seen  timestamptz,
    seen_in_tp boolean NOT NULL DEFAULT false,
    PRIMARY KEY (scope, scope_key, trait, valeur)
);
-- Rareté sur la FLOTTE : sur combien d'hôtes distincts cette valeur est-elle
-- connue ? C'est le principal anti-faux-positif — un binaire inédit sur cet
-- hôte mais présent sur dix autres est un déploiement, pas une intrusion.
CREATE INDEX IF NOT EXISTS ueba_profiles_flotte
    ON ueba_profiles (trait, valeur) WHERE scope = 'host';

-- Totaux par scope, dénominateur du calcul de rareté, et MATURITÉ du profil.
-- Un scope trop jeune n'est pas scoré du tout : le premier jour, tout y est
-- inédit, et scorer enverrait l'intégralité du parc au LLM.
CREATE TABLE IF NOT EXISTS ueba_scopes (
    scope        text NOT NULL,
    scope_key    text NOT NULL,
    trait        text NOT NULL,
    total        bigint NOT NULL DEFAULT 0,
    distincts    integer NOT NULL DEFAULT 0,
    premiere_obs timestamptz,
    derniere_obs timestamptz,
    PRIMARY KEY (scope, scope_key, trait)
);

-- Concentration d'alertes basses jugée anormale sur une machine, dans une
-- fenêtre. Table d'AUDIT autant que de travail : elle garde le score et ses
-- motifs même quand le signal n'est PAS promu, ce qui permet de calibrer le
-- plancher sur des données réelles sans consommer un seul token
-- (`python -m soc_agent.ueba --simulation`).
CREATE TABLE IF NOT EXISTS ueba_signals (
    id          bigserial PRIMARY KEY,
    agent_id    text NOT NULL,
    agent_name  text,
    debut       timestamptz NOT NULL,
    fin         timestamptz NOT NULL,
    score       double precision NOT NULL,
    motifs      jsonb NOT NULL DEFAULT '[]',
    alert_ids   text[] NOT NULL DEFAULT '{}',
    -- 'promu' : les alertes sont devenues grainables (correlate les traite
    -- comme une graine malgré leur niveau). 'en_attente' : sous le plancher ou
    -- budget épuisé — recalculé au cycle suivant, rien n'est perdu.
    statut      text NOT NULL DEFAULT 'en_attente',
    created_at  timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS ueba_signals_statut
    ON ueba_signals (statut, created_at DESC);

-- Marquage des alertes par le moteur.
--   ueba_vu     : déjà passée par l'observation (et donc absorbée dans la
--                 baseline). Le curseur du moteur — on score AVANT d'absorber.
--   ueba_score  : bits d'information portés par l'alerte.
--   ueba_traits : le détail qui explique le score. Sert au prompt LLM ET à
--                 l'analyste : un score sans explication est incontestable,
--                 donc inutilisable.
--   ueba_seed   : promue en graine. C'est le seul drapeau que lit correlate.
ALTER TABLE alerts ADD COLUMN IF NOT EXISTS ueba_vu boolean NOT NULL DEFAULT false;
ALTER TABLE alerts ADD COLUMN IF NOT EXISTS ueba_score double precision;
ALTER TABLE alerts ADD COLUMN IF NOT EXISTS ueba_traits jsonb;
ALTER TABLE alerts ADD COLUMN IF NOT EXISTS ueba_seed boolean NOT NULL DEFAULT false;
ALTER TABLE alerts ADD COLUMN IF NOT EXISTS ueba_signal_id bigint;
CREATE INDEX IF NOT EXISTS alerts_ueba_a_voir
    ON alerts (ts) WHERE NOT ueba_vu;
CREATE INDEX IF NOT EXISTS alerts_ueba_seed
    ON alerts (agent_id, ts) WHERE ueba_seed AND incident_id IS NULL;

-- L'incident vient-il d'un signal UEBA plutôt que d'une graine de niveau >= 12 ?
-- Le triage doit le savoir (son `max_level` est bas, il serait autrement écarté
-- du lot), le prompt doit l'expliquer, et la remédiation autonome est bornée
-- dessus tant que la justesse du moteur n'est pas mesurée (UEBA_MITIGATE).
ALTER TABLE incidents ADD COLUMN IF NOT EXISTS ueba boolean NOT NULL DEFAULT false;
ALTER TABLE incidents ADD COLUMN IF NOT EXISTS ueba_score double precision;
ALTER TABLE incidents ADD COLUMN IF NOT EXISTS ueba_motifs jsonb;
CREATE INDEX IF NOT EXISTS incidents_ueba ON incidents (ueba) WHERE ueba;

-- Pannes de capteur (watchdog.py).
--
-- Une panne est un ÉTAT, pas un événement : le watchdog repasse toutes les deux
-- minutes et reverrait le même capteur muet à chaque tour. Sans cette table il
-- ouvrirait un case IRIS par passage. On y garde donc l'ouverture, le case
-- associé et le rétablissement.
--
-- L'index unique partiel est le garde-fou d'idempotence : une seule panne
-- OUVERTE par (agent, capteur), garantie par la base et pas par une relecture
-- applicative qui peut courir avec elle-même.
CREATE TABLE IF NOT EXISTS capteur_pannes (
    id            bigserial PRIMARY KEY,
    agent_id      text        NOT NULL,
    agent_name    text,
    capteur       text        NOT NULL,
    -- Dernier événement réellement vu de ce capteur : c'est le début de la
    -- panne, pas l'instant où on l'a remarquée.
    dernier_event timestamptz NOT NULL,
    volume_ref    bigint      NOT NULL,
    seuil_minutes integer     NOT NULL,
    detectee_a    timestamptz NOT NULL DEFAULT now(),
    retablie_a    timestamptz,
    iris_case_id  bigint,
    statut        text        NOT NULL DEFAULT 'ouverte'
);
CREATE UNIQUE INDEX IF NOT EXISTS capteur_pannes_une_seule_ouverte
    ON capteur_pannes (agent_id, capteur) WHERE statut = 'ouverte';
CREATE INDEX IF NOT EXISTS capteur_pannes_recentes
    ON capteur_pannes (detectee_a DESC);

-- ---------------------------------------------------------------------------
-- CMDB : priorité des assets (cf. assets.py)
-- ---------------------------------------------------------------------------
--
-- Miroir interrogeable de ce que le manager Wazuh sait de chaque machine, plus
-- ce que lui seul ne sait pas : à quel point elle compte. Sans cette table, le
-- pipeline ne dispose que de `rule_level` — une propriété de la RÈGLE, pas de la
-- machine — et traite un contrôleur de domaine comme un poste de test.
--
-- La source de vérité reste les groupes Wazuh préfixés `role-` : cette table est
-- reconstruisible par `python -m soc_agent.assets --sync`. Une seule chose n'y
-- est pas reconstruisible, et c'est pourquoi `priorite_source` existe : la
-- priorité posée à la main par un opérateur (`operateur`), que la
-- synchronisation ne doit jamais écraser.
CREATE TABLE IF NOT EXISTS assets (
    agent_id        text PRIMARY KEY,
    nom             text,
    ip              text,
    os              text,
    groupes         text[] NOT NULL DEFAULT '{}',
    -- Rôle déclaré (dc, firewall, web…). NULL = jamais déclaré, la priorité
    -- retombe alors sur PRIORITE_DEFAUT.
    role            text,
    priorite        smallint NOT NULL DEFAULT 4 CHECK (priorite BETWEEN 1 AND 4),
    -- 'groupe' (déduite des groupes Wazuh) | 'operateur' (posée à la main,
    -- jamais écrasée) | 'defaut' (aucun rôle déclaré — dette d'inventaire).
    priorite_source text NOT NULL DEFAULT 'defaut',
    notes           text,
    vu_a            timestamptz,
    maj_a           timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS assets_priorite ON assets (priorite);
-- Résolution par nom : les alertes d'un agent CAPTEUR portent le conteneur
-- d'origine (alerts.container), qu'on résout par son nom d'agent.
CREATE INDEX IF NOT EXISTS assets_nom ON assets (nom);

-- Priorité de l'asset touché, et sévérité EFFECTIVE de l'incident.
--
-- Colonnes distinctes de `max_level`, qui n'est PAS modifié : il décrit ce que
-- la règle Wazuh a vu, et la corrélation, UEBA, les seuils de compromission et
-- le garde-fou de clôture s'appuient dessus. Décaler `max_level` selon l'asset
-- changerait silencieusement le sens de tous ces seuils. La sévérité est une
-- seconde grandeur : « à quel point ça tire » x « sur quoi ».
--
-- Figées à la création de l'incident plutôt que calculées à la lecture : la
-- priorité d'une machine change (reclassement, changement de rôle), et un
-- incident doit rester lisible avec le contexte qui était le sien.
ALTER TABLE incidents ADD COLUMN IF NOT EXISTS priorite smallint;
ALTER TABLE incidents ADD COLUMN IF NOT EXISTS severite smallint;
CREATE INDEX IF NOT EXISTS incidents_priorite ON incidents (priorite, severite DESC);

-- Rôle de l'asset TEL QU'IL A COMPTÉ pour cet incident. Figé à l'ouverture,
-- comme la priorité, et pour la même raison — mais aussi parce que le rôle
-- déclaré dans `assets` et celui qui a servi au calcul peuvent DIVERGER : sur un
-- agent capteur, la priorité est rabattue et le rôle vaut « capteur », pas
-- « firewall ». Une jointure sur `assets` au moment de la lecture affichait donc
-- « P3 — firewall (serveur interne sans exposition) », qui se contredit tout
-- seul. Constaté sur l'incident #2829 (pfSense) le 2026-08-12.
ALTER TABLE incidents ADD COLUMN IF NOT EXISTS asset_role text;

-- ---------------------------------------------------------------------------
-- VOC : cycle de vie des vulnérabilités (cf. vulns.py)
-- ---------------------------------------------------------------------------
--
-- Pourquoi une table ici alors que Wazuh a déjà `wazuh-states-vulnerabilities-*` :
-- cet index est un index d'ÉTAT. Quand un paquet est corrigé, Wazuh SUPPRIME le
-- document. On y lit donc en permanence « ce qui est ouvert maintenant », et
-- jamais « combien y en avait-il il y a un mois », ni « en combien de temps
-- corrige-t-on ». Les deux questions d'un VOC sont précisément celles-là.
--
-- Cette table est donc le JOURNAL que l'index d'état n'est pas : une ligne par
-- (machine, CVE, paquet), qui naît à la première observation, se met à jour tant
-- que la vulnérabilité est vue, et est CLÔTURÉE (jamais supprimée) quand elle
-- disparaît de l'inventaire.
CREATE TABLE IF NOT EXISTS vulnerabilites (
    id            bigserial PRIMARY KEY,
    agent_id      text NOT NULL,
    agent_name    text,
    cve           text NOT NULL,
    -- Le paquet, pas sa VERSION, fait partie de la clé. Une montée de version
    -- qui ne corrige pas la CVE (backport, correctif partiel) doit prolonger la
    -- même ligne : sinon chaque `apt upgrade` fabriquerait une résolution et une
    -- réapparition, et le MTTR mesurerait la cadence des mises à jour au lieu du
    -- délai de correction.
    paquet        text NOT NULL,
    version       text,
    severite      text NOT NULL DEFAULT '',
    score_base    real,
    -- Date de publication de la CVE, telle que le feed la donne. Sert à
    -- distinguer « ouverte depuis longtemps chez nous » de « publiée hier » :
    -- une CVE de 2019 encore ouverte est une dette, une CVE d'hier est normale.
    publiee_a     timestamptz,
    -- Première observation PAR NOUS. Distincte de `vulnerability.detected_at`
    -- de Wazuh, qui se réinitialise quand le scanner recalcule : le SLA doit
    -- courir depuis une date stable, sinon un redémarrage du manager remet tous
    -- les compteurs de retard à zéro et le VOC se félicite tout seul.
    vue_a         timestamptz NOT NULL DEFAULT now(),
    derniere_vue  timestamptz NOT NULL DEFAULT now(),
    -- Renseignée quand la vulnérabilité disparaît de l'inventaire de la machine.
    -- La ligne n'est PAS supprimée : c'est elle qui porte l'historique de
    -- remédiation, donc le seul MTTR mesurable.
    corrigee_a    timestamptz,
    statut        text NOT NULL DEFAULT 'ouverte',
    os_nom        text,
    UNIQUE (agent_id, cve, paquet)
);
CREATE INDEX IF NOT EXISTS vuln_ouvertes
    ON vulnerabilites (agent_id, severite) WHERE statut = 'ouverte';
CREATE INDEX IF NOT EXISTS vuln_corrigees ON vulnerabilites (corrigee_a)
    WHERE corrigee_a IS NOT NULL;
CREATE INDEX IF NOT EXISTS vuln_cve ON vulnerabilites (cve);

-- Un passage du scanner. Sert à deux choses, dont une vitale :
--
-- 1. tracer la couverture (combien de machines ont réellement répondu) ;
-- 2. GARDE-FOU de clôture. Une machine dont l'agent est arrêté, ou dont
--    syscollector est cassé, disparaît de l'index d'état — ses vulnérabilités
--    aussi. Sans mémoire des agents VUS à ce passage, le diff conclurait que
--    tout a été corrigé d'un coup : burn-down parfait, MTTR magnifique, et un
--    parc devenu invisible. On ne clôture donc QUE sur les agents qui ont
--    effectivement répondu à ce scan.
CREATE TABLE IF NOT EXISTS vuln_scans (
    id             bigserial PRIMARY KEY,
    lance_a        timestamptz NOT NULL DEFAULT now(),
    agents_vus     integer NOT NULL DEFAULT 0,
    vulns_vues     integer NOT NULL DEFAULT 0,
    nouvelles      integer NOT NULL DEFAULT 0,
    corrigees      integer NOT NULL DEFAULT 0,
    agents_muets   text[] NOT NULL DEFAULT '{}'
);
CREATE INDEX IF NOT EXISTS vuln_scans_recents ON vuln_scans (lance_a DESC);
