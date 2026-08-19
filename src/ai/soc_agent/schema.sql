-- soc-agent schema, phase 1 (ingest + correlation, no LLM).

-- Ingestion cursor. A single row.
--
-- The (timestamp, id) pair serves as the resume position: sorting on
-- timestamp alone is not enough, several alerts share the same millisecond
-- (all 25 canary alerts share the same @timestamp). Without the second
-- criterion, a resume skips or replays part of the batch.
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
    -- 'new' as long as phase 2 (LLM triage) has not touched it.
    status         text NOT NULL DEFAULT 'new',
    created_at     timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS incidents_agent_last_seen
    ON incidents (agent_id, last_seen DESC);
CREATE INDEX IF NOT EXISTS incidents_status ON incidents (status);

CREATE TABLE IF NOT EXISTS alerts (
    -- Native Wazuh identifier (the "id" field, e.g. 1784709916.5500471). Used
    -- as primary key rather than the indexer's _id: it stays stable if the
    -- alert is re-indexed, which makes ingestion idempotent and lets a window
    -- be replayed without creating duplicates.
    id            text PRIMARY KEY,
    ts            timestamptz NOT NULL,
    agent_id      text NOT NULL,
    agent_name    text,
    -- Originating LXC container when the alert comes from the pve host's
    -- auditd (cf. ingest._flatten). Reassigned to the container's own agent
    -- when it has one; this column tracks the container in every case.
    container     text,
    rule_id       text NOT NULL,
    rule_level    integer NOT NULL,
    rule_desc     text,
    rule_groups   text[] NOT NULL DEFAULT '{}',
    mitre_ids     text[] NOT NULL DEFAULT '{}',
    mitre_tactics text[] NOT NULL DEFAULT '{}',
    srcip         text,
    srcuser       text,
    -- Object involved: file path, process, hash... Used as the matching
    -- criterion between alerts from different rules.
    entity        text,
    -- Linux audit.uid (not necessarily numeric in audit JSON, hence text):
    -- a strong correlation link between auditd alerts from the same account.
    audit_uid     text,
    raw           jsonb NOT NULL,
    incident_id   bigint REFERENCES incidents(id) ON DELETE SET NULL,
    -- Post-retrieval suppression by the noise filter (query_level: false). The
    -- alert is ingested and kept for audit purposes, but excluded from
    -- correlation. query_level: true entries, on the other hand, are never
    -- ingested (must_not in OpenSearch) and therefore never appear here.
    suppressed     boolean NOT NULL DEFAULT false,
    suppress_reason text,
    ingested_at   timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS alerts_ts ON alerts (ts DESC);
CREATE INDEX IF NOT EXISTS alerts_incident ON alerts (incident_id);
-- Working index for correlation: it scans an agent's unlinked alerts in
-- chronological order.
CREATE INDEX IF NOT EXISTS alerts_unlinked
    ON alerts (agent_id, ts) WHERE incident_id IS NULL;

-- ---------------------------------------------------------------------------
-- Phase 2: LLM triage
-- ---------------------------------------------------------------------------

-- A verdict rendered by the model on an incident.
--
-- A separate table rather than columns on `incidents`: we want to be able to
-- replay the same incident after a prompt or model change and COMPARE, not
-- overwrite. That is the only way to know whether a change improves or
-- degrades things.
CREATE TABLE IF NOT EXISTS triages (
    id            bigserial PRIMARY KEY,
    incident_id   bigint NOT NULL REFERENCES incidents(id) ON DELETE CASCADE,
    verdict       text NOT NULL,
    confidence    text NOT NULL,
    mitre         text,
    actions       text[] NOT NULL DEFAULT '{}',
    reason        text NOT NULL,
    -- Traceability: without the model and the prompt fingerprint, a
    -- discrepancy between two passes is uninterpretable.
    model        text NOT NULL,
    prompt_sha    text NOT NULL,
    prompt_tokens integer,
    duration_ms      integer,
    -- 'shadow': the verdict is recorded, nothing is triggered. As long as
    -- accuracy is not measured on a labeled set, we do not act on it.
    mode          text NOT NULL DEFAULT 'shadow',
    created_at    timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS triages_incident ON triages (incident_id, created_at DESC);

-- Ground truth, entered by a human analyst.
--
-- Without it, we only know that the model answers, not whether it is right.
-- This is the prerequisite for ever leaving shadow mode.
CREATE TABLE IF NOT EXISTS labels (
    incident_id     bigint PRIMARY KEY REFERENCES incidents(id) ON DELETE CASCADE,
    verdict         text NOT NULL
        CHECK (verdict IN ('true_positive', 'false_positive', 'needs_investigation')),
    actions         text[] NOT NULL DEFAULT '{}',
    comment     text,
    -- 'human' vs 'synthetic': a manufactured bootstrap set must never be
    -- confused with cases that were actually observed and judged.
    origin         text NOT NULL DEFAULT 'human',
    labeled_by   text,
    created_at      timestamptz NOT NULL DEFAULT now()
);

-- Verdict/action inconsistencies flagged by coherence.py. A column, not a
-- table: this is a property of the triage, not an entity. A rising rate
-- signals a degraded prompt, and can be measured without a labeled set.
ALTER TABLE triages ADD COLUMN IF NOT EXISTS inconsistencies text[] NOT NULL DEFAULT '{}';

-- Injection patterns spotted in the incident's data, and interventions by the
-- deterministic guardrails. Measured: 3 out of 4 injection payloads make it
-- through to the model's verdict. We therefore trace both what got through
-- and what was blocked.
ALTER TABLE triages ADD COLUMN IF NOT EXISTS injection_patterns text[] NOT NULL DEFAULT '{}';
ALTER TABLE triages ADD COLUMN IF NOT EXISTS guardrails text[] NOT NULL DEFAULT '{}';

-- ---------------------------------------------------------------------------
-- Automatic whitelist
-- ---------------------------------------------------------------------------

-- Exceptions generated by the AI from recurring false positives.
--
-- A table separate from noise_filter.yaml (edited by a human): we do not want
-- an automated process rewriting a versioned file that the analyst also
-- edits. noise.py reads BOTH sources. An auto exception stays traceable
-- (originating incidents, FP count) and can be disabled without touching
-- code.
--
-- match_all: conjunction of fields (same keys as the noise filter — rule_id,
-- src_user, dst_user, command, agent_name, agent_id). Always post-retrieval:
-- the alert is ingested and kept for audit, never silently dropped on the
-- indexer side. An auto whitelist that is too broad must remain reversible.
CREATE TABLE IF NOT EXISTS whitelist_rules (
    id               bigserial PRIMARY KEY,
    signature        text UNIQUE NOT NULL,   -- canonical form of match_all, anti-duplicate
    match_all        jsonb NOT NULL,
    reason           text NOT NULL,
    source           text NOT NULL DEFAULT 'auto',   -- 'auto' | 'analyst' | 'human' | 'training'
    active           boolean NOT NULL DEFAULT true,
    origin_incidents bigint[] NOT NULL DEFAULT '{}',
    fp_count         integer NOT NULL DEFAULT 0,
    created_at       timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS whitelist_active ON whitelist_rules (active);

-- VirusTotal reputation of a file hash, cached. An executable's VT reputation
-- serves as a deterministic FILTER before correlation: an exe judged
-- legitimate (no positive engine, hash known to VT) suppresses the alert
-- carrying it, so that a clean binary does not open a case (cf. vt.py). A
-- cache is essential: the public VT API is rate-limited (4 req/min, 500/day).
-- TTL handled in code (re-check past VT_CACHE_TTL_DAYS) — a hash can go from
-- "unknown" to "malicious" over time.
CREATE TABLE IF NOT EXISTS vt_file_reputation (
    sha256      text PRIMARY KEY,      -- hash normalized to lowercase
    malicious   integer NOT NULL DEFAULT 0,
    suspicious  integer NOT NULL DEFAULT 0,
    harmless    integer NOT NULL DEFAULT 0,
    undetected  integer NOT NULL DEFAULT 0,
    total       integer NOT NULL DEFAULT 0,   -- engines that analyzed it
    verdict     text NOT NULL,          -- 'legit' | 'malicious' | 'unknown' | 'error'
    permalink   text,
    checked_at  timestamptz NOT NULL DEFAULT now()
);

-- IRIS case created for the incident (one per triaged incident). NULL until
-- created; serves as an anti-duplicate guard for the cycle.
ALTER TABLE incidents ADD COLUMN IF NOT EXISTS iris_case_id bigint;

-- Marker "the incident has gained new_count alerts since it was last
-- processed". Set by correlation when a burst from an ONGOING intrusion is
-- attached to an already-formed incident (the cycle's batching must not
-- reopen a fresh incident per burst). Consumed by triage (the verdict is
-- replayed) then by IRIS (the existing case is UPDATED instead of creating a
-- duplicate), which resets it to false.
ALTER TABLE incidents ADD COLUMN IF NOT EXISTS needs_refresh boolean NOT NULL DEFAULT false;
CREATE INDEX IF NOT EXISTS incidents_needs_refresh
    ON incidents (needs_refresh) WHERE needs_refresh;

-- ---------------------------------------------------------------------------
-- Pseudonymization before sending to the cloud LLM (DeepSeek)
-- ---------------------------------------------------------------------------

-- Token -> real value mapping, per incident. SOC data leaves for the cloud
-- pseudonymized; this table lets us REHYDRATE the model's response (the
-- analyst sees the real values in IRIS) and guarantees STABLE tokens across
-- re-triages (comparability between passes).
--
-- Contains sensitive values in clear text — but the same ones as `alerts.raw`,
-- and in the same place (Postgres loopback): no new exposure. Must never
-- leave the host.
CREATE TABLE IF NOT EXISTS anonymization_map (
    incident_id bigint PRIMARY KEY REFERENCES incidents(id) ON DELETE CASCADE,
    mapping     jsonb NOT NULL DEFAULT '{}',
    updated_at  timestamptz NOT NULL DEFAULT now()
);

-- ---------------------------------------------------------------------------
-- Remediation executed (mitigate.py)
-- ---------------------------------------------------------------------------

-- Trace of each remediation action attempted on an incident. Used for audit
-- (who/what/when), for idempotence (do not re-isolate an already isolated
-- host), and to carry the UNDO procedure — every mitigation must be
-- reversible.
--
-- The (incident, action, target) triple is unique: replaying the cycle does
-- not reapply a remediation that already happened.
CREATE TABLE IF NOT EXISTS mitigations (
    id           bigserial PRIMARY KEY,
    incident_id  bigint NOT NULL REFERENCES incidents(id) ON DELETE CASCADE,
    action       text NOT NULL,
    target        text,            -- agent_id, IP, or account targeted
    status       text NOT NULL,   -- executed | dry_run | failed | canceled |
                                  -- undo_failed | suspended
                                  -- 'canceled': action undone (IRIS task moved
                                  -- to Canceled -> reverse replayed, cf. reconcile).
    details      text,
    undo         text,            -- command / undo procedure
    iris_note_id bigint,          -- legacy: remediations used to be notes
    -- IRIS task (Tasks tab) carrying this remediation. Remediations are no
    -- longer notes: each action is a task, its targets are assets.
    iris_task_id bigint,
    executed_at  timestamptz NOT NULL DEFAULT now(),
    UNIQUE (incident_id, action, target)
);

CREATE INDEX IF NOT EXISTS mitigations_incident ON mitigations (incident_id);

-- ---------------------------------------------------------------------------
-- Catch-up for late-indexed alerts
-- ---------------------------------------------------------------------------

-- Date of the last full catch-up sweep (cf. ingest._sweep). The cursor
-- advances on the EVENT's date, not on its indexing date: an alert replayed
-- by a reconnected agent carries a timestamp the cursor has already passed,
-- so `search_after` will never return it. The periodic sweep picks it up;
-- this column carries its cadence.
ALTER TABLE ingest_cursor ADD COLUMN IF NOT EXISTS last_sweep_at timestamptz;

-- ---------------------------------------------------------------------------
-- Model usage metrics
-- ---------------------------------------------------------------------------

-- ONE LLM call = ONE row, regardless of the caller.
--
-- A separate table rather than columns on `triages`: triage is only one of
-- the model's consumers. The IRIS report, case naming, and whitelist task
-- processing also call DeepSeek, and their tokens were not counted anywhere —
-- `triages.prompt_tokens` saw neither the output tokens nor the other calls.
-- No way to estimate a real cost with that.
--
-- The write happens inside `llm.completion` itself, the single point of
-- passage: a new caller is instrumented without having to think about it. A
-- write failure never interrupts the call (a lost metric beats a lost
-- verdict).
CREATE TABLE IF NOT EXISTS llm_calls (
    id                bigserial PRIMARY KEY,
    ts                timestamptz NOT NULL DEFAULT now(),
    -- Caller: 'triage', 'report', 'case_name', 'whitelist_task'...
    usage             text NOT NULL,
    model            text NOT NULL,
    prompt_tokens     integer,
    completion_tokens integer,
    -- Requested budget. A `completion_tokens` that is right up against it
    -- explains a finish_reason=length (empty content on reasoning models).
    max_tokens        integer,
    duration_ms          integer,
    incident_id       bigint,
    ok                boolean NOT NULL DEFAULT true,
    error            text
);

CREATE INDEX IF NOT EXISTS llm_calls_ts ON llm_calls (ts DESC);

-- Breakdown of the input returned by DeepSeek. A cache hit is billed 50x
-- cheaper than a cache miss: without these two columns the cost is
-- overestimated, since the system prompt is constant from one incident to
-- the next and therefore served from cache most of the time. NULL on earlier
-- calls, and on any API that does not provide the breakdown — the
-- computation then falls back to "everything a cache miss", i.e. a high
-- estimate.
ALTER TABLE llm_calls ADD COLUMN IF NOT EXISTS cache_hit_tokens integer;
ALTER TABLE llm_calls ADD COLUMN IF NOT EXISTS cache_miss_tokens integer;

-- Machine on which a remediation actually applies. An incident can now span
-- SEVERAL agents (campaign merge, approach A): the target (account, IP,
-- process) is no longer enough to identify an action — the same account can
-- exist on two hosts. We therefore anchor each remediation to its agent, and
-- uniqueness moves from (incident, action, target) to (incident, action,
-- target, agent). Default '' for backward compatibility with existing rows.
ALTER TABLE mitigations ADD COLUMN IF NOT EXISTS agent_id text NOT NULL DEFAULT '';
ALTER TABLE mitigations DROP CONSTRAINT IF EXISTS mitigations_incident_id_action_cible_key;
CREATE UNIQUE INDEX IF NOT EXISTS mitigations_uniq
    ON mitigations (incident_id, action, target, agent_id);

-- Counter of emissions of the same remediation. An action left at 'sent'
-- (the command went out but no `ar-result` confirmed the effect) is NOT
-- terminal: it must be re-emitted on the next cycle, otherwise a recreated
-- attacker account is never disabled (purple-team #2/#3: `art-backdoor`
-- stuck on an inherited 'sent' record, disable_user never replayed). But an
-- unbounded re-emission would flood a fire-and-forget channel that never
-- confirms: we cap it at MITIGATE_MAX_ATTEMPTS. The reconcile job (1 min)
-- flips 'sent' -> 'confirmed'/'no_effect' well before the next cycle
-- (5 min) when the channel responds; only actions with genuinely no
-- feedback stay at 'sent', and those are retried up to the cap.
ALTER TABLE mitigations ADD COLUMN IF NOT EXISTS attempts int NOT NULL DEFAULT 1;

-- Ambient noise learning window ("training" mode, cf. training.py). Opened
-- at SOC startup by the administrator, it lasts TRAINING_DAYS days during
-- which the analysis pipeline is SUSPENDED (cycle.py checks
-- training.is_running) and every HIGH/CRITICAL alert becomes a whitelist
-- exception.
--
-- `status` alone governs the pipeline suspension: between `ends_at`
-- expiring and the actual closing (noise filter reapplied + IRIS case), the
-- window stays 'running'. Otherwise a cycle running in that interval would
-- correlate the backlog before the learned noise gets marked.
CREATE TABLE IF NOT EXISTS training_runs (
    id            bigserial PRIMARY KEY,
    started_at    timestamptz NOT NULL DEFAULT now(),
    ends_at       timestamptz NOT NULL,
    days         integer NOT NULL,
    status        text NOT NULL DEFAULT 'running',   -- 'running' | 'finished'
    iris_case_id  bigint,
    finished_at   timestamptz
);

-- Only one window open at a time: two concurrent windows would make closing
-- either one insufficient to unblock the pipeline.
CREATE UNIQUE INDEX IF NOT EXISTS training_single_active_run
    ON training_runs ((status)) WHERE status = 'running';

-- Links an exception to its training window and to the IRIS task that
-- represents it in the TRAINING case. `iris_task_id` is the revocation key:
-- the task moved to 'Canceled' by the analyst disables the exception
-- (training.reconcile).
ALTER TABLE whitelist_rules ADD COLUMN IF NOT EXISTS training_run_id bigint
    REFERENCES training_runs(id) ON DELETE SET NULL;
ALTER TABLE whitelist_rules ADD COLUMN IF NOT EXISTS iris_task_id bigint;

-- ---------------------------------------------------------------------------
-- UEBA — behavioral analysis of LOW/MEDIUM alerts (cf. ueba.py)
-- ---------------------------------------------------------------------------
--
-- The pipeline only opens an incident from level 12 up. Below that everything
-- is ingested but nothing seeds: a quiet intrusion (enumeration, a dropped
-- binary, a login from a country never seen before) is invisible. UEBA builds
-- a baseline of normal behavior, scores the RARITY of what comes in, and
-- promotes the best-scored concentrations to seed status — within a budget.
--
-- No new ingestion: everything is computed from `alerts` and `alerts.raw`.

-- Raw fact aggregated per day. One row = (who, which trait, which value,
-- which day, how many times). This is the ONLY source of truth:
-- `ueba_profiles` is a recomputable summary of it, which lets the baseline
-- age by deleting days rather than blindly decrementing counters.
CREATE TABLE IF NOT EXISTS ueba_observations (
    scope     text NOT NULL,   -- 'host' | 'user@host'
    scope_key text NOT NULL,   -- '002' | 'wazuh-admin@002'
    trait     text NOT NULL,   -- 'exe' | 'parent_child' | 'srcip' | 'country'...
    value    text NOT NULL,
    day      date NOT NULL,
    count        integer NOT NULL DEFAULT 0,
    PRIMARY KEY (scope, scope_key, trait, value, day)
);
CREATE INDEX IF NOT EXISTS ueba_obs_day ON ueba_observations (day);

-- Rolling summary per observed value.
--
-- `days_seen` (number of DISTINCT days) carries more information than
-- `total`: 500 executions in a single day is an incident, 5 executions over
-- 5 days is a habit. This is what decides that a value stops being scored.
--
-- `seen_in_tp`: the trait was involved in a true positive. It can NEVER
-- become a habit again — otherwise a patient attacker normalizes their own
-- tooling by running it every day. Same guardrail as the automatic
-- whitelist, which refuses any signature already seen in a TP.
CREATE TABLE IF NOT EXISTS ueba_profiles (
    scope      text NOT NULL,
    scope_key  text NOT NULL,
    trait      text NOT NULL,
    value     text NOT NULL,
    total      bigint NOT NULL DEFAULT 0,
    days_seen  integer NOT NULL DEFAULT 0,
    first_seen timestamptz,
    last_seen  timestamptz,
    seen_in_tp boolean NOT NULL DEFAULT false,
    PRIMARY KEY (scope, scope_key, trait, value)
);
-- Rarity across the FLEET: on how many distinct hosts is this value known?
-- This is the main anti-false-positive lever — a binary unseen on this host
-- but present on ten others is a deployment, not an intrusion.
CREATE INDEX IF NOT EXISTS ueba_profiles_fleet
    ON ueba_profiles (trait, value) WHERE scope = 'host';

-- Totals per scope, denominator for the rarity computation, and MATURITY of
-- the profile. A scope that is too young is not scored at all: on day one,
-- everything in it is novel, and scoring would send the entire fleet to the
-- LLM.
CREATE TABLE IF NOT EXISTS ueba_scopes (
    scope        text NOT NULL,
    scope_key    text NOT NULL,
    trait        text NOT NULL,
    total        bigint NOT NULL DEFAULT 0,
    distinct_values    integer NOT NULL DEFAULT 0,
    first_obs timestamptz,
    last_obs timestamptz,
    PRIMARY KEY (scope, scope_key, trait)
);

-- Concentration of low-severity alerts judged abnormal on a machine, within
-- a window. An AUDIT table as much as a working one: it keeps the score and
-- its patterns even when the signal is NOT promoted, which allows the floor
-- to be calibrated on real data without spending a single token
-- (`python -m soc_agent.ueba --simulation`).
CREATE TABLE IF NOT EXISTS ueba_signals (
    id          bigserial PRIMARY KEY,
    agent_id    text NOT NULL,
    agent_name  text,
    start_ts       timestamptz NOT NULL,
    end_ts         timestamptz NOT NULL,
    score       double precision NOT NULL,
    patterns      jsonb NOT NULL DEFAULT '[]',
    alert_ids   text[] NOT NULL DEFAULT '{}',
    -- 'promoted': the alerts have become seedable (correlate treats them as a
    -- seed despite their level). 'pending': below the floor or budget
    -- exhausted — recomputed on the next cycle, nothing is lost.
    status      text NOT NULL DEFAULT 'pending',
    created_at  timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS ueba_signals_status
    ON ueba_signals (status, created_at DESC);

-- Alert markers set by the engine.
--   ueba_seen     : already passed through observation (and thus absorbed
--                 into the baseline). The engine's cursor — we score BEFORE
--                 absorbing.
--   ueba_score  : bits of information carried by the alert.
--   ueba_traits : the detail that explains the score. Used both in the LLM
--                 prompt AND by the analyst: a score without an explanation
--                 cannot be contested, and is therefore useless.
--   ueba_seed   : promoted to seed. The only flag that correlate reads.
ALTER TABLE alerts ADD COLUMN IF NOT EXISTS ueba_seen boolean NOT NULL DEFAULT false;
ALTER TABLE alerts ADD COLUMN IF NOT EXISTS ueba_score double precision;
ALTER TABLE alerts ADD COLUMN IF NOT EXISTS ueba_traits jsonb;
ALTER TABLE alerts ADD COLUMN IF NOT EXISTS ueba_seed boolean NOT NULL DEFAULT false;
ALTER TABLE alerts ADD COLUMN IF NOT EXISTS ueba_signal_id bigint;
CREATE INDEX IF NOT EXISTS alerts_ueba_todo
    ON alerts (ts) WHERE NOT ueba_seen;
CREATE INDEX IF NOT EXISTS alerts_ueba_seed
    ON alerts (agent_id, ts) WHERE ueba_seed AND incident_id IS NULL;

-- Does the incident come from a UEBA signal rather than from a level >= 12
-- seed? Triage needs to know (its `max_level` is low, and it would otherwise
-- be dropped from the batch), the prompt needs to explain it, and autonomous
-- remediation is gated on it as long as the engine's accuracy is not
-- measured (UEBA_MITIGATE).
ALTER TABLE incidents ADD COLUMN IF NOT EXISTS ueba boolean NOT NULL DEFAULT false;
ALTER TABLE incidents ADD COLUMN IF NOT EXISTS ueba_score double precision;
ALTER TABLE incidents ADD COLUMN IF NOT EXISTS ueba_patterns jsonb;
CREATE INDEX IF NOT EXISTS incidents_ueba ON incidents (ueba) WHERE ueba;

-- Sensor outages (watchdog.py).
--
-- An outage is a STATE, not an event: the watchdog runs every two minutes and
-- would see the same silent sensor again on every pass. Without this table
-- it would open one IRIS case per pass. So we keep the opening, the
-- associated case, and the recovery here.
--
-- The partial unique index is the idempotence guardrail: only one OPEN
-- outage per (agent, sensor), guaranteed by the database and not by an
-- application-side re-read that can race with itself.
CREATE TABLE IF NOT EXISTS sensor_outages (
    id            bigserial PRIMARY KEY,
    agent_id      text        NOT NULL,
    agent_name    text,
    sensor       text        NOT NULL,
    -- Last event actually seen from this sensor: this is the start of the
    -- outage, not the moment it was noticed.
    last_event timestamptz NOT NULL,
    volume_ref    bigint      NOT NULL,
    threshold_minutes integer     NOT NULL,
    detected_at    timestamptz NOT NULL DEFAULT now(),
    recovered_at    timestamptz,
    iris_case_id  bigint,
    status        text        NOT NULL DEFAULT 'open'
);
CREATE UNIQUE INDEX IF NOT EXISTS sensor_outages_single_open
    ON sensor_outages (agent_id, sensor) WHERE status = 'open';
CREATE INDEX IF NOT EXISTS sensor_outages_recent
    ON sensor_outages (detected_at DESC);
-- ALERT channel (WATCHDOG_IRIS_CHANNEL=alert, default since 2026-08-13): a
-- sensor outage is not an investigation, it is a state to acknowledge. It
-- lives in IRIS's Alerts tab, which has a native lifecycle and leaves it to
-- the analyst to escalate to a case if they judge it warrants a file.
--
-- A SEPARATE column from `iris_case_id`, not a rename: outages opened before
-- the switch point to real cases, and are closed through their original
-- channel (cf. watchdog.monitor, which chooses based on the stored id, not
-- the current configuration).
ALTER TABLE sensor_outages ADD COLUMN IF NOT EXISTS iris_alert_id bigint;

-- ---------------------------------------------------------------------------
-- Evidence items already placed in IRIS (cf. iris._evidences)
-- ---------------------------------------------------------------------------
--
-- Idempotence of Evidence items used to be carried by IRIS itself: we would
-- re-read `list_evidences(cid)` and skip alerts already present. That holds
-- up until the case reaches tens of thousands of them — the call eventually
-- fails or gets truncated, the failure was swallowed in `log.debug`, the
-- "already placed" list fell back to empty, and ALL of the incident's alerts
-- were re-posted. On every cycle, i.e. every 5 minutes.
--
-- Observed on 2026-08-14: 2,987,572 rows in `case_received_file` for 217,542
-- distinct items (factor of 14; up to 54 copies of the same file), 8.3 GB of
-- IRIS database. The cause was not the volume of alerts, it was ASKING IRIS
-- what we had already done.
--
-- The tracking is therefore local and transactional: the primary key carries
-- the idempotence, not the network round trip. `INSERT ... ON CONFLICT DO
-- NOTHING` before the API call — if the insert returns nothing, the item
-- already exists and IRIS is not called again.
CREATE TABLE IF NOT EXISTS iris_evidences (
    incident_id bigint      NOT NULL REFERENCES incidents(id) ON DELETE CASCADE,
    -- Wazuh alert id (text: it is a `timestamp.offset`, not an integer).
    alert_id    text        NOT NULL,
    placed_at     timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (incident_id, alert_id)
);

-- ---------------------------------------------------------------------------
-- CMDB: asset priority (cf. assets.py)
-- ---------------------------------------------------------------------------
--
-- A queryable mirror of what the Wazuh manager knows about each machine, plus
-- what it alone does not know: how much it matters. Without this table, the
-- pipeline only has `rule_level` — a property of the RULE, not of the
-- machine — and treats a domain controller like a test workstation.
--
-- The source of truth remains the Wazuh groups prefixed `role-`: this table
-- can be rebuilt with `python -m soc_agent.assets --sync`. One thing is not
-- rebuildable, and that is why `priority_source` exists: the priority set by
-- hand by an operator (`operator`), which synchronization must never
-- overwrite.
CREATE TABLE IF NOT EXISTS assets (
    agent_id        text PRIMARY KEY,
    name             text,
    ip              text,
    os              text,
    groups         text[] NOT NULL DEFAULT '{}',
    -- Declared role (dc, firewall, web...). NULL = never declared, priority
    -- then falls back to DEFAULT_PRIORITY.
    role            text,
    priority        smallint NOT NULL DEFAULT 4 CHECK (priority BETWEEN 1 AND 4),
    -- 'group' (deduced from Wazuh groups) | 'operator' (set by hand, never
    -- overwritten) | 'default' (no role declared — inventory debt).
    priority_source text NOT NULL DEFAULT 'default',
    notes           text,
    seen_at            timestamptz,
    updated_at           timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS assets_priority ON assets (priority);
-- Resolution by name: alerts from a SENSOR agent carry the originating
-- container (alerts.container), which is resolved via its agent name.
CREATE INDEX IF NOT EXISTS assets_name ON assets (name);

-- Priority of the affected asset, and EFFECTIVE severity of the incident.
--
-- Columns distinct from `max_level`, which is NOT modified: it describes what
-- the Wazuh rule saw, and correlation, UEBA, compromise thresholds, and the
-- closing guardrail all rely on it. Shifting `max_level` based on the asset
-- would silently change the meaning of all those thresholds. Severity is a
-- second dimension: "how hard does this hit" x "on what".
--
-- Frozen at incident creation rather than computed on read: a machine's
-- priority changes (reclassification, role change), and an incident must
-- stay legible with the context it had at the time.
ALTER TABLE incidents ADD COLUMN IF NOT EXISTS priority smallint;
ALTER TABLE incidents ADD COLUMN IF NOT EXISTS severity smallint;
CREATE INDEX IF NOT EXISTS incidents_priority ON incidents (priority, severity DESC);

-- Role of the asset AS IT COUNTED for this incident. Frozen at opening, like
-- priority, and for the same reason — but also because the role declared in
-- `assets` and the one that was used in the computation can DIVERGE: on a
-- sensor agent, the priority is capped and the role reads "sensor", not
-- "firewall". A join against `assets` at read time therefore displayed
-- "P3 — firewall (internal server, no exposure)", which contradicts itself.
-- Observed on incident #2829 (pfSense) on 2026-08-12.
ALTER TABLE incidents ADD COLUMN IF NOT EXISTS asset_role text;

-- ---------------------------------------------------------------------------
-- VOC: vulnerability lifecycle (cf. vulns.py)
-- ---------------------------------------------------------------------------
--
-- Why a table here when Wazuh already has `wazuh-states-vulnerabilities-*`:
-- that index is a STATE index. When a package is fixed, Wazuh DELETES the
-- document. So it can only ever tell you "what is open right now", never
-- "how many were there a month ago", nor "how long does it take to fix". A
-- VOC's two core questions are exactly those.
--
-- This table is therefore the LOG that the state index is not: one row per
-- (machine, CVE, package), born at first observation, kept up to day as long
-- as the vulnerability is seen, and CLOSED (never deleted) when it
-- disappears from the inventory.
CREATE TABLE IF NOT EXISTS vulnerabilities (
    id            bigserial PRIMARY KEY,
    agent_id      text NOT NULL,
    agent_name    text,
    cve           text NOT NULL,
    -- The package, not its VERSION, is part of the key. A version bump that
    -- does not fix the CVE (backport, partial fix) must extend the same row:
    -- otherwise every `apt upgrade` would fabricate a resolution followed by
    -- a reappearance, and the MTTR would measure the pace of updates instead
    -- of the actual fix delay.
    package        text NOT NULL,
    version       text,
    severity      text NOT NULL DEFAULT '',
    base_score    real,
    -- CVE publication date, as given by the feed. Used to distinguish
    -- "open with us for a long time" from "published yesterday": a 2019 CVE
    -- still open is debt, a CVE from yesterday is normal.
    published_at     timestamptz,
    -- First observation BY US. Distinct from Wazuh's `vulnerability.detected_at`,
    -- which resets whenever the scanner recomputes: the SLA must run from a
    -- stable date, otherwise a manager restart resets every lag counter to
    -- zero and the VOC congratulates itself for nothing.
    first_seen         timestamptz NOT NULL DEFAULT now(),
    last_seen  timestamptz NOT NULL DEFAULT now(),
    -- Set when the vulnerability disappears from the machine's inventory.
    -- The row is NOT deleted: it is what carries the remediation history,
    -- hence the only measurable MTTR.
    fixed_at    timestamptz,
    status        text NOT NULL DEFAULT 'open',
    os_name        text,
    UNIQUE (agent_id, cve, package)
);
CREATE INDEX IF NOT EXISTS vuln_open
    ON vulnerabilities (agent_id, severity) WHERE status = 'open';
CREATE INDEX IF NOT EXISTS vuln_fixed ON vulnerabilities (fixed_at)
    WHERE fixed_at IS NOT NULL;
CREATE INDEX IF NOT EXISTS vuln_cve ON vulnerabilities (cve);

-- One scanner pass. Serves two purposes, one of them vital:
--
-- 1. tracking coverage (how many machines actually responded);
-- 2. a closing GUARDRAIL. A machine whose agent is stopped, or whose
--    syscollector is broken, disappears from the state index — its
--    vulnerabilities too. Without a memory of the agents SEEN on this pass,
--    the diff would conclude that everything was fixed at once: a perfect
--    burn-down, a beautiful MTTR, and a fleet gone invisible. We therefore
--    only close on agents that actually responded to this scan.
CREATE TABLE IF NOT EXISTS vuln_scans (
    id             bigserial PRIMARY KEY,
    started_at        timestamptz NOT NULL DEFAULT now(),
    agents_seen     integer NOT NULL DEFAULT 0,
    vulns_seen     integer NOT NULL DEFAULT 0,
    new_count      integer NOT NULL DEFAULT 0,
    fixed_count      integer NOT NULL DEFAULT 0,
    silent_agents   text[] NOT NULL DEFAULT '{}'
);
CREATE INDEX IF NOT EXISTS vuln_scans_recent ON vuln_scans (started_at DESC);

-- Watch articles already processed by cti_articles.py.
--
-- Serves as a CURSOR, and that is its vital function: without it, every pass
-- would re-download the same articles and have the model re-read them — a
-- cost that grows with every run, for zero new information. It is also this
-- cursor that turns the Malpedia bibliography (no date, no feed of novelty)
-- into an actual stream of new items.
--
-- Articles WITHOUT any IOC are recorded too, along with the pattern. Two
-- reasons: not re-reading them indefinitely (most press pieces describe no
-- infrastructure at all), and being able to measure the real yield of each
-- source — a source that never yields anything costs model calls and
-- deserves to be disabled, which is only visible if failures are tracked.
CREATE TABLE IF NOT EXISTS cti_articles (
    id             bigserial PRIMARY KEY,
    source         text NOT NULL,
    -- The URL is the deduplication key, not the title: outlets rewrite their
    -- titles, never their permalinks.
    url            text NOT NULL UNIQUE,
    processed_at       timestamptz NOT NULL DEFAULT now(),
    iocs_kept   integer NOT NULL DEFAULT 0,
    -- MISP event created, when there is one. Lets us trace what the SOC
    -- published from which article, and retract it if the extraction turns
    -- out to be bad.
    misp_event_id  integer,
    threat         text NOT NULL DEFAULT '',
    -- Why nothing was kept (no candidate, negative arbitration, cap
    -- exceeded, warninglists). The field that makes the rejection rate
    -- legible.
    pattern          text NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS cti_articles_recent ON cti_articles (processed_at DESC);
CREATE INDEX IF NOT EXISTS cti_articles_with_iocs ON cti_articles (source, processed_at DESC)
    WHERE iocs_kept > 0;

-- ---------------------------------------------------------------------------
-- Routing of log sources to their index (routing.py)
-- ---------------------------------------------------------------------------
--
-- A "log source" is not an agent: it is what PRODUCES the lines (a Wazuh
-- decoder, or a rule group when the decoder is generic). The indexer's
-- ingest pipeline routes each source to its dated index; this table is the
-- memory of that routing, and the only place where it is decided.
--
-- Why a table and not just the pipeline's JSON: the `alerts-pipeline.json`
-- file is bind-mounted into the manager's filebeat module, and filebeat
-- OVERWRITES it on every manager restart. A branch added via the API alone
-- disappears on the next `docker compose up`. The pipeline's rendering is
-- therefore recomputed from this table on every watchdog pass, and reapplied
-- as soon as it diverges from what is running — filebeat's overwrite fixes
-- itself within under two minutes.
--
-- `source_key` is COMPOSITE (`decoder:npm-access`, `groups:suricata`): the
-- decoder is the stable criterion when it is specific (cf. the comment in
-- the routing script — groups depend on WHICH rule wins), but a generic
-- decoder like `json` serves both AdGuard and Suricata and cannot be a key.
-- For those, the criterion falls back to the rule group.
CREATE TABLE IF NOT EXISTS routing_sources (
    id             bigserial PRIMARY KEY,
    source_key     text NOT NULL UNIQUE,
    -- 'decoder' | 'groups': what the painless branch tests on.
    criterion_type   text NOT NULL,
    criterion_value text NOT NULL,
    -- Prefix WITHOUT the date: 'wazuh-proxy' gives 'wazuh-proxy-2026.08.14'.
    index_base     text NOT NULL,
    -- 'applicative' (keeps the product's name) | 'generique' (business name).
    kind           text NOT NULL DEFAULT 'generique',
    -- 'proposed'  : named, pending (deterministic fallback, or daily cap)
    -- 'applied' : all five pieces are in place (pipeline, template, ISM,
    --              read by the AI, dashboard index pattern)
    -- 'refused'   : dismissed by hand, do not propose again
    status         text NOT NULL DEFAULT 'proposed',
    -- 'static' : branch already present in alerts-pipeline.json, discovered
    --              by observation and never regenerated by us
    -- 'llm' | 'fallback' | 'human' : who chose the name
    named_by      text NOT NULL DEFAULT 'llm',
    justification  text NOT NULL DEFAULT '',
    -- Last observed volume on the window, and when. This pair is what makes
    -- an ESTABLISHED source going silent visible: an index that no longer
    -- exists because nobody writes to it anymore shows up in no dashboard.
    volume_ref     bigint NOT NULL DEFAULT 0,
    last_seen           timestamptz NOT NULL DEFAULT now(),
    -- Actually observed alert, kept as a WITNESS: before every pipeline PUT,
    -- each witness is replayed through `_simulate` and must come out in its
    -- expected index. This is the guardrail against an invalid painless
    -- script, which — since `on_failure: drop` — would silently drop every
    -- alert in the SOC.
    example        jsonb,
    created_at        timestamptz NOT NULL DEFAULT now(),
    applied_at    timestamptz
);
CREATE INDEX IF NOT EXISTS routing_sources_status ON routing_sources (status);
CREATE INDEX IF NOT EXISTS routing_sources_applied
    ON routing_sources (applied_at DESC) WHERE applied_at IS NOT NULL;

-- ---------------------------------------------------------------------------
-- Cold archival to S3 (archive.py)
-- ---------------------------------------------------------------------------
--
-- The record of "what is archived" lives HERE, never in the remote system.
-- That is the lesson from IRIS's Evidence items: `iris._evidences` used to
-- ask IRIS for the list of items already placed; past a few thousand the
-- call would start failing, the failure was swallowed, the list fell back to
-- empty, and everything was re-posted — 8.3 GB and up to 54 copies of the
-- same file. An S3 that does not respond must produce a VISIBLE FAILURE,
-- never a "nothing is archived" that re-triggers twelve months of upload.
--
-- A row is only written AFTER re-reading the object back from S3 (HEAD, size
-- compared). If the process dies between the upload and the INSERT, the key
-- is deterministic: the next pass finds the orphaned object, reads its
-- manifest, compares the document count to the live count, and ADOPTS the
-- row instead of re-uploading (cf. archive._adopt).
CREATE TABLE IF NOT EXISTS archives_s3 (
    id             bigserial PRIMARY KEY,
    -- FORMAT version (key prefix). Part of the uniqueness constraint:
    -- bumping to v2 must allow re-archiving a month already covered in v1
    -- without deleting the old row or the old object.
    format_version text NOT NULL,
    -- Index prefix WITHOUT the date: 'wazuh-firewall', 'wazuh-alerts-4.x'.
    index_base     text NOT NULL,
    period        text NOT NULL,               -- 'YYYY-MM'
    key            text NOT NULL,               -- S3 key of the encrypted object
    manifest_key  text NOT NULL,
    -- Dated indices actually read. Kept because they will not be there
    -- anymore: once the ISM purge has run, this is the only trace of what
    -- the archive covers.
    indices        text[] NOT NULL DEFAULT '{}',
    documents      bigint NOT NULL DEFAULT 0,
    plain_bytes   bigint NOT NULL DEFAULT 0,
    object_bytes   bigint NOT NULL DEFAULT 0,
    -- SHA-256 of the plaintext NDJSON: what lets us prove, two years from
    -- now, that what we decrypt is indeed what was archived. Without it we
    -- have a backup, not a proof.
    sha256_plain   text NOT NULL,
    -- SHA-256 of the object as stored. The only one verifiable without the
    -- private key, hence the only one usable by the automated drill.
    sha256_encrypted text NOT NULL,
    -- Exact processing chain and age recipients, so a human knows how to
    -- read it back without reading this version's code.
    chain         text NOT NULL DEFAULT '',
    recipients  text[] NOT NULL DEFAULT '{}',
    excluded_fields  text[] NOT NULL DEFAULT '{}',
    object_lock_until timestamptz,
    archived_at     timestamptz NOT NULL DEFAULT now(),
    -- Drill: when the object was read back, and what the read-back found.
    -- 'ok' | 'absent' | 'sha256-divergent' | 'documents-divergents' | 'error: ...'
    verified_at      timestamptz,
    verify_state     text,
    verify_full  boolean NOT NULL DEFAULT false,
    UNIQUE (format_version, index_base, period)
);
-- Drill selection: least recently verified first, never-verified at the
-- front.
CREATE INDEX IF NOT EXISTS archives_s3_drill
    ON archives_s3 (verified_at NULLS FIRST);
CREATE INDEX IF NOT EXISTS archives_s3_coverage
    ON archives_s3 (index_base, period);

-- Data-leak watch: last XposedOrNot check per monitored email (members of the
-- IRIS group "veille-data-leak", cf. data_leak.py). `signature` is a hash of
-- the breach names found; a case is (re)opened only when it CHANGES, so an
-- old, still-present breach is never replayed into a new case every pass.
CREATE TABLE IF NOT EXISTS data_leak_email_check (
    email        text PRIMARY KEY,
    user_login   text NOT NULL DEFAULT '',
    breaches     jsonb NOT NULL DEFAULT '[]',
    signature    text NOT NULL DEFAULT '',
    -- Last IRIS case opened for this email, NULL as long as no breach was
    -- ever found. Reused on refresh instead of opening a second case.
    iris_case_id bigint,
    checked_at   timestamptz NOT NULL DEFAULT now()
);
